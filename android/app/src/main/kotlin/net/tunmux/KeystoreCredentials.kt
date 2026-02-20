package net.tunmux

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object KeystoreCredentials {
    private const val ALIAS    = "tunmux_cred"
    private const val PREFS    = "tunmux_secure"
    private const val K_PROV   = "provider"
    private const val K_ENC    = "enc"
    private const val K_IV     = "iv"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        )
        return kg.generateKey()
    }

    fun save(context: Context, provider: String, credentialJson: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").also { it.init(Cipher.ENCRYPT_MODE, key()) }
        val enc = cipher.doFinal(credentialJson.toByteArray(Charsets.UTF_8))
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putString(K_PROV, provider)
            putString(K_ENC, Base64.encodeToString(enc, Base64.NO_WRAP))
            putString(K_IV,  Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
        }
    }

    /** Returns (provider, credentialJson) or null if nothing saved or decryption fails. */
    fun load(context: Context): Pair<String, String>? = try {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val provider = p.getString(K_PROV, null) ?: return null
        val enc = Base64.decode(p.getString(K_ENC, null) ?: return null, Base64.NO_WRAP)
        val iv  = Base64.decode(p.getString(K_IV,  null) ?: return null, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            .also { it.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
        provider to cipher.doFinal(enc).toString(Charsets.UTF_8)
    } catch (_: Exception) { null }

    fun clear(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { clear() }
}

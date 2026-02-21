package net.tunmux

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.core.content.edit
import java.security.KeyStore
import java.security.KeyStoreException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object KeystoreCredentials {
    private const val ALIAS = "tunmux_cred"
    private const val PREFS = "tunmux_secure"
    private const val LEGACY_PROVIDER = "provider"
    private const val LEGACY_ENC = "enc"
    private const val LEGACY_IV = "iv"
    private const val ENC_PREFIX = "enc_"
    private const val IV_PREFIX = "iv_"

    private val supportedProviders = setOf("proton", "airvpn", "mullvad", "ivpn")

    class CredentialStoreException(
        val errorCode: String,
        message: String,
        cause: Throwable? = null,
    ) : Exception(message, cause)

    private fun key(): SecretKey {
        try {
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
                    .build(),
            )
            return kg.generateKey()
        } catch (ex: Throwable) {
            throw mapKeystoreError("keystore_unavailable", "android_keystore_unavailable", ex)
        }
    }

    private fun providerKey(provider: String): String {
        val normalized = provider.trim().lowercase()
        if (normalized !in supportedProviders) {
            throw CredentialStoreException(
                errorCode = "invalid_provider",
                message = "unsupported provider '$provider'",
            )
        }
        return normalized
    }

    private fun encKey(provider: String): String = "$ENC_PREFIX$provider"

    private fun ivKey(provider: String): String = "$IV_PREFIX$provider"

    fun clearLegacyEntries(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            remove(LEGACY_PROVIDER)
            remove(LEGACY_ENC)
            remove(LEGACY_IV)
        }
    }

    fun save(context: Context, provider: String, credentialJson: String) {
        val canonicalProvider = providerKey(provider)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                .also { it.init(Cipher.ENCRYPT_MODE, key()) }
            val enc = cipher.doFinal(credentialJson.toByteArray(Charsets.UTF_8))
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
                putString(encKey(canonicalProvider), Base64.encodeToString(enc, Base64.NO_WRAP))
                putString(ivKey(canonicalProvider), Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            }
        } catch (ex: Throwable) {
            throw mapKeystoreError("store_failed", "failed_to_save_credential", ex)
        }
    }

    fun loadForProvider(context: Context, provider: String): String? {
        val canonicalProvider = providerKey(provider)
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val encValue = p.getString(encKey(canonicalProvider), null) ?: return null
        val ivValue = p.getString(ivKey(canonicalProvider), null) ?: return null

        return try {
            val enc = Base64.decode(encValue, Base64.NO_WRAP)
            val iv = Base64.decode(ivValue, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                .also { it.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
            cipher.doFinal(enc).toString(Charsets.UTF_8)
        } catch (ex: Throwable) {
            throw mapKeystoreError("load_failed", "failed_to_load_credential", ex)
        }
    }

    fun deleteForProvider(context: Context, provider: String) {
        val canonicalProvider = providerKey(provider)
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
                remove(encKey(canonicalProvider))
                remove(ivKey(canonicalProvider))
            }
        } catch (ex: Throwable) {
            throw mapKeystoreError("delete_failed", "failed_to_delete_credential", ex)
        }
    }

    private fun mapKeystoreError(defaultCode: String, fallbackMessage: String, ex: Throwable): CredentialStoreException {
        val code = when (ex) {
            is CredentialStoreException -> ex.errorCode
            is KeyPermanentlyInvalidatedException -> "key_invalidated"
            is UserNotAuthenticatedException -> "keystore_locked"
            is KeyStoreException -> "keystore_unavailable"
            else -> defaultCode
        }
        val message = ex.message?.trim().orEmpty().ifEmpty { fallbackMessage }
        return CredentialStoreException(code, message, ex)
    }
}

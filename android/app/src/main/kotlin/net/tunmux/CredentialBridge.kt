package net.tunmux

import android.content.Context
import android.util.Log
import org.json.JSONObject

object CredentialBridge {
    private const val TAG = "tunmux"
    private const val CONTRACT_VERSION = 1

    @Volatile
    private var appContext: Context? = null

    @JvmStatic
    fun initialize(context: Context) {
        appContext = context.applicationContext
        runCatching { KeystoreCredentials.clearLegacyEntries(context.applicationContext) }
            .onFailure { ex ->
                Log.w(TAG, "credential_bridge legacy cleanup failed", ex)
            }
    }

    @JvmStatic
    fun save(provider: String, json: String): String {
        val operation = "save"
        val ctx = appContext
            ?: return error(operation, "context_not_initialized", "credential bridge context is not initialized")
        return runCatching {
            KeystoreCredentials.save(ctx, provider, json)
            Log.d(TAG, "credential_bridge_save_ok provider=${provider.trim().lowercase()}")
            ok(operation)
        }.getOrElse { ex ->
            val code = when (ex) {
                is KeystoreCredentials.CredentialStoreException -> ex.errorCode
                else -> "store_failed"
            }
            Log.w(
                TAG,
                "credential_bridge_save_failed provider=${provider.trim().lowercase()} code=$code",
                ex,
            )
            error(operation, code, ex.message ?: "credential save failed")
        }
    }

    @JvmStatic
    fun load(provider: String): String {
        val operation = "load"
        val ctx = appContext
            ?: return error(operation, "context_not_initialized", "credential bridge context is not initialized")
        return runCatching {
            val payload = KeystoreCredentials.loadForProvider(ctx, provider)
            JSONObject()
                .put("version", CONTRACT_VERSION)
                .put("ok", true)
                .put("operation", operation)
                .put("payload", payload)
                .put("error_code", JSONObject.NULL)
                .put("error", JSONObject.NULL)
                .toString()
        }.getOrElse { ex ->
            val code = when (ex) {
                is KeystoreCredentials.CredentialStoreException -> ex.errorCode
                else -> "load_failed"
            }
            Log.w(
                TAG,
                "credential_bridge_load_failed provider=${provider.trim().lowercase()} code=$code",
                ex,
            )
            error(operation, code, ex.message ?: "credential load failed")
        }
    }

    @JvmStatic
    fun delete(provider: String): String {
        val operation = "delete"
        val ctx = appContext
            ?: return error(operation, "context_not_initialized", "credential bridge context is not initialized")
        return runCatching {
            KeystoreCredentials.deleteForProvider(ctx, provider)
            Log.d(TAG, "credential_bridge_delete_ok provider=${provider.trim().lowercase()}")
            ok(operation)
        }.getOrElse { ex ->
            val code = when (ex) {
                is KeystoreCredentials.CredentialStoreException -> ex.errorCode
                else -> "delete_failed"
            }
            Log.w(
                TAG,
                "credential_bridge_delete_failed provider=${provider.trim().lowercase()} code=$code",
                ex,
            )
            error(operation, code, ex.message ?: "credential delete failed")
        }
    }

    private fun ok(operation: String): String {
        return JSONObject()
            .put("version", CONTRACT_VERSION)
            .put("ok", true)
            .put("operation", operation)
            .put("error_code", JSONObject.NULL)
            .put("error", JSONObject.NULL)
            .toString()
    }

    private fun error(operation: String, code: String, reason: String): String {
        return JSONObject()
            .put("version", CONTRACT_VERSION)
            .put("ok", false)
            .put("operation", operation)
            .put("error_code", code)
            .put("error", reason)
            .toString()
    }
}

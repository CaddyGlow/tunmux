package net.tunmux

import android.content.Context
import org.json.JSONObject

object CredentialBridge {
    @Volatile
    private var appContext: Context? = null

    @JvmStatic
    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @JvmStatic
    fun save(provider: String, json: String): String {
        val ctx = appContext ?: return error("save", "context_not_initialized")
        return runCatching {
            KeystoreCredentials.save(ctx, provider, json)
            ok()
        }.getOrElse { ex ->
            error("save", ex.message ?: "unknown_error")
        }
    }

    @JvmStatic
    fun load(provider: String): String {
        val ctx = appContext ?: return error("load", "context_not_initialized")
        return runCatching {
            val payload = KeystoreCredentials.loadForProvider(ctx, provider)
            JSONObject()
                .put("ok", true)
                .put("payload", payload)
                .toString()
        }.getOrElse { ex ->
            error("load", ex.message ?: "unknown_error")
        }
    }

    @JvmStatic
    fun delete(provider: String): String {
        val ctx = appContext ?: return error("delete", "context_not_initialized")
        return runCatching {
            KeystoreCredentials.deleteForProvider(ctx, provider)
            ok()
        }.getOrElse { ex ->
            error("delete", ex.message ?: "unknown_error")
        }
    }

    private fun ok(): String = JSONObject().put("ok", true).toString()

    private fun error(operation: String, reason: String): String {
        return JSONObject()
            .put("ok", false)
            .put("operation", operation)
            .put("error", reason)
            .toString()
    }
}

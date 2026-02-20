package net.tunmux.model

import android.content.Context

data class AutoRuntimeState(
    val provider: String = "",
    val server: String = "",
)

object AutoRuntimeStore {
    private const val PREFS = "tunmux_auto_runtime"
    private const val KEY_PROVIDER = "provider"
    private const val KEY_SERVER = "server"

    fun load(context: Context): AutoRuntimeState {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return AutoRuntimeState(
            provider = prefs.getString(KEY_PROVIDER, "").orEmpty(),
            server = prefs.getString(KEY_SERVER, "").orEmpty(),
        )
    }

    fun saveProvider(context: Context, provider: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_PROVIDER, provider.trim()).apply()
    }

    fun save(context: Context, provider: String, server: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_PROVIDER, provider.trim())
            .putString(KEY_SERVER, server.trim())
            .apply()
    }

    fun clear(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
    }
}

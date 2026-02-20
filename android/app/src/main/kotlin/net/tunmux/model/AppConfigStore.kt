package net.tunmux.model

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class GeneralConfig(
    val backend: String = "wg-quick",
    val credentialStore: String = "file",
    val proxy: Boolean = false,
    val socksPort: Int? = null,
    val httpPort: Int? = null,
    val proxyAccessLog: Boolean = false,
    val privilegedTransport: String = "socket",
    val privilegedAutostart: Boolean = true,
    val privilegedAutostartTimeoutMs: Long = 5000L,
    val privilegedAuthorizedGroup: String = "",
    val privilegedAutostopMode: String = "never",
    val privilegedAutostopTimeoutMs: Long = 30000L,
    val appMode: String = "vpn",
    val splitTunnelApps: List<String> = emptyList(),
    val splitTunnelOnlyAllowSelected: Boolean = false,
)

data class ProviderConfig(
    val defaultCountry: String = "",
)

data class AirvpnConfig(
    val defaultCountry: String = "",
    val defaultDevice: String = "",
)

data class AutoTunnelConfig(
    val enabled: Boolean = false,
    val onWifi: Boolean = true,
    val onMobile: Boolean = true,
    val onEthernet: Boolean = true,
    val stopOnNoInternet: Boolean = true,
    val startOnBoot: Boolean = false,
)

data class AppConfigModel(
    val general: GeneralConfig = GeneralConfig(),
    val proton: ProviderConfig = ProviderConfig(),
    val airvpn: AirvpnConfig = AirvpnConfig(),
    val mullvad: ProviderConfig = ProviderConfig(),
    val ivpn: ProviderConfig = ProviderConfig(),
    val auto: AutoTunnelConfig = AutoTunnelConfig(),
)

object AppConfigStore {
    private const val PREFS = "tunmux_config"
    private const val KEY_JSON = "app_config_json"

    fun load(context: Context): AppConfigModel {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val jsonText = prefs.getString(KEY_JSON, null) ?: return AppConfigModel()
        return runCatching { fromJson(JSONObject(jsonText)) }.getOrElse { AppConfigModel() }
    }

    fun save(context: Context, config: AppConfigModel) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_JSON, toJson(config).toString()).apply()
    }

    private fun toJson(config: AppConfigModel): JSONObject {
        val general = JSONObject()
            .put("backend", config.general.backend)
            .put("credential_store", config.general.credentialStore)
            .put("proxy", config.general.proxy)
            .put("socks_port", config.general.socksPort)
            .put("http_port", config.general.httpPort)
            .put("proxy_access_log", config.general.proxyAccessLog)
            .put("privileged_transport", config.general.privilegedTransport)
            .put("privileged_autostart", config.general.privilegedAutostart)
            .put("privileged_autostart_timeout_ms", config.general.privilegedAutostartTimeoutMs)
            .put("privileged_authorized_group", config.general.privilegedAuthorizedGroup)
            .put("privileged_autostop_mode", config.general.privilegedAutostopMode)
            .put("privileged_autostop_timeout_ms", config.general.privilegedAutostopTimeoutMs)
            .put("app_mode", config.general.appMode)
            .put("split_tunnel_apps", JSONArray(config.general.splitTunnelApps))
            .put("split_tunnel_only_allow_selected", config.general.splitTunnelOnlyAllowSelected)

        val proton = JSONObject().put("default_country", config.proton.defaultCountry)
        val airvpn = JSONObject()
            .put("default_country", config.airvpn.defaultCountry)
            .put("default_device", config.airvpn.defaultDevice)
        val mullvad = JSONObject().put("default_country", config.mullvad.defaultCountry)
        val ivpn = JSONObject().put("default_country", config.ivpn.defaultCountry)
        val auto = JSONObject()
            .put("enabled", config.auto.enabled)
            .put("on_wifi", config.auto.onWifi)
            .put("on_mobile", config.auto.onMobile)
            .put("on_ethernet", config.auto.onEthernet)
            .put("stop_on_no_internet", config.auto.stopOnNoInternet)
            .put("start_on_boot", config.auto.startOnBoot)

        return JSONObject()
            .put("general", general)
            .put("proton", proton)
            .put("airvpn", airvpn)
            .put("mullvad", mullvad)
            .put("ivpn", ivpn)
            .put("auto", auto)
    }

    private fun fromJson(root: JSONObject): AppConfigModel {
        val generalJson = root.optJSONObject("general") ?: JSONObject()
        val protonJson = root.optJSONObject("proton") ?: JSONObject()
        val airvpnJson = root.optJSONObject("airvpn") ?: JSONObject()
        val mullvadJson = root.optJSONObject("mullvad") ?: JSONObject()
        val ivpnJson = root.optJSONObject("ivpn") ?: JSONObject()
        val autoJson = root.optJSONObject("auto") ?: JSONObject()

        val general = GeneralConfig(
            backend = generalJson.optString("backend", "wg-quick"),
            credentialStore = generalJson.optString("credential_store", "file"),
            proxy = generalJson.optBoolean("proxy", false),
            socksPort = generalJson.optNullableInt("socks_port"),
            httpPort = generalJson.optNullableInt("http_port"),
            proxyAccessLog = generalJson.optBoolean("proxy_access_log", false),
            privilegedTransport = generalJson.optString("privileged_transport", "socket"),
            privilegedAutostart = generalJson.optBoolean("privileged_autostart", true),
            privilegedAutostartTimeoutMs = generalJson.optLong("privileged_autostart_timeout_ms", 5000L),
            privilegedAuthorizedGroup = generalJson.optString("privileged_authorized_group", ""),
            privilegedAutostopMode = generalJson.optString("privileged_autostop_mode", "never"),
            privilegedAutostopTimeoutMs = generalJson.optLong("privileged_autostop_timeout_ms", 30000L),
            appMode = generalJson.optString("app_mode", "vpn"),
            splitTunnelApps = generalJson.optStringArray("split_tunnel_apps"),
            splitTunnelOnlyAllowSelected = generalJson.optBoolean("split_tunnel_only_allow_selected", false),
        )

        val proton = ProviderConfig(
            defaultCountry = protonJson.optString("default_country", ""),
        )
        val airvpn = AirvpnConfig(
            defaultCountry = airvpnJson.optString("default_country", ""),
            defaultDevice = airvpnJson.optString("default_device", ""),
        )
        val mullvad = ProviderConfig(
            defaultCountry = mullvadJson.optString("default_country", ""),
        )
        val ivpn = ProviderConfig(
            defaultCountry = ivpnJson.optString("default_country", ""),
        )
        val auto = AutoTunnelConfig(
            enabled = autoJson.optBoolean("enabled", false),
            onWifi = autoJson.optBoolean("on_wifi", true),
            onMobile = autoJson.optBoolean("on_mobile", true),
            onEthernet = autoJson.optBoolean("on_ethernet", true),
            stopOnNoInternet = autoJson.optBoolean("stop_on_no_internet", true),
            startOnBoot = autoJson.optBoolean("start_on_boot", false),
        )

        return AppConfigModel(
            general = general,
            proton = proton,
            airvpn = airvpn,
            mullvad = mullvad,
            ivpn = ivpn,
            auto = auto,
        )
    }
}

private fun JSONObject.optNullableInt(key: String): Int? {
    return if (isNull(key) || !has(key)) null else optInt(key)
}

private fun JSONObject.optStringArray(key: String): List<String> {
    val arr = optJSONArray(key) ?: return emptyList()
    val out = mutableListOf<String>()
    for (i in 0 until arr.length()) {
        val value = arr.optString(i).trim()
        if (value.isNotEmpty()) out += value
    }
    return out
}

package net.tunmux.model

import android.app.Application
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import net.tunmux.KeystoreCredentials
import net.tunmux.RustBridge
import net.tunmux.TunmuxVpnService
import org.json.JSONArray
import org.json.JSONObject

enum class Screen { ProviderSelect, Login, Dashboard }
enum class DashboardTab { Main, Config, Settings, Auto }
enum class ConnectionState { Disconnected, Connecting, Connected }

data class AirvpnKey(
    val name: String,
    val ipv4: String,
    val ipv6: String,
)

data class AirvpnDevice(
    val id: String,
    val name: String,
    val ipv4: String,
    val ipv6: String,
    val publicKey: String,
)

data class AutoTunnelConfig(
    val enabled: Boolean = false,
    val onWifi: Boolean = true,
    val onMobile: Boolean = true,
    val stopOnNoInternet: Boolean = true,
    val startOnBoot: Boolean = false,
)

data class UiState(
    val screen: Screen = Screen.ProviderSelect,
    val selectedProvider: String = "",
    val activeTab: DashboardTab = DashboardTab.Main,
    val connectionState: ConnectionState = ConnectionState.Disconnected,
    val serverList: List<String> = emptyList(),
    val activeServer: String = "",
    val wgLikeStatus: String = "",
    val errorMessage: String = "",
    val config: AppConfigModel = AppConfigModel(),
    val airvpnKeys: List<AirvpnKey> = emptyList(),
    val selectedAirvpnKey: String = "",
    val airvpnDevices: List<AirvpnDevice> = emptyList(),
    val settingsMessage: String = "",
    val autoConfig: AutoTunnelConfig = AutoTunnelConfig(),
)

class VpnViewModel(app: Application) : AndroidViewModel(app) {
    companion object {
        private const val TAG = "tunmux"
    }

    private val ctx get() = getApplication<Application>()

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    private var statusJob: Job? = null

    init {
        val config = AppConfigStore.load(ctx)
        _state.value = _state.value.copy(config = config)
        ensureStatusPolling()

        // Attempt silent re-login with credentials stored in Keystore.
        val saved = KeystoreCredentials.load(ctx)
        if (saved != null) {
            val (provider, savedCredential) = saved
            _state.value = _state.value.copy(selectedProvider = provider)
            viewModelScope.launch(Dispatchers.IO) {
                try {
                    val loginCredential = applyConfigToCredential(provider, savedCredential, config)
                    val result = RustBridge.login(provider, loginCredential)
                    val json = JSONObject(result)
                    if (json.optString("status") == "ok") {
                        val servers = fetchServersNow(provider) ?: return@launch
                        _state.value = _state.value.copy(
                            screen = Screen.Dashboard,
                            activeTab = DashboardTab.Main,
                            serverList = servers,
                            errorMessage = "",
                        )
                        if (provider == "airvpn") {
                            refreshAirvpnSettingsDataInternal()
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "auto-login failed provider=$provider", e)
                }
            }
        }
    }

    override fun onCleared() {
        statusJob?.cancel()
        super.onCleared()
    }

    fun selectProvider(provider: String) {
        _state.value = _state.value.copy(
            selectedProvider = provider,
            screen = Screen.Login,
            errorMessage = "",
            settingsMessage = "",
        )
    }

    fun switchTab(tab: DashboardTab) {
        _state.value = _state.value.copy(activeTab = tab, errorMessage = "")
        if (tab == DashboardTab.Config && _state.value.selectedProvider == "airvpn") {
            refreshAirvpnSettingsData()
        }
    }

    /**
     * @param twoFa TOTP code; pass blank string if 2FA is not enabled.
     */
    fun login(username: String, password: String, twoFa: String) {
        val provider = _state.value.selectedProvider
        if (provider.isBlank()) {
            _state.value = _state.value.copy(errorMessage = "No VPN provider selected")
            return
        }

        val config = _state.value.config
        val credential = JSONObject().apply {
            put("username", username)
            put("password", password)
            if (twoFa.isNotBlank()) put("totp", twoFa)
            if (provider == "airvpn") {
                val defaultDevice = config.airvpn.defaultDevice.trim()
                if (defaultDevice.isNotEmpty()) put("device", defaultDevice)
            }
        }.toString()

        val credentialToStore = JSONObject().apply {
            put("username", username)
            put("password", password)
        }.toString()

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = RustBridge.login(provider, credential)
                val json = JSONObject(result)
                val status = json.optString("status", "error")
                if (status == "ok") {
                    KeystoreCredentials.save(ctx, provider, credentialToStore)
                    val servers = fetchServersNow(provider) ?: return@launch
                    _state.value = _state.value.copy(
                        screen = Screen.Dashboard,
                        activeTab = DashboardTab.Main,
                        serverList = servers,
                        errorMessage = "",
                    )
                    if (provider == "airvpn") {
                        refreshAirvpnSettingsDataInternal()
                    }
                } else {
                    val error = json.optString("error", "login failed")
                    _state.value = _state.value.copy(errorMessage = error)
                }
            } catch (e: Exception) {
                Log.e(TAG, "login failed provider=$provider", e)
                _state.value = _state.value.copy(errorMessage = e.message ?: "unexpected error")
            }
        }
    }

    fun logout() {
        val provider = _state.value.selectedProvider
        if (provider.isNotBlank()) {
            runCatching { RustBridge.logout(provider) }
        }
        KeystoreCredentials.clear(ctx)
        _state.value = UiState(
            screen = Screen.ProviderSelect,
            config = _state.value.config,
            autoConfig = _state.value.autoConfig,
        )
    }

    private fun fetchServersNow(provider: String): List<String>? {
        return try {
            val raw = RustBridge.fetchServers(provider)
            val arr = JSONArray(raw)
            val allServers = List(arr.length()) { i -> arr.getString(i) }
            val servers = applyProviderDefaults(provider, allServers)
            if (servers.isEmpty()) {
                val message = "Login succeeded but no servers were returned for $provider"
                Log.w(TAG, message)
                _state.value = _state.value.copy(errorMessage = message)
                null
            } else {
                servers
            }
        } catch (e: Exception) {
            Log.e(TAG, "fetchServers failed provider=$provider", e)
            _state.value = _state.value.copy(
                errorMessage = "Failed to fetch servers for $provider: ${e.message ?: "unknown error"}",
            )
            null
        }
    }

    private fun applyProviderDefaults(provider: String, servers: List<String>): List<String> {
        val country = when (provider) {
            "proton" -> _state.value.config.proton.defaultCountry
            "airvpn" -> _state.value.config.airvpn.defaultCountry
            "mullvad" -> _state.value.config.mullvad.defaultCountry
            "ivpn" -> _state.value.config.ivpn.defaultCountry
            else -> ""
        }.trim()

        if (country.isEmpty()) return servers

        val token = "[${country.lowercase()}]"
        val filtered = servers.filter { it.lowercase().contains(token) }
        return if (filtered.isEmpty()) servers else filtered
    }

    private fun applyConfigToCredential(provider: String, credentialJson: String, config: AppConfigModel): String {
        if (provider != "airvpn") return credentialJson
        return try {
            val obj = JSONObject(credentialJson)
            val defaultDevice = config.airvpn.defaultDevice.trim()
            if (defaultDevice.isNotEmpty()) {
                obj.put("device", defaultDevice)
            }
            obj.toString()
        } catch (_: Exception) {
            credentialJson
        }
    }

    fun connect(context: Context, serverJson: String) {
        val provider = _state.value.selectedProvider
        _state.value = _state.value.copy(
            connectionState = ConnectionState.Connecting,
            activeServer = serverJson,
            errorMessage = "",
        )
        val intent = Intent(context, TunmuxVpnService::class.java).apply {
            action = TunmuxVpnService.ACTION_CONNECT
            putExtra(TunmuxVpnService.EXTRA_PROVIDER, provider)
            putExtra(TunmuxVpnService.EXTRA_SERVER_JSON, serverJson)
        }
        context.startService(intent)
    }

    fun disconnect(context: Context) {
        val intent = Intent(context, TunmuxVpnService::class.java).apply {
            action = TunmuxVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
        _state.value = _state.value.copy(
            connectionState = ConnectionState.Disconnected,
            wgLikeStatus = "",
        )
    }

    private fun ensureStatusPolling() {
        if (statusJob != null) return
        statusJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                refreshConnectionStatusOnce()
                delay(1500)
            }
        }
    }

    private fun refreshConnectionStatusOnce() {
        try {
            val statusJson = JSONObject(RustBridge.getConnectionStatus())
            when (statusJson.optString("state")) {
                "connected" -> {
                    _state.value = _state.value.copy(
                        connectionState = ConnectionState.Connected,
                        wgLikeStatus = buildWgLikeStatus(statusJson),
                    )
                }
                "degraded" -> {
                    _state.value = _state.value.copy(
                        connectionState = ConnectionState.Disconnected,
                        errorMessage = statusJson.optString("reason", "VPN data plane not ready"),
                    )
                }
                else -> {
                    if (_state.value.connectionState == ConnectionState.Connected ||
                        _state.value.connectionState == ConnectionState.Connecting
                    ) {
                        _state.value = _state.value.copy(
                            connectionState = ConnectionState.Disconnected,
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Keep existing UI state if status polling fails momentarily.
        }
    }

    private fun buildWgLikeStatus(status: JSONObject): String {
        val iface = status.optString("interface", "tunmux0")
        val provider = status.optString("provider", _state.value.selectedProvider)
        val backend = status.optString("backend", "userspace")
        val server = status.optString("server", _state.value.activeServer)
        val endpoint = status.optString("endpoint", "")
        val peer = status.optString("peer_public_key", "")
        val selectedKey = status.optString("selected_key", "")
        val keepalive = status.optInt("keepalive_secs", 0)
        val mtu = status.optInt("mtu", 0)

        val addresses = readStringArray(status.optJSONArray("addresses"))
        val allowedIps = readStringArray(status.optJSONArray("allowed_ips"))
        val dns = readStringArray(status.optJSONArray("dns"))

        val connectedSince = status.optLong("connected_since_epoch_secs", 0L)
        val now = System.currentTimeMillis() / 1000L
        val elapsed = if (connectedSince > 0L && now >= connectedSince) now - connectedSince else 0L

        return buildString {
            appendLine("interface: $iface")
            appendLine("  provider: $provider")
            appendLine("  backend: $backend")
            if (addresses.isNotEmpty()) appendLine("  address: ${addresses.joinToString(", ")}")
            if (dns.isNotEmpty()) appendLine("  dns: ${dns.joinToString(", ")}")
            if (mtu > 0) appendLine("  mtu: $mtu")
            appendLine()
            appendLine("peer: ${if (peer.isBlank()) "n/a" else peer}")
            if (server.isNotBlank()) appendLine("  server: $server")
            if (selectedKey.isNotBlank()) appendLine("  selected key: $selectedKey")
            if (endpoint.isNotBlank()) appendLine("  endpoint: $endpoint")
            if (allowedIps.isNotEmpty()) appendLine("  allowed ips: ${allowedIps.joinToString(", ")}")
            appendLine("  latest handshake: ${formatElapsed(elapsed)} ago")
            appendLine("  transfer: n/a")
            if (keepalive > 0) appendLine("  persistent keepalive: $keepalive sec")
        }.trim()
    }

    private fun readStringArray(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val out = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            val v = arr.optString(i)
            if (v.isNotBlank()) out += v
        }
        return out
    }

    private fun formatElapsed(seconds: Long): String {
        if (seconds < 60) return "${seconds}s"
        val minutes = seconds / 60
        if (minutes < 60) return "${minutes}m ${seconds % 60}s"
        val hours = minutes / 60
        return "${hours}h ${minutes % 60}m"
    }

    fun saveConfig(config: AppConfigModel) {
        AppConfigStore.save(ctx, config)
        val oldDefaultDevice = _state.value.config.airvpn.defaultDevice
        _state.value = _state.value.copy(
            config = config,
            settingsMessage = "Config saved",
        )

        if (
            _state.value.selectedProvider == "airvpn" &&
            config.airvpn.defaultDevice.isNotBlank() &&
            !config.airvpn.defaultDevice.equals(oldDefaultDevice, ignoreCase = true)
        ) {
            selectAirvpnKey(config.airvpn.defaultDevice, persistAsDefault = false)
        }
    }

    fun refreshAirvpnSettingsData() {
        viewModelScope.launch(Dispatchers.IO) {
            refreshAirvpnSettingsDataInternal()
        }
    }

    private fun refreshAirvpnSettingsDataInternal() {
        if (_state.value.selectedProvider != "airvpn") return

        try {
            val keysResp = JSONObject(RustBridge.airvpnListKeys())
            if (keysResp.optString("status") != "ok") {
                _state.value = _state.value.copy(
                    settingsMessage = keysResp.optString("error", "Failed to load AirVPN keys"),
                )
                return
            }

            val keysJson = keysResp.optJSONArray("keys") ?: JSONArray()
            val keys = mutableListOf<AirvpnKey>()
            for (i in 0 until keysJson.length()) {
                val row = keysJson.optJSONObject(i) ?: continue
                keys += AirvpnKey(
                    name = row.optString("name"),
                    ipv4 = row.optString("ipv4"),
                    ipv6 = row.optString("ipv6"),
                )
            }

            val devicesResp = JSONObject(RustBridge.airvpnListDevices())
            val devices = mutableListOf<AirvpnDevice>()
            if (devicesResp.optString("status") == "ok") {
                val arr = devicesResp.optJSONArray("devices") ?: JSONArray()
                for (i in 0 until arr.length()) {
                    val row = arr.optJSONObject(i) ?: continue
                    devices += AirvpnDevice(
                        id = row.optString("id"),
                        name = row.optString("name"),
                        ipv4 = row.optString("wg_ipv4"),
                        ipv6 = row.optString("wg_ipv6"),
                        publicKey = row.optString("wg_public_key"),
                    )
                }
            }

            _state.value = _state.value.copy(
                airvpnKeys = keys,
                selectedAirvpnKey = keysResp.optString("selected", ""),
                airvpnDevices = devices,
                settingsMessage = "",
            )
        } catch (e: Exception) {
            Log.e(TAG, "refreshAirvpnSettingsData failed", e)
            _state.value = _state.value.copy(
                settingsMessage = "Failed to load AirVPN key/device data",
            )
        }
    }

    fun selectAirvpnKey(keyName: String, persistAsDefault: Boolean = true) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resp = JSONObject(RustBridge.airvpnSelectKey(keyName))
                if (resp.optString("status") == "ok") {
                    val selected = resp.optString("selected", keyName)
                    var config = _state.value.config
                    if (persistAsDefault) {
                        config = config.copy(
                            airvpn = config.airvpn.copy(defaultDevice = selected),
                        )
                        AppConfigStore.save(ctx, config)
                    }
                    _state.value = _state.value.copy(
                        config = config,
                        selectedAirvpnKey = selected,
                        settingsMessage = "Selected key: $selected",
                    )
                    refreshAirvpnSettingsDataInternal()
                } else {
                    _state.value = _state.value.copy(
                        settingsMessage = resp.optString("error", "Failed to select AirVPN key"),
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "selectAirvpnKey failed", e)
                _state.value = _state.value.copy(
                    settingsMessage = "Failed to select AirVPN key",
                )
            }
        }
    }

    fun addAirvpnDevice(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resp = JSONObject(RustBridge.airvpnAddDevice(name))
                if (resp.optString("status") == "ok") {
                    val selected = resp.optString("selected", _state.value.selectedAirvpnKey)
                    if (selected.isNotBlank()) {
                        val config = _state.value.config.copy(
                            airvpn = _state.value.config.airvpn.copy(defaultDevice = selected),
                        )
                        AppConfigStore.save(ctx, config)
                        _state.value = _state.value.copy(config = config)
                    }
                    _state.value = _state.value.copy(settingsMessage = "Device created")
                    refreshAirvpnSettingsDataInternal()
                } else {
                    _state.value = _state.value.copy(
                        settingsMessage = resp.optString("error", "Failed to add AirVPN device"),
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "addAirvpnDevice failed", e)
                _state.value = _state.value.copy(
                    settingsMessage = "Failed to add AirVPN device",
                )
            }
        }
    }

    fun renameAirvpnDevice(device: String, newName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resp = JSONObject(RustBridge.airvpnRenameDevice(device, newName))
                if (resp.optString("status") == "ok") {
                    var config = _state.value.config
                    if (config.airvpn.defaultDevice.equals(device, ignoreCase = true)) {
                        config = config.copy(
                            airvpn = config.airvpn.copy(defaultDevice = newName.trim()),
                        )
                        AppConfigStore.save(ctx, config)
                    }
                    _state.value = _state.value.copy(
                        config = config,
                        settingsMessage = "Device renamed",
                    )
                    refreshAirvpnSettingsDataInternal()
                } else {
                    _state.value = _state.value.copy(
                        settingsMessage = resp.optString("error", "Failed to rename AirVPN device"),
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "renameAirvpnDevice failed", e)
                _state.value = _state.value.copy(
                    settingsMessage = "Failed to rename AirVPN device",
                )
            }
        }
    }

    fun deleteAirvpnDevice(device: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resp = JSONObject(RustBridge.airvpnDeleteDevice(device))
                if (resp.optString("status") == "ok") {
                    val selected = resp.optString("selected", "")
                    var config = _state.value.config
                    if (selected.isNotBlank()) {
                        config = config.copy(
                            airvpn = config.airvpn.copy(defaultDevice = selected),
                        )
                        AppConfigStore.save(ctx, config)
                    }
                    _state.value = _state.value.copy(
                        config = config,
                        settingsMessage = "Device deleted",
                    )
                    refreshAirvpnSettingsDataInternal()
                } else {
                    _state.value = _state.value.copy(
                        settingsMessage = resp.optString("error", "Failed to delete AirVPN device"),
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "deleteAirvpnDevice failed", e)
                _state.value = _state.value.copy(
                    settingsMessage = "Failed to delete AirVPN device",
                )
            }
        }
    }

    fun setAutoTunnelEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(autoConfig = _state.value.autoConfig.copy(enabled = enabled))
    }

    fun setAutoOnWifi(enabled: Boolean) {
        _state.value = _state.value.copy(autoConfig = _state.value.autoConfig.copy(onWifi = enabled))
    }

    fun setAutoOnMobile(enabled: Boolean) {
        _state.value = _state.value.copy(autoConfig = _state.value.autoConfig.copy(onMobile = enabled))
    }

    fun setStopOnNoInternet(enabled: Boolean) {
        _state.value = _state.value.copy(autoConfig = _state.value.autoConfig.copy(stopOnNoInternet = enabled))
    }

    fun setStartOnBoot(enabled: Boolean) {
        _state.value = _state.value.copy(autoConfig = _state.value.autoConfig.copy(startOnBoot = enabled))
    }

    fun navigateBack() {
        _state.value = when (_state.value.screen) {
            Screen.Login -> _state.value.copy(screen = Screen.ProviderSelect)
            Screen.ProviderSelect, Screen.Dashboard -> _state.value
        }
    }
}

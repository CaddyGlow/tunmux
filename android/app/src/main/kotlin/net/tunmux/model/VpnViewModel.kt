package net.tunmux.model

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import net.tunmux.KeystoreCredentials
import net.tunmux.AutoTunnelService
import net.tunmux.RustBridge
import net.tunmux.TunmuxVpnService
import org.json.JSONArray
import org.json.JSONObject

enum class Screen { ProviderSelect, Login, Dashboard }
enum class DashboardTab { Main, Tunnels, Config, Settings, Auto }
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

data class SplitTunnelApp(
    val packageName: String,
    val label: String,
)

data class UiState(
    val screen: Screen = Screen.Dashboard,
    val selectedProvider: String = "proton",
    val isLoggedIn: Boolean = false,
    val loggedInUsername: String = "",
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
    val providerCurrentKeys: Map<String, String> = emptyMap(),
    val settingsMessage: String = "",
    val autoConfig: AutoTunnelConfig = AutoTunnelConfig(),
    val splitTunnelApps: List<SplitTunnelApp> = emptyList(),
    val connectedWifiSsid: String = "",
    val knownWifiSsids: List<String> = emptyList(),
    val locationPermissionGranted: Boolean = false,
    val locationServicesEnabled: Boolean = false,
    val localProxyAddress: String? = null,
)

class VpnViewModel(app: Application) : AndroidViewModel(app) {
    companion object {
        private const val TAG = "tunmux"
    }

    private val ctx get() = getApplication<Application>()

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    private var statusJob: Job? = null
    private var networkMonitorJob: Job? = null
    private var currentWifiSsid: String = ""
    private val networkMonitor = AndroidNetworkMonitor(ctx)

    init {
        val config = AppConfigStore.load(ctx)
        val runtime = AutoRuntimeStore.load(ctx)
        _state.value = _state.value.copy(
            config = config,
            autoConfig = config.auto,
            selectedProvider = runtime.provider.ifBlank { _state.value.selectedProvider },
            activeServer = runtime.server,
        )
        ensureStatusPolling()
        startNetworkMonitoring()
        if (config.auto.enabled) {
            startAutoTunnelService(AutoTunnelService.ACTION_START)
        }
        loadInstalledApps()
        refreshKnownWifiSsids()

        // Attempt silent re-login with credentials stored in Keystore.
        val saved = KeystoreCredentials.load(ctx)
        if (saved != null) {
            val (provider, savedCredential) = saved
            _state.value = _state.value.copy(
                selectedProvider = provider,
                activeServer = if (runtime.provider.equals(provider, ignoreCase = true)) {
                    runtime.server
                } else {
                    ""
                },
            )
            AutoRuntimeStore.saveProvider(ctx, provider)
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
                            isLoggedIn = true,
                            loggedInUsername = extractUsername(savedCredential),
                        )
                        if (provider == "airvpn") {
                            refreshAirvpnSettingsDataInternal()
                        }
                        evaluateAutoTunnel("auto-login")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "auto-login failed provider=$provider", e)
                }
            }
        }
    }

    override fun onCleared() {
        networkMonitor.stop()
        networkMonitorJob?.cancel()
        statusJob?.cancel()
        super.onCleared()
    }

    fun selectProvider(provider: String) {
        val prev = _state.value
        if (prev.isLoggedIn) {
            val prevProvider = prev.selectedProvider
            KeystoreCredentials.clear(ctx)
            AutoRuntimeStore.clear(ctx)
            viewModelScope.launch(Dispatchers.IO) {
                runCatching { RustBridge.logout(prevProvider) }
            }
        }
        AutoRuntimeStore.saveProvider(ctx, provider)
        _state.value = prev.copy(
            selectedProvider = provider,
            isLoggedIn = false,
            loggedInUsername = "",
            serverList = emptyList(),
            activeServer = "",
            connectionState = ConnectionState.Disconnected,
            wgLikeStatus = "",
            errorMessage = "",
            settingsMessage = "",
        )
    }

    fun openLogin() {
        _state.value = _state.value.copy(screen = Screen.Login, errorMessage = "")
    }

    fun switchTab(tab: DashboardTab) {
        _state.value = _state.value.copy(activeTab = tab, errorMessage = "")
        if (tab == DashboardTab.Config && _state.value.selectedProvider == "airvpn") {
            refreshAirvpnSettingsData()
        }
        if (tab == DashboardTab.Auto) {
            refreshKnownWifiSsids()
            networkMonitor.refreshPermissions()
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
                    AutoRuntimeStore.saveProvider(ctx, provider)
                    KeystoreCredentials.save(ctx, provider, credentialToStore)
                    val servers = fetchServersNow(provider) ?: return@launch
                    _state.value = _state.value.copy(
                        screen = Screen.Dashboard,
                        activeTab = DashboardTab.Main,
                        serverList = servers,
                        errorMessage = "",
                        isLoggedIn = true,
                        loggedInUsername = username,
                    )
                    if (provider == "airvpn") {
                        refreshAirvpnSettingsDataInternal()
                    }
                    evaluateAutoTunnel("manual-login")
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
        AutoRuntimeStore.clear(ctx)
        val config = _state.value.config
        val splitApps = _state.value.splitTunnelApps
        _state.value = UiState(
            screen = Screen.Dashboard,
            selectedProvider = provider,
            isLoggedIn = false,
            loggedInUsername = "",
            config = config,
            autoConfig = config.auto,
            splitTunnelApps = splitApps,
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
        val server = serverJson.trim()
        var config = _state.value.config
        val countryCode = extractCountryCodeFromServer(server)
        if (countryCode.isNotBlank()) {
            val updated = updateProviderDefaultCountry(config, provider, countryCode)
            if (updated != config) {
                config = updated
                AppConfigStore.save(ctx, config)
            }
        }
        AutoRuntimeStore.save(ctx, provider, server)
        _state.value = _state.value.copy(
            connectionState = ConnectionState.Connecting,
            activeServer = server,
            config = config,
            errorMessage = "",
        )
        val intent = Intent(context, TunmuxVpnService::class.java).apply {
            action = TunmuxVpnService.ACTION_CONNECT
            putExtra(TunmuxVpnService.EXTRA_PROVIDER, provider)
            putExtra(TunmuxVpnService.EXTRA_SERVER_JSON, server)
            putExtra(TunmuxVpnService.EXTRA_APP_MODE, config.general.appMode)
            putStringArrayListExtra(
                TunmuxVpnService.EXTRA_SPLIT_TUNNEL_APPS,
                ArrayList(config.general.splitTunnelApps),
            )
            putExtra(
                TunmuxVpnService.EXTRA_SPLIT_TUNNEL_ONLY_ALLOW_SELECTED,
                config.general.splitTunnelOnlyAllowSelected,
            )
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
            val prev = _state.value
            val provider = statusJson.optString("provider", prev.selectedProvider).trim().lowercase()
            val server = statusJson.optString("server", prev.activeServer).trim()
            val selectedKey = statusJson.optString("selected_key", "").trim()
            val providerKeys = if (provider.isNotBlank() && selectedKey.isNotBlank()) {
                prev.providerCurrentKeys + (provider to selectedKey)
            } else {
                prev.providerCurrentKeys
            }
            when (statusJson.optString("state")) {
                "connected" -> {
                    _state.value = _state.value.copy(
                        connectionState = ConnectionState.Connected,
                        selectedProvider = provider.ifBlank { prev.selectedProvider },
                        activeServer = server.ifBlank { prev.activeServer },
                        providerCurrentKeys = providerKeys,
                        wgLikeStatus = buildWgLikeStatus(statusJson),
                    )
                    if (
                        provider.isNotBlank() &&
                        server.isNotBlank() &&
                        (provider != prev.selectedProvider || server != prev.activeServer)
                    ) {
                        AutoRuntimeStore.save(ctx, provider, server)
                    }
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
        } catch (_: Throwable) {
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

        val latestHandshakeAgeSecs = status.optNullableLong("latest_handshake_age_secs")
        val rxBytes = status.optNullableLong("rx_bytes")
        val txBytes = status.optNullableLong("tx_bytes")

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
            if (latestHandshakeAgeSecs != null) {
                appendLine("  latest handshake: ${formatElapsed(latestHandshakeAgeSecs)} ago")
            } else {
                appendLine("  latest handshake: ${formatElapsed(elapsed)} ago")
            }
            val transfer = if (rxBytes != null && txBytes != null) {
                "${formatBytes(rxBytes)} received, ${formatBytes(txBytes)} sent"
            } else {
                "n/a"
            }
            appendLine("  transfer: $transfer")
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

    private fun formatBytes(bytes: Long): String {
        val kib = 1024.0
        val mib = kib * 1024.0
        val gib = mib * 1024.0
        val v = bytes.toDouble()
        return when {
            v >= gib -> String.format("%.2f GiB", v / gib)
            v >= mib -> String.format("%.2f MiB", v / mib)
            v >= kib -> String.format("%.1f KiB", v / kib)
            else -> "$bytes B"
        }
    }

    private fun extractCountryCodeFromServer(server: String): String {
        val match = "\\[([A-Za-z]{2})\\]".toRegex().find(server.trim()) ?: return ""
        return match.groupValues.getOrNull(1)?.uppercase().orEmpty()
    }

    private fun updateProviderDefaultCountry(config: AppConfigModel, provider: String, countryCode: String): AppConfigModel {
        val code = countryCode.trim().uppercase()
        if (code.length != 2) return config
        return when (provider.trim().lowercase()) {
            "proton" ->
                if (config.proton.defaultCountry.equals(code, ignoreCase = true)) config else
                    config.copy(proton = config.proton.copy(defaultCountry = code))
            "airvpn" ->
                if (config.airvpn.defaultCountry.equals(code, ignoreCase = true)) config else
                    config.copy(airvpn = config.airvpn.copy(defaultCountry = code))
            "mullvad" ->
                if (config.mullvad.defaultCountry.equals(code, ignoreCase = true)) config else
                    config.copy(mullvad = config.mullvad.copy(defaultCountry = code))
            "ivpn" ->
                if (config.ivpn.defaultCountry.equals(code, ignoreCase = true)) config else
                    config.copy(ivpn = config.ivpn.copy(defaultCountry = code))
            else -> config
        }
    }

    fun saveConfig(config: AppConfigModel) {
        AppConfigStore.save(ctx, config)
        val oldDefaultDevice = _state.value.config.airvpn.defaultDevice
        _state.value = _state.value.copy(
            config = config,
            autoConfig = config.auto,
            settingsMessage = "Config saved",
        )

        if (
            _state.value.selectedProvider == "airvpn" &&
            config.airvpn.defaultDevice.isNotBlank() &&
            !config.airvpn.defaultDevice.equals(oldDefaultDevice, ignoreCase = true)
        ) {
            selectAirvpnKey(config.airvpn.defaultDevice, persistAsDefault = false)
        }
        evaluateAutoTunnel("config-saved")
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

            val selected = keysResp.optString("selected", "").trim()
            val previous = _state.value
            val updatedConfig = if (
                selected.isNotBlank() &&
                !previous.config.airvpn.defaultDevice.equals(selected, ignoreCase = true)
            ) {
                previous.config.copy(
                    airvpn = previous.config.airvpn.copy(defaultDevice = selected),
                ).also { AppConfigStore.save(ctx, it) }
            } else {
                previous.config
            }
            val providerKeys = if (selected.isNotBlank()) {
                previous.providerCurrentKeys + ("airvpn" to selected)
            } else {
                previous.providerCurrentKeys
            }
            _state.value = _state.value.copy(
                config = updatedConfig,
                airvpnKeys = keys,
                selectedAirvpnKey = selected,
                airvpnDevices = devices,
                providerCurrentKeys = providerKeys,
                settingsMessage = "",
            )
        } catch (e: Throwable) {
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
                        providerCurrentKeys = if (selected.isNotBlank()) {
                            _state.value.providerCurrentKeys + ("airvpn" to selected)
                        } else {
                            _state.value.providerCurrentKeys
                        },
                        settingsMessage = "Selected key: $selected",
                    )
                    refreshAirvpnSettingsDataInternal()
                } else {
                    _state.value = _state.value.copy(
                        settingsMessage = resp.optString("error", "Failed to select AirVPN key"),
                    )
                }
            } catch (e: Throwable) {
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
            } catch (e: Throwable) {
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
            } catch (e: Throwable) {
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
            } catch (e: Throwable) {
                Log.e(TAG, "deleteAirvpnDevice failed", e)
                _state.value = _state.value.copy(
                    settingsMessage = "Failed to delete AirVPN device",
                )
            }
        }
    }

    fun setAutoTunnelEnabled(enabled: Boolean) {
        updateAutoConfig { it.copy(enabled = enabled) }
    }

    fun setAutoOnWifi(enabled: Boolean) {
        updateAutoConfig { it.copy(onWifi = enabled) }
    }

    fun setAutoOnMobile(enabled: Boolean) {
        updateAutoConfig { it.copy(onMobile = enabled) }
    }

    fun setAutoOnEthernet(enabled: Boolean) {
        updateAutoConfig { it.copy(onEthernet = enabled) }
    }

    fun setAutoWifiSsids(rawValue: String) {
        val parsed = parseWifiSsidInput(rawValue)
        updateAutoConfig { it.copy(wifiSsids = parsed) }
    }

    fun setAutoWifiDetectionMethod(method: WifiDetectionMethod) {
        updateAutoConfig { it.copy(wifiDetectionMethod = method) }
        networkMonitor.updateDetectionMethod(method)
        networkMonitor.refreshPermissions()
    }

    fun setAutoDebounceDelaySeconds(seconds: Int) {
        updateAutoConfig { it.copy(debounceDelaySeconds = seconds.coerceIn(0, 60)) }
    }

    fun refreshAutoNetworkPermissions() {
        networkMonitor.refreshPermissions()
    }

    fun setAutoDisconnectOnMatchedWifi(enabled: Boolean) {
        updateAutoConfig { it.copy(disconnectOnMatchedWifi = enabled) }
    }

    fun addConnectedWifiToAutoList() {
        addAutoWifiSsid(currentWifiSsid)
    }

    fun addAutoWifiSsid(ssid: String) {
        val normalized = normalizeSsid(ssid)
        if (normalized.isEmpty()) return
        val merged = (_state.value.autoConfig.wifiSsids + normalized)
            .distinctBy { it.lowercase() }
        updateAutoConfig { it.copy(wifiSsids = merged) }
    }

    fun setStopOnNoInternet(enabled: Boolean) {
        updateAutoConfig { it.copy(stopOnNoInternet = enabled) }
    }

    fun setStartOnBoot(enabled: Boolean) {
        updateAutoConfig { it.copy(startOnBoot = enabled) }
    }

    fun setAppMode(mode: String) {
        val normalized = if (mode.equals("split", ignoreCase = true)) "split" else "vpn"
        val config = _state.value.config.copy(
            general = _state.value.config.general.copy(appMode = normalized),
        )
        AppConfigStore.save(ctx, config)
        _state.value = _state.value.copy(
            config = config,
            settingsMessage = "App mode set to $normalized",
        )
        evaluateAutoTunnel("app-mode-changed")
    }

    fun setSplitTunnelApp(packageName: String, enabled: Boolean) {
        val current = _state.value.config.general.splitTunnelApps.toMutableSet()
        if (enabled) {
            current += packageName
        } else {
            current -= packageName
        }

        val config = _state.value.config.copy(
            general = _state.value.config.general.copy(
                splitTunnelApps = current.toList().sorted(),
            ),
        )
        AppConfigStore.save(ctx, config)
        _state.value = _state.value.copy(config = config)
    }

    fun setSplitTunnelOnlyAllowSelected(enabled: Boolean) {
        val config = _state.value.config.copy(
            general = _state.value.config.general.copy(
                splitTunnelOnlyAllowSelected = enabled,
            ),
        )
        AppConfigStore.save(ctx, config)
        _state.value = _state.value.copy(config = config)
    }

    fun setServerFavorite(server: String, favorite: Boolean) {
        val normalized = server.trim()
        if (normalized.isEmpty()) return

        val current = _state.value.config.general.favoriteServers
        val next = if (favorite) {
            (current + normalized).distinctBy { it.lowercase() }.sortedBy { it.lowercase() }
        } else {
            current.filterNot { it.equals(normalized, ignoreCase = true) }
        }
        if (next == current) return

        val config = _state.value.config.copy(
            general = _state.value.config.general.copy(favoriteServers = next),
        )
        AppConfigStore.save(ctx, config)
        _state.value = _state.value.copy(config = config)
    }

    private fun updateAutoConfig(update: (AutoTunnelConfig) -> AutoTunnelConfig) {
        val current = _state.value.autoConfig
        val next = update(current)
        val config = _state.value.config.copy(auto = next)
        AppConfigStore.save(ctx, config)
        _state.value = _state.value.copy(
            config = config,
            autoConfig = next,
        )
        evaluateAutoTunnel("auto-config-changed")
    }

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    private fun startNetworkMonitoring() {
        val detectionMethod = _state.value.autoConfig.wifiDetectionMethod
        networkMonitor.start(detectionMethod)
        networkMonitorJob?.cancel()
        networkMonitorJob =
            viewModelScope.launch {
                _state
                    .map { it.autoConfig.debounceDelaySeconds }
                    .distinctUntilChanged()
                    .flatMapLatest { seconds ->
                        if (seconds <= 0) {
                            networkMonitor.state
                        } else {
                            networkMonitor.state.debounce(seconds * 1000L)
                        }
                    }
                    .collectLatest { snapshot ->
                    currentWifiSsid = snapshot.wifiSsid
                    _state.value =
                        _state.value.copy(
                            connectedWifiSsid = snapshot.wifiSsid,
                            locationPermissionGranted = snapshot.locationPermissionGranted,
                            locationServicesEnabled = snapshot.locationServicesEnabled,
                        )
                    }
            }
    }

    private fun evaluateAutoTunnel(reason: String) {
        val action =
            if (_state.value.autoConfig.enabled) {
                AutoTunnelService.ACTION_REFRESH
            } else {
                AutoTunnelService.ACTION_STOP
            }
        Log.d(TAG, "auto-tunnel service sync reason=$reason action=$action")
        startAutoTunnelService(action)
    }

    private fun startAutoTunnelService(action: String) {
        val intent = Intent(ctx, AutoTunnelService::class.java).apply { this.action = action }
        runCatching {
            if (action == AutoTunnelService.ACTION_STOP) {
                ctx.startService(intent)
            } else {
                ctx.startForegroundService(intent)
            }
        }.onFailure { Log.w(TAG, "auto-tunnel service action failed: $action", it) }
    }

    private fun loadInstalledApps() {
        viewModelScope.launch(Dispatchers.IO) {
            val pm = ctx.packageManager
            val selected = _state.value.config.general.splitTunnelApps.toSet()
            val apps = mutableListOf<SplitTunnelApp>()
            val launchIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val launcherActivities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(launchIntent, PackageManager.ResolveInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launchIntent, 0)
            }

            val seenPackages = HashSet<String>()
            for (resolveInfo in launcherActivities) {
                val activityInfo = resolveInfo.activityInfo ?: continue
                val packageName = activityInfo.packageName
                if (packageName == ctx.packageName) continue
                if (!seenPackages.add(packageName)) continue
                val label = resolveInfo.loadLabel(pm)?.toString().orEmpty().ifBlank { packageName }
                apps += SplitTunnelApp(packageName = packageName, label = label)
            }

            apps.sortBy { it.label.lowercase() }
            val cleanedSelection = selected.intersect(apps.map { it.packageName }.toSet())
                .toList()
                .sorted()
            val nextConfig = _state.value.config.copy(
                general = _state.value.config.general.copy(
                    splitTunnelApps = cleanedSelection,
                ),
            )
            if (cleanedSelection != _state.value.config.general.splitTunnelApps) {
                AppConfigStore.save(ctx, nextConfig)
            }
            _state.value = _state.value.copy(
                splitTunnelApps = apps,
                config = nextConfig,
            )
        }
    }

    fun refreshKnownWifiSsids() {
        viewModelScope.launch(Dispatchers.IO) {
            val known = loadKnownWifiSsids()
            _state.value = _state.value.copy(knownWifiSsids = known)
        }
    }

    private fun loadKnownWifiSsids(): List<String> {
        return try {
            val wifiManager = ctx.applicationContext.getSystemService(WifiManager::class.java)
                ?: return emptyList()
            @Suppress("DEPRECATION")
            val configured = wifiManager.configuredNetworks ?: emptyList()
            configured
                .mapNotNull { normalizeSsid(it.SSID) }
                .filter { it.isNotEmpty() }
                .distinctBy { it.lowercase() }
                .sortedBy { it.lowercase() }
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun connectLocalProxy(serverJson: String) {
        val provider = _state.value.selectedProvider
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = JSONObject(RustBridge.startLocalProxy(provider, serverJson, 0, 0))
                if (result.optString("status") == "ok") {
                    val socks = result.optInt("socks_port", 0)
                    val http = result.optInt("http_port", 0)
                    _state.value = _state.value.copy(
                        localProxyAddress = "SOCKS5 127.0.0.1:$socks  HTTP 127.0.0.1:$http",
                        errorMessage = "",
                    )
                } else {
                    _state.value = _state.value.copy(
                        errorMessage = result.optString("error", "Failed to start local proxy"),
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "connectLocalProxy failed provider=$provider", e)
                _state.value = _state.value.copy(errorMessage = e.message ?: "unexpected error")
            }
        }
    }

    fun disconnectLocalProxy() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                RustBridge.stopLocalProxy()
            } catch (e: Exception) {
                Log.e(TAG, "disconnectLocalProxy failed", e)
            }
            _state.value = _state.value.copy(localProxyAddress = null)
        }
    }

    fun createAccount(provider: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = JSONObject(RustBridge.createAccount(provider))
                if (result.optString("status") == "ok") {
                    val id = result.optString("account_number").ifBlank { result.optString("account_id") }
                    _state.value = _state.value.copy(settingsMessage = "Account created: $id")
                } else {
                    _state.value = _state.value.copy(
                        errorMessage = result.optString("error", "Failed to create account"),
                    )
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "unexpected error")
            }
        }
    }

    private fun extractUsername(credentialJson: String): String =
        try { JSONObject(credentialJson).optString("username", "") } catch (_: Exception) { "" }

    fun navigateBack() {
        _state.value = when (_state.value.screen) {
            Screen.Login -> _state.value.copy(screen = Screen.Dashboard)
            Screen.ProviderSelect, Screen.Dashboard -> _state.value
        }
    }
}

private fun JSONObject.optNullableLong(key: String): Long? {
    if (!has(key) || isNull(key)) return null
    return try {
        getLong(key)
    } catch (_: Exception) {
        null
    }
}

private fun parseWifiSsidInput(rawValue: String): List<String> {
    return rawValue
        .split(",", "\n")
        .map { normalizeSsid(it) }
        .filter { it.isNotEmpty() }
        .distinctBy { it.lowercase() }
}

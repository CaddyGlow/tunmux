package net.tunmux

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import net.tunmux.model.AirvpnDevice
import net.tunmux.model.AirvpnKey
import net.tunmux.model.AirvpnConfig
import net.tunmux.model.AppConfigModel
import net.tunmux.model.AutoTunnelConfig
import net.tunmux.model.ConnectionState
import net.tunmux.model.DashboardTab
import net.tunmux.model.GeneralConfig
import net.tunmux.model.ProviderConfig
import net.tunmux.model.Screen
import net.tunmux.model.SplitTunnelApp
import net.tunmux.model.VpnViewModel

private val TunmuxDarkColors = darkColorScheme(
    primary = Color(0xFF69C7CC),
    onPrimary = Color(0xFF0E161D),
    background = Color(0xFF121D26),
    onBackground = Color(0xFFD6E0E8),
    surface = Color(0xFF18242F),
    onSurface = Color(0xFFD6E0E8),
    secondary = Color(0xFF6EAAB0),
    onSecondary = Color(0xFF0E161D),
)

class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            pendingConnectAction?.invoke()
        }
        pendingConnectAction = null
    }

    private var pendingConnectAction: (() -> Unit)? = null

    fun requestVpnPermissionAndConnect(onGranted: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            onGranted()
        } else {
            pendingConnectAction = onGranted
            vpnPermissionLauncher.launch(intent)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = TunmuxDarkColors) {
                TunmuxApp()
            }
        }
    }
}

@Composable
fun TunmuxApp(vm: VpnViewModel = viewModel()) {
    val state by vm.state.collectAsState()
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? MainActivity

    when (state.screen) {
        Screen.ProviderSelect -> ProviderScreen(
            onSelect = { vm.selectProvider(it) }
        )
        Screen.Login -> LoginScreen(
            provider = state.selectedProvider,
            error = state.errorMessage,
            onLogin = { u, p, t -> vm.login(u, p, t) },
            onBack = { vm.navigateBack() },
        )
        Screen.Dashboard -> DashboardScreen(
            provider = state.selectedProvider,
            tab = state.activeTab,
            connectionState = state.connectionState,
            error = state.errorMessage,
            settingsMessage = state.settingsMessage,
            servers = state.serverList,
            activeServer = state.activeServer,
            wgLikeStatus = state.wgLikeStatus,
            config = state.config,
            airvpnKeys = state.airvpnKeys,
            selectedAirvpnKey = state.selectedAirvpnKey,
            airvpnDevices = state.airvpnDevices,
            autoConfig = state.autoConfig,
            splitTunnelApps = state.splitTunnelApps,
            onTabSelect = { vm.switchTab(it) },
            onConnect = { server ->
                activity?.requestVpnPermissionAndConnect {
                    vm.connect(context, server)
                }
            },
            onDisconnect = { vm.disconnect(context) },
            onLogout = { vm.logout() },
            onSaveConfig = { vm.saveConfig(it) },
            onRefreshAirvpn = { vm.refreshAirvpnSettingsData() },
            onSelectAirvpnKey = { vm.selectAirvpnKey(it) },
            onAddAirvpnDevice = { vm.addAirvpnDevice(it) },
            onRenameAirvpnDevice = { from, to -> vm.renameAirvpnDevice(from, to) },
            onDeleteAirvpnDevice = { vm.deleteAirvpnDevice(it) },
            onSetAutoEnabled = { vm.setAutoTunnelEnabled(it) },
            onSetAutoWifi = { vm.setAutoOnWifi(it) },
            onSetAutoMobile = { vm.setAutoOnMobile(it) },
            onSetAutoEthernet = { vm.setAutoOnEthernet(it) },
            onSetStopOnNoInternet = { vm.setStopOnNoInternet(it) },
            onSetStartOnBoot = { vm.setStartOnBoot(it) },
            onSetAppMode = { vm.setAppMode(it) },
            onSetSplitTunnelOnlyAllowSelected = { vm.setSplitTunnelOnlyAllowSelected(it) },
            onSetSplitTunnelApp = { pkg, enabled -> vm.setSplitTunnelApp(pkg, enabled) },
        )
    }
}

@Composable
fun ProviderScreen(onSelect: (String) -> Unit) {
    val providers = listOf("proton", "airvpn", "mullvad", "ivpn")
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Tunnels", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(20.dp))
        for (p in providers) {
            Card(
                onClick = { onSelect(p) },
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 6.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("•", color = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.padding(horizontal = 6.dp))
                    Text(p)
                }
            }
        }
    }
}

@Composable
fun LoginScreen(
    provider: String,
    error: String,
    onLogin: (String, String, String) -> Unit,
    onBack: () -> Unit,
) {
    val needsPassword = provider == "proton" || provider == "airvpn"
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var twoFa by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("$provider login", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = username,
            onValueChange = { username = it },
            label = { Text(if (needsPassword) "Username" else "Account Number") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        if (needsPassword) {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        if (provider == "proton") {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = twoFa,
                onValueChange = { twoFa = it },
                label = { Text("2FA code") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        if (error.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text(error, color = Color(0xFFFF8A80))
        }

        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Button(onClick = { onLogin(username, password, twoFa) }) { Text("Login") }
        }
    }
}

@Composable
fun DashboardScreen(
    provider: String,
    tab: DashboardTab,
    connectionState: ConnectionState,
    error: String,
    settingsMessage: String,
    servers: List<String>,
    activeServer: String,
    wgLikeStatus: String,
    config: AppConfigModel,
    airvpnKeys: List<AirvpnKey>,
    selectedAirvpnKey: String,
    airvpnDevices: List<AirvpnDevice>,
    autoConfig: AutoTunnelConfig,
    splitTunnelApps: List<SplitTunnelApp>,
    onTabSelect: (DashboardTab) -> Unit,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onLogout: () -> Unit,
    onSaveConfig: (AppConfigModel) -> Unit,
    onRefreshAirvpn: () -> Unit,
    onSelectAirvpnKey: (String) -> Unit,
    onAddAirvpnDevice: (String) -> Unit,
    onRenameAirvpnDevice: (String, String) -> Unit,
    onDeleteAirvpnDevice: (String) -> Unit,
    onSetAutoEnabled: (Boolean) -> Unit,
    onSetAutoWifi: (Boolean) -> Unit,
    onSetAutoMobile: (Boolean) -> Unit,
    onSetAutoEthernet: (Boolean) -> Unit,
    onSetStopOnNoInternet: (Boolean) -> Unit,
    onSetStartOnBoot: (Boolean) -> Unit,
    onSetAppMode: (String) -> Unit,
    onSetSplitTunnelOnlyAllowSelected: (Boolean) -> Unit,
    onSetSplitTunnelApp: (String, Boolean) -> Unit,
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF16232D)) {
                DashboardTab.entries.forEach { item ->
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { onTabSelect(item) },
                        icon = {
                            Text(
                                when (item) {
                                    DashboardTab.Main -> "H"
                                    DashboardTab.Config -> "B"
                                    DashboardTab.Settings -> "S"
                                    DashboardTab.Auto -> "A"
                                }
                            )
                        },
                        label = {
                            Text(
                                when (item) {
                                    DashboardTab.Main -> "Home"
                                    DashboardTab.Config -> "Config"
                                    DashboardTab.Settings -> "Settings"
                                    DashboardTab.Auto -> "Auto"
                                }
                            )
                        },
                        alwaysShowLabel = false,
                    )
                }
            }
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("$provider", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.weight(1f))
                OutlinedButton(onClick = onLogout) { Text("Logout") }
            }

            if (error.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(error, color = Color(0xFFFF8A80))
            }
            if (settingsMessage.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(settingsMessage, color = MaterialTheme.colorScheme.primary)
            }

            Spacer(Modifier.height(8.dp))

            when (tab) {
                DashboardTab.Main -> MainTabContent(
                    connectionState = connectionState,
                    servers = servers,
                    activeServer = activeServer,
                    wgLikeStatus = wgLikeStatus,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                )
                DashboardTab.Config -> ConfigTabContent(
                    provider = provider,
                    config = config,
                    airvpnKeys = airvpnKeys,
                    selectedAirvpnKey = selectedAirvpnKey,
                    airvpnDevices = airvpnDevices,
                    onSaveConfig = onSaveConfig,
                    onRefreshAirvpn = onRefreshAirvpn,
                    onSelectAirvpnKey = onSelectAirvpnKey,
                    onAddAirvpnDevice = onAddAirvpnDevice,
                    onRenameAirvpnDevice = onRenameAirvpnDevice,
                    onDeleteAirvpnDevice = onDeleteAirvpnDevice,
                )
                DashboardTab.Settings -> SettingsTabContent(
                    config = config,
                    splitTunnelApps = splitTunnelApps,
                    onSaveConfig = onSaveConfig,
                    onSetAppMode = onSetAppMode,
                    onSetSplitTunnelOnlyAllowSelected = onSetSplitTunnelOnlyAllowSelected,
                    onSetSplitTunnelApp = onSetSplitTunnelApp,
                )
                DashboardTab.Auto -> AutoTabContent(
                    autoConfig = autoConfig,
                    onSetAutoEnabled = onSetAutoEnabled,
                    onSetAutoWifi = onSetAutoWifi,
                    onSetAutoMobile = onSetAutoMobile,
                    onSetAutoEthernet = onSetAutoEthernet,
                    onSetStopOnNoInternet = onSetStopOnNoInternet,
                    onSetStartOnBoot = onSetStartOnBoot,
                )
            }
        }
    }
}

@Composable
private fun MainTabContent(
    connectionState: ConnectionState,
    servers: List<String>,
    activeServer: String,
    wgLikeStatus: String,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                when (connectionState) {
                    ConnectionState.Connected -> "Connected"
                    ConnectionState.Connecting -> "Connecting..."
                    ConnectionState.Disconnected -> "Disconnected"
                },
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (connectionState == ConnectionState.Connected) {
                    Button(onClick = onDisconnect) { Text("Disconnect") }
                } else {
                    val target = if (activeServer.isNotBlank()) activeServer else servers.firstOrNull().orEmpty()
                    Button(onClick = { if (target.isNotBlank()) onConnect(target) }) { Text("Connect") }
                }
            }
            if (wgLikeStatus.isNotBlank()) {
                Spacer(Modifier.height(10.dp))
                Text(wgLikeStatus, fontFamily = FontFamily.Monospace)
            }
        }
    }

    Spacer(Modifier.height(10.dp))
    Text("Tunnels", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(6.dp))

    if (servers.isEmpty()) {
        Text("No servers available")
        return
    }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        items(servers.take(160)) { server ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                onClick = { onConnect(server) },
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("•", color = MaterialTheme.colorScheme.secondary)
                    Spacer(Modifier.padding(horizontal = 6.dp))
                    Text(server, modifier = Modifier.weight(1f))
                    Switch(
                        checked = connectionState == ConnectionState.Connected && activeServer == server,
                        onCheckedChange = { checked ->
                            if (checked) onConnect(server) else onDisconnect()
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun ConfigTabContent(
    provider: String,
    config: AppConfigModel,
    airvpnKeys: List<AirvpnKey>,
    selectedAirvpnKey: String,
    airvpnDevices: List<AirvpnDevice>,
    onSaveConfig: (AppConfigModel) -> Unit,
    onRefreshAirvpn: () -> Unit,
    onSelectAirvpnKey: (String) -> Unit,
    onAddAirvpnDevice: (String) -> Unit,
    onRenameAirvpnDevice: (String, String) -> Unit,
    onDeleteAirvpnDevice: (String) -> Unit,
) {
    var protonCountry by remember(config) { mutableStateOf(config.proton.defaultCountry) }
    var airvpnCountry by remember(config) { mutableStateOf(config.airvpn.defaultCountry) }
    var airvpnDevice by remember(config) { mutableStateOf(config.airvpn.defaultDevice) }
    var mullvadCountry by remember(config) { mutableStateOf(config.mullvad.defaultCountry) }
    var ivpnCountry by remember(config) { mutableStateOf(config.ivpn.defaultCountry) }

    var addDeviceName by remember { mutableStateOf("") }
    var renameFrom by remember { mutableStateOf("") }
    var renameTo by remember { mutableStateOf("") }
    var deleteName by remember { mutableStateOf("") }

    val saveConfig = {
        onSaveConfig(
            config.copy(
                proton = ProviderConfig(defaultCountry = protonCountry.trim()),
                airvpn = AirvpnConfig(
                    defaultCountry = airvpnCountry.trim(),
                    defaultDevice = airvpnDevice.trim(),
                ),
                mullvad = ProviderConfig(defaultCountry = mullvadCountry.trim()),
                ivpn = ProviderConfig(defaultCountry = ivpnCountry.trim()),
            )
        )
    }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = saveConfig) { Text("Save") }
                if (provider == "airvpn") {
                    OutlinedButton(onClick = onRefreshAirvpn) { Text("Refresh") }
                }
            }
        }

        item { Text("Provider defaults", style = MaterialTheme.typography.titleMedium) }
        item {
            OutlinedTextField(
                value = protonCountry,
                onValueChange = { protonCountry = it },
                label = { Text("proton.default_country") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = airvpnCountry,
                onValueChange = { airvpnCountry = it },
                label = { Text("airvpn.default_country") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = airvpnDevice,
                onValueChange = { airvpnDevice = it },
                label = { Text("airvpn.default_device") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = mullvadCountry,
                onValueChange = { mullvadCountry = it },
                label = { Text("mullvad.default_country") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = ivpnCountry,
                onValueChange = { ivpnCountry = it },
                label = { Text("ivpn.default_country") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        if (provider == "airvpn") {
            item { Spacer(Modifier.height(6.dp)) }
            item { Text("AirVPN devices and keys", style = MaterialTheme.typography.titleMedium) }
            item { Text("Selected key: $selectedAirvpnKey") }

            if (airvpnKeys.isEmpty()) {
                item { Text("No AirVPN keys") }
            } else {
                items(airvpnKeys) { key ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(key.name)
                                if (key.ipv4.isNotBlank()) Text(key.ipv4)
                            }
                            OutlinedButton(onClick = { onSelectAirvpnKey(key.name) }) {
                                Text("Select")
                            }
                        }
                    }
                }
            }

            item {
                OutlinedTextField(
                    value = addDeviceName,
                    onValueChange = { addDeviceName = it },
                    label = { Text("Create device") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
            item {
                Button(onClick = {
                    onAddAirvpnDevice(addDeviceName)
                    addDeviceName = ""
                }) { Text("Create") }
            }

            item {
                OutlinedTextField(
                    value = renameFrom,
                    onValueChange = { renameFrom = it },
                    label = { Text("Rename from") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
            item {
                OutlinedTextField(
                    value = renameTo,
                    onValueChange = { renameTo = it },
                    label = { Text("Rename to") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
            item {
                Button(onClick = {
                    onRenameAirvpnDevice(renameFrom, renameTo)
                    renameFrom = ""
                    renameTo = ""
                }) { Text("Rename") }
            }

            item {
                OutlinedTextField(
                    value = deleteName,
                    onValueChange = { deleteName = it },
                    label = { Text("Delete device") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
            item {
                Button(onClick = {
                    onDeleteAirvpnDevice(deleteName)
                    deleteName = ""
                }) { Text("Delete") }
            }
            item {
                Text("Devices: ${airvpnDevices.joinToString { it.name }}")
            }
        }
    }
}

@Composable
private fun SettingsTabContent(
    config: AppConfigModel,
    splitTunnelApps: List<SplitTunnelApp>,
    onSaveConfig: (AppConfigModel) -> Unit,
    onSetAppMode: (String) -> Unit,
    onSetSplitTunnelOnlyAllowSelected: (Boolean) -> Unit,
    onSetSplitTunnelApp: (String, Boolean) -> Unit,
) {
    var backend by remember(config) { mutableStateOf(config.general.backend) }
    var credentialStore by remember(config) { mutableStateOf(config.general.credentialStore) }
    var proxy by remember(config) { mutableStateOf(config.general.proxy) }
    var proxyAccessLog by remember(config) { mutableStateOf(config.general.proxyAccessLog) }
    var socksPort by remember(config) { mutableStateOf(config.general.socksPort?.toString().orEmpty()) }
    var httpPort by remember(config) { mutableStateOf(config.general.httpPort?.toString().orEmpty()) }
    var privilegedTransport by remember(config) { mutableStateOf(config.general.privilegedTransport) }
    var privilegedAutostart by remember(config) { mutableStateOf(config.general.privilegedAutostart) }
    var privilegedAutostartTimeout by remember(config) {
        mutableStateOf(config.general.privilegedAutostartTimeoutMs.toString())
    }
    var privilegedAuthorizedGroup by remember(config) {
        mutableStateOf(config.general.privilegedAuthorizedGroup)
    }
    var privilegedAutostopMode by remember(config) { mutableStateOf(config.general.privilegedAutostopMode) }
    var privilegedAutostopTimeout by remember(config) {
        mutableStateOf(config.general.privilegedAutostopTimeoutMs.toString())
    }

    val saveConfig = {
        onSaveConfig(
            config.copy(
                general = GeneralConfig(
                    backend = backend.trim(),
                    credentialStore = credentialStore.trim(),
                    proxy = proxy,
                    socksPort = parseIntOrNull(socksPort),
                    httpPort = parseIntOrNull(httpPort),
                    proxyAccessLog = proxyAccessLog,
                    privilegedTransport = privilegedTransport.trim(),
                    privilegedAutostart = privilegedAutostart,
                    privilegedAutostartTimeoutMs = parseLongOrDefault(privilegedAutostartTimeout, 5000L),
                    privilegedAuthorizedGroup = privilegedAuthorizedGroup.trim(),
                    privilegedAutostopMode = privilegedAutostopMode.trim(),
                    privilegedAutostopTimeoutMs = parseLongOrDefault(privilegedAutostopTimeout, 30000L),
                    appMode = config.general.appMode,
                    splitTunnelApps = config.general.splitTunnelApps,
                    splitTunnelOnlyAllowSelected = config.general.splitTunnelOnlyAllowSelected,
                )
            )
        )
    }

    val appMode = config.general.appMode
    val selectedSplitApps = config.general.splitTunnelApps.toSet()

    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = saveConfig) { Text("Save") }
            }
        }

        item { Text("Tunnel", style = MaterialTheme.typography.titleMedium) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onSetAppMode("vpn") },
                    enabled = appMode != "vpn",
                ) { Text("App mode: VPN") }
                OutlinedButton(
                    onClick = { onSetAppMode("split") },
                    enabled = appMode != "split",
                ) { Text("Split tunnel") }
            }
        }
        if (appMode == "split") {
            item {
                ToggleRow(
                    title = "Only allow selected apps",
                    checked = config.general.splitTunnelOnlyAllowSelected,
                    onToggle = onSetSplitTunnelOnlyAllowSelected,
                )
            }
            item {
                Text(
                    if (config.general.splitTunnelOnlyAllowSelected) {
                        "Selected apps use VPN; all other apps bypass VPN"
                    } else {
                        "Selected apps bypass VPN; all other apps use VPN"
                    }
                )
            }
            if (splitTunnelApps.isEmpty()) {
                item { Text("No launchable apps found") }
            } else {
                items(splitTunnelApps.take(200)) { app ->
                    ToggleRow(
                        title = app.label,
                        checked = selectedSplitApps.contains(app.packageName),
                        onToggle = { onSetSplitTunnelApp(app.packageName, it) },
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = backend,
                onValueChange = { backend = it },
                label = { Text("general.backend") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = credentialStore,
                onValueChange = { credentialStore = it },
                label = { Text("general.credential_store") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        item { Text("Ports", style = MaterialTheme.typography.titleMedium) }
        item {
            OutlinedTextField(
                value = socksPort,
                onValueChange = { socksPort = it },
                label = { Text("general.socks_port") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = httpPort,
                onValueChange = { httpPort = it },
                label = { Text("general.http_port") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        item { Text("Privileged", style = MaterialTheme.typography.titleMedium) }
        item {
            OutlinedTextField(
                value = privilegedTransport,
                onValueChange = { privilegedTransport = it },
                label = { Text("general.privileged_transport") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = privilegedAuthorizedGroup,
                onValueChange = { privilegedAuthorizedGroup = it },
                label = { Text("general.privileged_authorized_group") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = privilegedAutostopMode,
                onValueChange = { privilegedAutostopMode = it },
                label = { Text("general.privileged_autostop_mode") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = privilegedAutostartTimeout,
                onValueChange = { privilegedAutostartTimeout = it },
                label = { Text("general.privileged_autostart_timeout_ms") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        item {
            OutlinedTextField(
                value = privilegedAutostopTimeout,
                onValueChange = { privilegedAutostopTimeout = it },
                label = { Text("general.privileged_autostop_timeout_ms") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        item {
            ToggleRow(
                title = "general.proxy",
                checked = proxy,
                onToggle = { proxy = it },
            )
        }
        item {
            ToggleRow(
                title = "general.proxy_access_log",
                checked = proxyAccessLog,
                onToggle = { proxyAccessLog = it },
            )
        }
        item {
            ToggleRow(
                title = "general.privileged_autostart",
                checked = privilegedAutostart,
                onToggle = { privilegedAutostart = it },
            )
        }
    }
}

@Composable
private fun AutoTabContent(
    autoConfig: AutoTunnelConfig,
    onSetAutoEnabled: (Boolean) -> Unit,
    onSetAutoWifi: (Boolean) -> Unit,
    onSetAutoMobile: (Boolean) -> Unit,
    onSetAutoEthernet: (Boolean) -> Unit,
    onSetStopOnNoInternet: (Boolean) -> Unit,
    onSetStartOnBoot: (Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Auto-tunnel", style = MaterialTheme.typography.headlineSmall)
        ToggleRow(
            title = "Auto-tunnel running",
            checked = autoConfig.enabled,
            onToggle = onSetAutoEnabled,
        )
        ToggleRow(
            title = "Tunnel on Wi-Fi",
            checked = autoConfig.onWifi,
            onToggle = onSetAutoWifi,
        )
        ToggleRow(
            title = "Tunnel on mobile data",
            checked = autoConfig.onMobile,
            onToggle = onSetAutoMobile,
        )
        ToggleRow(
            title = "Tunnel on ethernet",
            checked = autoConfig.onEthernet,
            onToggle = onSetAutoEthernet,
        )
        ToggleRow(
            title = "Stop on no internet",
            checked = autoConfig.stopOnNoInternet,
            onToggle = onSetStopOnNoInternet,
        )
        ToggleRow(
            title = "Start on boot",
            checked = autoConfig.startOnBoot,
            onToggle = onSetStartOnBoot,
        )
    }
}

@Composable
private fun ToggleRow(
    title: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title)
            Spacer(Modifier.weight(1f))
            Switch(
                checked = checked,
                onCheckedChange = onToggle,
            )
        }
    }
}

private fun parseIntOrNull(value: String): Int? {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return null
    return trimmed.toIntOrNull()
}

private fun parseLongOrDefault(value: String, fallback: Long): Long {
    return value.trim().toLongOrNull() ?: fallback
}

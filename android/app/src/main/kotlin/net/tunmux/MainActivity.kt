package net.tunmux

import android.app.Activity
import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.autofill.AutofillNode
import androidx.compose.ui.autofill.AutofillType
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalAutofill
import androidx.compose.ui.platform.LocalAutofillTree
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import net.tunmux.ui.theme.TunmuxTheme
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
import net.tunmux.model.WifiDetectionMethod

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
    private var pendingLocationPermissionAction: (() -> Unit)? = null

    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        pendingLocationPermissionAction?.invoke()
        pendingLocationPermissionAction = null
    }

    fun requestVpnPermissionAndConnect(onGranted: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            onGranted()
        } else {
            pendingConnectAction = onGranted
            vpnPermissionLauncher.launch(intent)
        }
    }

    fun requestLocationPermissions(onCompleted: () -> Unit) {
        val permissions =
            buildList {
                add(Manifest.permission.ACCESS_FINE_LOCATION)
                add(Manifest.permission.ACCESS_COARSE_LOCATION)
            }
        val missing =
            permissions.filter {
                ContextCompat.checkSelfPermission(this, it) !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED
            }
        if (missing.isEmpty()) {
            onCompleted()
            return
        }
        pendingLocationPermissionAction = onCompleted
        locationPermissionLauncher.launch(missing.toTypedArray())
    }

    fun openLocationSettings() {
        startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TunmuxTheme {
                TunmuxApp()
            }
        }
    }

    fun openCreateAccount(provider: String) {
        val url = when (provider) {
            "proton" -> "https://proton.me/vpn/signup"
            "airvpn" -> "https://airvpn.it/register"
            else -> return
        }
        startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
    }
}

@Composable
fun TunmuxApp(vm: VpnViewModel = viewModel()) {
    val state by vm.state.collectAsState()
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? MainActivity

    when (state.screen) {
        Screen.Login -> LoginScreen(
            provider = state.selectedProvider,
            error = state.errorMessage,
            onLogin = { u, p, t -> vm.login(u, p, t) },
            onBack = { vm.navigateBack() },
        )
        Screen.ProviderSelect, Screen.Dashboard -> DashboardScreen(
            provider = state.selectedProvider,
            isLoggedIn = state.isLoggedIn,
            loggedInUsername = state.loggedInUsername,
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
            connectedWifiSsid = state.connectedWifiSsid,
            knownWifiSsids = state.knownWifiSsids,
            locationPermissionGranted = state.locationPermissionGranted,
            locationServicesEnabled = state.locationServicesEnabled,
            splitTunnelApps = state.splitTunnelApps,
            favoriteServers = state.config.general.favoriteServers,
            onSelectProvider = { vm.selectProvider(it) },
            onOpenLogin = { vm.openLogin() },
            onCreateAccount = {
                val provider = state.selectedProvider
                if (provider == "mullvad" || provider == "ivpn") {
                    vm.createAccount(provider)
                } else {
                    activity?.openCreateAccount(provider)
                }
            },
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
            onSetAutoWifiSsids = { vm.setAutoWifiSsids(it) },
            onSetAutoWifiDetectionMethod = { vm.setAutoWifiDetectionMethod(it) },
            onSetAutoDebounceDelaySeconds = { vm.setAutoDebounceDelaySeconds(it) },
            onSetAutoDisconnectOnMatchedWifi = { vm.setAutoDisconnectOnMatchedWifi(it) },
            onAddCurrentWifi = { vm.addConnectedWifiToAutoList() },
            onAddKnownWifi = { vm.addAutoWifiSsid(it) },
            onRefreshKnownWifi = { vm.refreshKnownWifiSsids() },
            onRequestLocationPermissions = {
                activity?.requestLocationPermissions { vm.refreshAutoNetworkPermissions() }
            },
            onOpenLocationSettings = { activity?.openLocationSettings() },
            onSetStopOnNoInternet = { vm.setStopOnNoInternet(it) },
            onSetStartOnBoot = { vm.setStartOnBoot(it) },
            onSetAppMode = { vm.setAppMode(it) },
            onSetSplitTunnelOnlyAllowSelected = { vm.setSplitTunnelOnlyAllowSelected(it) },
            onSetSplitTunnelApp = { pkg, enabled -> vm.setSplitTunnelApp(pkg, enabled) },
            onSetServerFavorite = { server, favorite -> vm.setServerFavorite(server, favorite) },
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

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun LoginScreen(
    provider: String,
    error: String,
    onLogin: (String, String, String) -> Unit,
    onBack: () -> Unit,
) {
    val needsPassword = provider == "proton" || provider == "airvpn"
    var username by remember(provider) { mutableStateOf("") }
    var password by remember(provider) { mutableStateOf("") }
    var twoFa by remember(provider) { mutableStateOf("") }

    val autofill = LocalAutofill.current
    val usernameNode = remember(provider) {
        AutofillNode(autofillTypes = listOf(AutofillType.Username), onFill = { username = it })
    }
    val passwordNode = remember(provider) {
        AutofillNode(autofillTypes = listOf(AutofillType.Password), onFill = { password = it })
    }
    val autofillTree = LocalAutofillTree.current
    autofillTree += usernameNode
    if (needsPassword) autofillTree += passwordNode

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
            modifier = Modifier
                .fillMaxWidth()
                .onGloballyPositioned { usernameNode.boundingBox = it.boundsInWindow() }
                .onFocusChanged { fs ->
                    autofill?.run {
                        if (fs.isFocused) requestAutofillForNode(usernameNode)
                        else cancelAutofillForNode(usernameNode)
                    }
                },
            singleLine = true,
        )
        if (needsPassword) {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier
                    .fillMaxWidth()
                    .onGloballyPositioned { passwordNode.boundingBox = it.boundsInWindow() }
                    .onFocusChanged { fs ->
                        autofill?.run {
                            if (fs.isFocused) requestAutofillForNode(passwordNode)
                            else cancelAutofillForNode(passwordNode)
                        }
                    },
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
    isLoggedIn: Boolean,
    loggedInUsername: String,
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
    connectedWifiSsid: String,
    knownWifiSsids: List<String>,
    locationPermissionGranted: Boolean,
    locationServicesEnabled: Boolean,
    splitTunnelApps: List<SplitTunnelApp>,
    favoriteServers: List<String>,
    onSelectProvider: (String) -> Unit,
    onOpenLogin: () -> Unit,
    onCreateAccount: () -> Unit,
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
    onSetAutoWifiSsids: (String) -> Unit,
    onSetAutoWifiDetectionMethod: (WifiDetectionMethod) -> Unit,
    onSetAutoDebounceDelaySeconds: (Int) -> Unit,
    onSetAutoDisconnectOnMatchedWifi: (Boolean) -> Unit,
    onAddCurrentWifi: () -> Unit,
    onAddKnownWifi: (String) -> Unit,
    onRefreshKnownWifi: () -> Unit,
    onRequestLocationPermissions: () -> Unit,
    onOpenLocationSettings: () -> Unit,
    onSetStopOnNoInternet: (Boolean) -> Unit,
    onSetStartOnBoot: (Boolean) -> Unit,
    onSetAppMode: (String) -> Unit,
    onSetSplitTunnelOnlyAllowSelected: (Boolean) -> Unit,
    onSetSplitTunnelApp: (String, Boolean) -> Unit,
    onSetServerFavorite: (String, Boolean) -> Unit,
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
                            Icon(
                                imageVector = when (item) {
                                    DashboardTab.Main -> Icons.Filled.Home
                                    DashboardTab.Tunnels -> Icons.AutoMirrored.Filled.List
                                    DashboardTab.Config -> Icons.Filled.Tune
                                    DashboardTab.Settings -> Icons.Filled.Settings
                                    DashboardTab.Auto -> Icons.Filled.Autorenew
                                },
                                contentDescription = null,
                            )
                        },
                        label = {
                            Text(
                                when (item) {
                                    DashboardTab.Main -> "Home"
                                    DashboardTab.Tunnels -> "Tunnels"
                                    DashboardTab.Config -> "Config"
                                    DashboardTab.Settings -> "Settings"
                                    DashboardTab.Auto -> "Auto"
                                }
                            )
                        },
                        alwaysShowLabel = true,
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
            DashboardHeader(
                selectedProvider = provider,
                isLoggedIn = isLoggedIn,
                loggedInUsername = loggedInUsername,
                onSelectProvider = onSelectProvider,
                onOpenLogin = onOpenLogin,
                onLogout = onLogout,
                onCreateAccount = onCreateAccount,
            )

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
                    isLoggedIn = isLoggedIn,
                    connectionState = connectionState,
                    servers = servers,
                    favoriteServers = favoriteServers,
                    activeServer = activeServer,
                    wgLikeStatus = wgLikeStatus,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                    onSetServerFavorite = onSetServerFavorite,
                )
                DashboardTab.Tunnels -> TunnelsTabContent(
                    isLoggedIn = isLoggedIn,
                    servers = servers,
                    favoriteServers = favoriteServers,
                    activeServer = activeServer,
                    connectionState = connectionState,
                    onSetServerFavorite = onSetServerFavorite,
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
                DashboardTab.Auto -> Box(modifier = Modifier.weight(1f, fill = true)) {
                    AutoTabContent(
                        autoConfig = autoConfig,
                        connectedWifiSsid = connectedWifiSsid,
                        knownWifiSsids = knownWifiSsids,
                        locationPermissionGranted = locationPermissionGranted,
                        locationServicesEnabled = locationServicesEnabled,
                        onSetAutoEnabled = onSetAutoEnabled,
                        onSetAutoWifi = onSetAutoWifi,
                        onSetAutoMobile = onSetAutoMobile,
                        onSetAutoEthernet = onSetAutoEthernet,
                        onSetAutoWifiSsids = onSetAutoWifiSsids,
                        onSetAutoWifiDetectionMethod = onSetAutoWifiDetectionMethod,
                        onSetAutoDebounceDelaySeconds = onSetAutoDebounceDelaySeconds,
                        onSetAutoDisconnectOnMatchedWifi = onSetAutoDisconnectOnMatchedWifi,
                        onAddCurrentWifi = onAddCurrentWifi,
                        onAddKnownWifi = onAddKnownWifi,
                        onRefreshKnownWifi = onRefreshKnownWifi,
                        onRequestLocationPermissions = onRequestLocationPermissions,
                        onOpenLocationSettings = onOpenLocationSettings,
                        onSetStopOnNoInternet = onSetStopOnNoInternet,
                        onSetStartOnBoot = onSetStartOnBoot,
                    )
                }
            }
        }
    }
}

@Composable
private fun MainTabContent(
    isLoggedIn: Boolean,
    connectionState: ConnectionState,
    servers: List<String>,
    favoriteServers: List<String>,
    activeServer: String,
    wgLikeStatus: String,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onSetServerFavorite: (String, Boolean) -> Unit,
) {
    val favoriteSet = remember(favoriteServers) { favoriteServers.map { it.lowercase() }.toSet() }
    val favoriteAvailable = remember(servers, favoriteSet) {
        servers.filter { favoriteSet.contains(it.lowercase()) }
    }

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
                    val target = when {
                        activeServer.isNotBlank() -> activeServer
                        favoriteAvailable.isNotEmpty() -> favoriteAvailable.first()
                        else -> servers.firstOrNull().orEmpty()
                    }
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
    Text("Favorite Tunnels", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(6.dp))

    if (!isLoggedIn) {
        Text("Log in to manage favorites from the Tunnels tab.")
        return
    }
    if (favoriteAvailable.isEmpty()) {
        Text("No favorites yet. Open the Tunnels tab and star your servers.")
        return
    }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        items(favoriteAvailable.take(120)) { server ->
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
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(server, modifier = Modifier.weight(1f))
                    IconButton(onClick = { onSetServerFavorite(server, false) }) {
                        Icon(
                            imageVector = Icons.Filled.Star,
                            contentDescription = "Unfavorite tunnel",
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
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

private enum class TunnelSortOption(val label: String) {
    FavoritesFirst("Favorites first"),
    NameAsc("Name A-Z"),
    NameDesc("Name Z-A"),
    CountryAsc("Country"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnelsTabContent(
    isLoggedIn: Boolean,
    servers: List<String>,
    favoriteServers: List<String>,
    activeServer: String,
    connectionState: ConnectionState,
    onSetServerFavorite: (String, Boolean) -> Unit,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    var searchQuery by remember { mutableStateOf("") }
    var sortOption by remember { mutableStateOf(TunnelSortOption.FavoritesFirst) }
    var countryFilter by remember { mutableStateOf("All") }
    var sortExpanded by remember { mutableStateOf(false) }
    var countryExpanded by remember { mutableStateOf(false) }

    val favoriteSet = remember(favoriteServers) { favoriteServers.map { it.lowercase() }.toSet() }
    val countries = remember(servers) {
        buildList {
            add("All")
            addAll(
                servers
                    .map { extractCountryCode(it) }
                    .filter { it != "--" }
                    .distinct()
                    .sorted()
            )
        }
    }
    LaunchedEffect(countries) {
        if (countryFilter !in countries) {
            countryFilter = "All"
        }
    }
    val filteredServers = remember(servers, favoriteSet, searchQuery, sortOption, countryFilter) {
        val normalizedQuery = searchQuery.trim().lowercase()
        val searched = servers.filter { server ->
            normalizedQuery.isEmpty() || server.lowercase().contains(normalizedQuery)
        }
        val countryFiltered = if (countryFilter == "All") {
            searched
        } else {
            searched.filter { extractCountryCode(it) == countryFilter }
        }
        when (sortOption) {
            TunnelSortOption.FavoritesFirst -> {
                countryFiltered.sortedWith(
                    compareByDescending<String> { favoriteSet.contains(it.lowercase()) }
                        .thenBy { it.lowercase() }
                )
            }
            TunnelSortOption.NameAsc -> countryFiltered.sortedBy { it.lowercase() }
            TunnelSortOption.NameDesc -> countryFiltered.sortedByDescending { it.lowercase() }
            TunnelSortOption.CountryAsc -> {
                countryFiltered.sortedWith(
                    compareBy<String> { extractCountryCode(it) }.thenBy { it.lowercase() }
                )
            }
        }
    }

    if (!isLoggedIn) {
        Text("Log in to see tunnels.")
        return
    }
    if (servers.isEmpty()) {
        Text("No tunnels available.")
        return
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            label = { Text("Search tunnels") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExposedDropdownMenuBox(
                expanded = sortExpanded,
                onExpandedChange = { sortExpanded = it },
                modifier = Modifier.weight(1f),
            ) {
                OutlinedTextField(
                    value = sortOption.label,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Sort") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = sortExpanded) },
                    modifier = Modifier
                        .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                        .fillMaxWidth(),
                    singleLine = true,
                )
                ExposedDropdownMenu(expanded = sortExpanded, onDismissRequest = { sortExpanded = false }) {
                    TunnelSortOption.entries.forEach { option ->
                        DropdownMenuItem(
                            text = { Text(option.label) },
                            onClick = {
                                sortOption = option
                                sortExpanded = false
                            },
                        )
                    }
                }
            }

            ExposedDropdownMenuBox(
                expanded = countryExpanded,
                onExpandedChange = { countryExpanded = it },
                modifier = Modifier.weight(1f),
            ) {
                OutlinedTextField(
                    value = countryFilter,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Country") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = countryExpanded) },
                    modifier = Modifier
                        .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                        .fillMaxWidth(),
                    singleLine = true,
                )
                ExposedDropdownMenu(expanded = countryExpanded, onDismissRequest = { countryExpanded = false }) {
                    countries.forEach { option ->
                        DropdownMenuItem(
                            text = { Text(option) },
                            onClick = {
                                countryFilter = option
                                countryExpanded = false
                            },
                        )
                    }
                }
            }
        }

        Text(
            "Showing ${filteredServers.size} of ${servers.size}",
            style = MaterialTheme.typography.bodySmall,
        )

        LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(filteredServers.take(240)) { server ->
                val isFavorite = favoriteSet.contains(server.lowercase())
                val isConnected = connectionState == ConnectionState.Connected && activeServer == server
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
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(server)
                            Text(
                                "Country: ${extractCountryCode(server)}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        IconButton(onClick = { onSetServerFavorite(server, !isFavorite) }) {
                            Icon(
                                imageVector = if (isFavorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                                contentDescription = if (isFavorite) "Remove favorite" else "Add favorite",
                                tint = if (isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                            )
                        }
                        Switch(
                            checked = isConnected,
                            onCheckedChange = { checked ->
                                if (checked) onConnect(server) else onDisconnect()
                            },
                        )
                    }
                }
            }
        }
    }
}

private fun extractCountryCode(server: String): String {
    val match = "\\[([A-Za-z]{2})\\]".toRegex().find(server) ?: return "--"
    return match.groupValues.getOrNull(1)?.uppercase().orEmpty().ifBlank { "--" }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DashboardHeader(
    selectedProvider: String,
    isLoggedIn: Boolean,
    loggedInUsername: String,
    onSelectProvider: (String) -> Unit,
    onOpenLogin: () -> Unit,
    onLogout: () -> Unit,
    onCreateAccount: () -> Unit,
) {
    val providers = listOf("proton", "airvpn", "mullvad", "ivpn")
    var expanded by remember { mutableStateOf(false) }
    Column {
        ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
            OutlinedTextField(
                value = selectedProvider,
                onValueChange = {},
                readOnly = true,
                label = { Text("Provider") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor(MenuAnchorType.PrimaryNotEditable).fillMaxWidth(),
                singleLine = true,
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                providers.forEach { p ->
                    DropdownMenuItem(
                        text = { Text(p) },
                        onClick = { expanded = false; if (p != selectedProvider) onSelectProvider(p) },
                    )
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (isLoggedIn) {
                Text(
                    loggedInUsername,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                OutlinedButton(onClick = onLogout) { Text("Logout") }
            } else {
                Spacer(Modifier.weight(1f))
                OutlinedButton(onClick = onOpenLogin) { Text("Login") }
                OutlinedButton(onClick = onCreateAccount) { Text("Create Account") }
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
                    favoriteServers = config.general.favoriteServers,
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
    connectedWifiSsid: String,
    knownWifiSsids: List<String>,
    locationPermissionGranted: Boolean,
    locationServicesEnabled: Boolean,
    onSetAutoEnabled: (Boolean) -> Unit,
    onSetAutoWifi: (Boolean) -> Unit,
    onSetAutoMobile: (Boolean) -> Unit,
    onSetAutoEthernet: (Boolean) -> Unit,
    onSetAutoWifiSsids: (String) -> Unit,
    onSetAutoWifiDetectionMethod: (WifiDetectionMethod) -> Unit,
    onSetAutoDebounceDelaySeconds: (Int) -> Unit,
    onSetAutoDisconnectOnMatchedWifi: (Boolean) -> Unit,
    onAddCurrentWifi: () -> Unit,
    onAddKnownWifi: (String) -> Unit,
    onRefreshKnownWifi: () -> Unit,
    onRequestLocationPermissions: () -> Unit,
    onOpenLocationSettings: () -> Unit,
    onSetStopOnNoInternet: (Boolean) -> Unit,
    onSetStartOnBoot: (Boolean) -> Unit,
) {
    var wifiSsidInput by remember(autoConfig.wifiSsids) {
        mutableStateOf(autoConfig.wifiSsids.joinToString(", "))
    }
    val debounceOptions = listOf(0, 1, 3, 5, 10)
    val locationWarning =
        when {
            !locationPermissionGranted && !locationServicesEnabled ->
                "SSID matching requires location permission and location services."
            !locationPermissionGranted ->
                "SSID matching requires location permission."
            !locationServicesEnabled ->
                "SSID matching requires location services to be enabled."
            else -> ""
        }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { Text("Auto-tunnel", style = MaterialTheme.typography.headlineSmall) }
        item {
            ToggleRow(
                title = "Auto-tunnel running",
                checked = autoConfig.enabled,
                onToggle = onSetAutoEnabled,
            )
        }
        item {
            ToggleRow(
                title = "Tunnel on Wi-Fi",
                checked = autoConfig.onWifi,
                onToggle = onSetAutoWifi,
            )
        }
        if (autoConfig.onWifi) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            "Current Wi-Fi: ${if (connectedWifiSsid.isBlank()) "Unknown" else connectedWifiSsid}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            "Detection method: ${autoConfig.wifiDetectionMethod.name}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { onSetAutoWifiDetectionMethod(WifiDetectionMethod.DEFAULT) },
                                enabled = autoConfig.wifiDetectionMethod != WifiDetectionMethod.DEFAULT,
                            ) { Text("DEFAULT") }
                            OutlinedButton(
                                onClick = { onSetAutoWifiDetectionMethod(WifiDetectionMethod.LEGACY) },
                                enabled = autoConfig.wifiDetectionMethod != WifiDetectionMethod.LEGACY,
                            ) { Text("LEGACY") }
                        }
                        if (locationWarning.isNotEmpty()) {
                            Text(
                                locationWarning,
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFFFB4AB),
                            )
                            Text(
                                "Permission: ${if (locationPermissionGranted) "granted" else "missing"} • Services: ${if (locationServicesEnabled) "on" else "off"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFFFB4AB),
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (!locationPermissionGranted) {
                                    OutlinedButton(onClick = onRequestLocationPermissions) {
                                        Text("Grant location")
                                    }
                                }
                                if (!locationServicesEnabled) {
                                    OutlinedButton(onClick = onOpenLocationSettings) {
                                        Text("Open location settings")
                                    }
                                }
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = onAddCurrentWifi,
                                enabled = connectedWifiSsid.isNotBlank(),
                            ) { Text("Add current") }
                            OutlinedButton(onClick = onRefreshKnownWifi) { Text("Refresh known") }
                        }
                        if (knownWifiSsids.isNotEmpty()) {
                            Text("Known Wi-Fi")
                            knownWifiSsids.take(12).forEach { ssid ->
                                OutlinedButton(onClick = { onAddKnownWifi(ssid) }) {
                                    Text(ssid)
                                }
                            }
                        }
                    }
                }
            }
            item {
                ToggleRow(
                    title = "Disconnect on matched Wi-Fi",
                    checked = autoConfig.disconnectOnMatchedWifi,
                    onToggle = onSetAutoDisconnectOnMatchedWifi,
                )
            }
            item {
                OutlinedTextField(
                    value = wifiSsidInput,
                    onValueChange = {
                        wifiSsidInput = it
                        onSetAutoWifiSsids(it)
                    },
                    label = { Text("Wi-Fi SSIDs (comma-separated)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = false,
                )
            }
            if (autoConfig.wifiSsids.isNotEmpty()) {
                item {
                    Text(
                        if (autoConfig.disconnectOnMatchedWifi) {
                            "VPN disconnects on listed SSIDs"
                        } else {
                            "VPN connects only on listed SSIDs"
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                item { Text("Saved SSIDs", style = MaterialTheme.typography.bodySmall) }
                items(autoConfig.wifiSsids) { ssid ->
                    Text("- $ssid", style = MaterialTheme.typography.bodySmall)
                }
            }
            item {
                Text(
                    "Network debounce: ${autoConfig.debounceDelaySeconds}s",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            item {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(debounceOptions) { seconds ->
                        OutlinedButton(
                            onClick = { onSetAutoDebounceDelaySeconds(seconds) },
                            enabled = autoConfig.debounceDelaySeconds != seconds,
                        ) { Text("${seconds}s") }
                    }
                }
            }
        }
        item {
            ToggleRow(
                title = "Tunnel on mobile data",
                checked = autoConfig.onMobile,
                onToggle = onSetAutoMobile,
            )
        }
        item {
            ToggleRow(
                title = "Tunnel on ethernet",
                checked = autoConfig.onEthernet,
                onToggle = onSetAutoEthernet,
            )
        }
        item {
            ToggleRow(
                title = "Stop on no internet",
                checked = autoConfig.stopOnNoInternet,
                onToggle = onSetStopOnNoInternet,
            )
        }
        item {
            ToggleRow(
                title = "Start on boot",
                checked = autoConfig.startOnBoot,
                onToggle = onSetStartOnBoot,
            )
        }
        item { Spacer(Modifier.height(12.dp)) }
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

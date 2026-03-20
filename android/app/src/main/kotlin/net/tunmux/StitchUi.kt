@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package net.tunmux

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.tunmux.model.AirvpnConfig
import net.tunmux.model.AirvpnDevice
import net.tunmux.model.AirvpnKey
import net.tunmux.model.AppConfigModel
import net.tunmux.model.AutoTunnelConfig
import net.tunmux.model.ConnectionState
import net.tunmux.model.DashboardTab
import net.tunmux.model.ProviderConfig
import net.tunmux.model.SplitTunnelApp
import net.tunmux.model.WifiDetectionMethod

// ── Design Tokens ──────────────────────────────────────────────────────────────

private val StitchBackground = Color(0xFF131313)
private val StitchSurfaceLow = Color(0xFF1C1B1B)
private val StitchSurface = Color(0xFF201F1F)
private val StitchSurfaceHigh = Color(0xFF2A2A2A)
private val StitchSurfaceBright = Color(0xFF353534)
private val StitchPrimary = Color(0xFFA5C8FF)
private val StitchPrimaryDeep = Color(0xFF004C8F)
private val StitchSuccess = Color(0xFF00E475)
private val StitchText = Color(0xFFE5E2E1)
private val StitchMuted = Color(0xFFC3C6D4)
private val StitchOutline = Color(0xFF434652)
private val StitchDanger = Color(0xFFFFB4AB)

// ── Login Screen ───────────────────────────────────────────────────────────────

@Composable
fun StitchLoginScreen(
    provider: String,
    error: String,
    onLogin: (String, String, String) -> Unit,
    onBack: () -> Unit,
) {
    val needsPassword = provider == "proton" || provider == "airvpn"
    var username by remember(provider) { mutableStateOf("") }
    var password by remember(provider) { mutableStateOf("") }
    var twoFa by remember(provider) { mutableStateOf("") }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(stitchBackdropBrush()),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 28.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            item {
                IconButton(
                    onClick = onBack,
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(StitchSurface.copy(alpha = 0.92f)),
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = StitchText)
                }
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "TUNMUX",
                        style = MaterialTheme.typography.labelLarge,
                        color = StitchPrimary,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 2.sp,
                    )
                    Text(
                        text = "Authenticate your\nsecure route",
                        style = MaterialTheme.typography.headlineLarge,
                        color = StitchText,
                        fontWeight = FontWeight.Bold,
                    )
                    ProviderPill(provider = provider, detail = providerDescription(provider))
                }
            }
            item {
                StitchPanel {
                    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        Text(
                            text = "Provider credentials",
                            style = MaterialTheme.typography.titleMedium,
                            color = StitchText,
                        )
                        StitchField(
                            value = username,
                            onValueChange = { username = it },
                            label = if (needsPassword) "Username" else "Account number",
                        )
                        if (needsPassword) {
                            StitchField(
                                value = password,
                                onValueChange = { password = it },
                                label = "Password",
                                password = true,
                            )
                        }
                        if (provider == "proton") {
                            StitchField(
                                value = twoFa,
                                onValueChange = { twoFa = it },
                                label = "2FA code",
                            )
                        }
                        if (error.isNotBlank()) {
                            Text(
                                text = error,
                                style = MaterialTheme.typography.bodyMedium,
                                color = StitchDanger,
                            )
                        }
                        Button(
                            onClick = { onLogin(username, password, twoFa) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = StitchPrimary,
                                contentColor = Color(0xFF00315F),
                            ),
                            shape = RoundedCornerShape(12.dp),
                        ) {
                            Text("Continue", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
            item {
                Text(
                    text = "WireGuard sessions, provider login, and routing stay backed by the current tunmux Android runtime.",
                    style = MaterialTheme.typography.bodySmall,
                    color = StitchMuted,
                )
            }
        }
    }
}

// ── Dashboard Screen ───────────────────────────────────────────────────────────

@Composable
fun StitchDashboardScreen(
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
    providerCurrentKeys: Map<String, String>,
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
    // Map Config and Auto tabs to Settings for the 3-tab nav
    val visibleTab = when (tab) {
        DashboardTab.Config, DashboardTab.Auto -> DashboardTab.Settings
        else -> tab
    }

    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            StitchBottomNav(
                currentTab = visibleTab,
                onTabSelect = onTabSelect,
            )
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(stitchBackdropBrush())
                .padding(innerPadding),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                // Banners
                if (error.isNotBlank()) {
                    item { BannerMessage(message = error, tone = StitchDanger) }
                }
                if (settingsMessage.isNotBlank()) {
                    item { BannerMessage(message = settingsMessage, tone = StitchPrimary) }
                }

                when (visibleTab) {
                    DashboardTab.Main -> {
                        item {
                            DashboardHeroSection(
                                provider = provider,
                                isLoggedIn = isLoggedIn,
                                loggedInUsername = loggedInUsername,
                                connectionState = connectionState,
                                activeServer = activeServer,
                                appMode = config.general.appMode,
                                servers = servers,
                                favoriteServers = favoriteServers,
                                onSelectProvider = onSelectProvider,
                                onOpenLogin = onOpenLogin,
                                onCreateAccount = onCreateAccount,
                                onLogout = onLogout,
                                onConnect = onConnect,
                                onDisconnect = onDisconnect,
                            )
                        }
                        if (connectionState == ConnectionState.Connected && wgLikeStatus.isNotBlank()) {
                            item { PerformanceMetricsPanel(wgLikeStatus = wgLikeStatus, activeServer = activeServer) }
                        }
                        if (connectionState == ConnectionState.Connected) {
                            item {
                                Button(
                                    onClick = onDisconnect,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(48.dp),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = StitchDanger.copy(alpha = 0.15f),
                                        contentColor = StitchDanger,
                                    ),
                                    shape = RoundedCornerShape(12.dp),
                                ) {
                                    Text("Disconnect Active Session", fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                        item {
                            OperationModesPanel(
                                appMode = config.general.appMode,
                                onSetAppMode = onSetAppMode,
                            )
                        }
                        item {
                            FavoriteTunnelsSection(
                                isLoggedIn = isLoggedIn,
                                connectionState = connectionState,
                                servers = servers,
                                favoriteServers = favoriteServers,
                                activeServer = activeServer,
                                onConnect = onConnect,
                                onDisconnect = onDisconnect,
                                onSetServerFavorite = onSetServerFavorite,
                            )
                        }
                        if (wgLikeStatus.isNotBlank()) {
                            item { ProcessStreamPanel(wgLikeStatus = wgLikeStatus) }
                        }
                    }

                    DashboardTab.Tunnels -> {
                        item {
                            TunnelDashboardSection(
                                isLoggedIn = isLoggedIn,
                                servers = servers,
                                favoriteServers = favoriteServers,
                                activeServer = activeServer,
                                connectionState = connectionState,
                                onSetServerFavorite = onSetServerFavorite,
                                onConnect = onConnect,
                                onDisconnect = onDisconnect,
                            )
                        }
                    }

                    DashboardTab.Settings -> {
                        // Account section
                        if (isLoggedIn) {
                            item {
                                AccountSection(
                                    provider = provider,
                                    loggedInUsername = loggedInUsername,
                                    onLogout = onLogout,
                                )
                            }
                        }
                        // Provider Configuration section (was Config tab)
                        item {
                            ConfigDashboardSection(
                                provider = provider,
                                config = config,
                                airvpnKeys = airvpnKeys,
                                selectedAirvpnKey = selectedAirvpnKey,
                                airvpnDevices = airvpnDevices,
                                providerCurrentKeys = providerCurrentKeys,
                                onSaveConfig = onSaveConfig,
                                onRefreshAirvpn = onRefreshAirvpn,
                                onSelectAirvpnKey = onSelectAirvpnKey,
                                onAddAirvpnDevice = onAddAirvpnDevice,
                                onRenameAirvpnDevice = onRenameAirvpnDevice,
                                onDeleteAirvpnDevice = onDeleteAirvpnDevice,
                            )
                        }
                        // Application Parameters
                        item {
                            ApplicationParametersSection(
                                config = config,
                                autoConfig = autoConfig,
                                onSetAutoEnabled = onSetAutoEnabled,
                                onSetStopOnNoInternet = onSetStopOnNoInternet,
                                onSetAppMode = onSetAppMode,
                            )
                        }
                        // App Filter section (was Settings tab)
                        item {
                            AppFilterSection(
                                config = config,
                                splitTunnelApps = splitTunnelApps,
                                onSetSplitTunnelOnlyAllowSelected = onSetSplitTunnelOnlyAllowSelected,
                                onSetSplitTunnelApp = onSetSplitTunnelApp,
                            )
                        }
                        // Auto-Tunnel section (was Auto tab)
                        item {
                            AutoDashboardSection(
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
                        // Danger zone
                        item {
                            DangerZoneSection(
                                isLoggedIn = isLoggedIn,
                                onLogout = onLogout,
                                onOpenLogin = onOpenLogin,
                            )
                        }
                    }

                    // Config and Auto are now rendered inside Settings,
                    // but we still handle them to avoid compiler warnings.
                    DashboardTab.Config, DashboardTab.Auto -> {}
                }
            }
        }
    }
}

// ── Bottom Navigation ──────────────────────────────────────────────────────────

@Composable
private fun StitchBottomNav(
    currentTab: DashboardTab,
    onTabSelect: (DashboardTab) -> Unit,
) {
    val navItems = listOf(
        Triple(DashboardTab.Main, Icons.Filled.Home, "Dashboard"),
        Triple(DashboardTab.Tunnels, Icons.AutoMirrored.Filled.List, "Servers"),
        Triple(DashboardTab.Settings, Icons.Filled.Settings, "Settings"),
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(StitchBackground.copy(alpha = 0.96f))
            .navigationBarsPadding()
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        NavigationBar(
            containerColor = StitchSurface,
            tonalElevation = 0.dp,
            modifier = Modifier.clip(RoundedCornerShape(12.dp)),
        ) {
            navItems.forEach { (tab, icon, label) ->
                NavigationBarItem(
                    selected = currentTab == tab,
                    onClick = { onTabSelect(tab) },
                    icon = { Icon(icon, contentDescription = label) },
                    label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = StitchPrimary,
                        selectedTextColor = StitchPrimary,
                        unselectedIconColor = StitchMuted,
                        unselectedTextColor = StitchMuted,
                        indicatorColor = StitchPrimaryDeep.copy(alpha = 0.3f),
                    ),
                )
            }
        }
    }
}

// ── Dashboard Tab: Hero Section ────────────────────────────────────────────────

@Composable
private fun DashboardHeroSection(
    provider: String,
    isLoggedIn: Boolean,
    loggedInUsername: String,
    connectionState: ConnectionState,
    activeServer: String,
    appMode: String,
    servers: List<String>,
    favoriteServers: List<String>,
    onSelectProvider: (String) -> Unit,
    onOpenLogin: () -> Unit,
    onCreateAccount: () -> Unit,
    onLogout: () -> Unit,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    val favoriteSet = remember(favoriteServers) { favoriteServers.map { it.lowercase() }.toSet() }
    val connectTarget = remember(activeServer, servers, favoriteSet) {
        when {
            activeServer.isNotBlank() -> activeServer
            else -> servers.firstOrNull { favoriteSet.contains(it.lowercase()) }
                ?: servers.firstOrNull().orEmpty()
        }
    }

    StitchPanel {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            // Brand + status dot
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "TUNMUX",
                    style = MaterialTheme.typography.labelLarge,
                    color = StitchPrimary,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 2.sp,
                )
                StatusDot(connectionState = connectionState)
            }

            // Headline
            Text(
                text = connectionHeadline(connectionState),
                style = MaterialTheme.typography.headlineLarge,
                color = StitchText,
                fontWeight = FontWeight.Bold,
            )

            // Subtitle
            Text(
                text = when (connectionState) {
                    ConnectionState.Connected -> "Connected (Mode: ${appMode.uppercase()})"
                    ConnectionState.Connecting -> "Negotiating Route"
                    ConnectionState.Disconnected -> "Select a provider and configure your secure tunnel."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = StitchMuted,
            )

            // Detailed description when connected
            if (connectionState == ConnectionState.Connected && activeServer.isNotBlank()) {
                Text(
                    text = "Secure tunnel established via $activeServer. All traffic is being routed through WireGuard encrypted node.",
                    style = MaterialTheme.typography.bodySmall,
                    color = StitchMuted,
                )
            }

            // Provider filter chips
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                listOf("proton", "airvpn", "mullvad", "ivpn").forEach { item ->
                    FilterChip(
                        selected = item == provider,
                        onClick = { if (item != provider) onSelectProvider(item) },
                        label = { Text(item.uppercase(), style = MaterialTheme.typography.labelMedium) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = StitchPrimaryDeep,
                            selectedLabelColor = StitchPrimary,
                            containerColor = StitchSurfaceHigh,
                            labelColor = StitchMuted,
                        ),
                        shape = RoundedCornerShape(999.dp),
                    )
                }
            }

            // Quick connect / Disconnect + Login/Logout
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = {
                        if (connectionState == ConnectionState.Connected) onDisconnect()
                        else if (connectTarget.isNotBlank()) onConnect(connectTarget)
                    },
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (connectionState == ConnectionState.Connected) StitchSuccess else StitchPrimaryDeep,
                        contentColor = if (connectionState == ConnectionState.Connected) Color(0xFF003918) else StitchPrimary,
                    ),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text(
                        if (connectionState == ConnectionState.Connected) "Disconnect" else "Quick Connect",
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                if (isLoggedIn) {
                    OutlinedButton(
                        onClick = onLogout,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchMuted),
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Logout, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Logout")
                    }
                } else {
                    OutlinedButton(
                        onClick = onOpenLogin,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                    ) {
                        Text("Login")
                    }
                }
            }

            // Identity metrics
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MetricBlock(
                    title = "Provider",
                    value = provider.uppercase(),
                    modifier = Modifier.weight(1f),
                )
                MetricBlock(
                    title = "Identity",
                    value = if (isLoggedIn) loggedInUsername.ifBlank { "Authenticated" } else "Guest session",
                    modifier = Modifier.weight(1f),
                )
            }

            if (!isLoggedIn) {
                OutlinedButton(
                    onClick = onCreateAccount,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchMuted),
                ) {
                    Text("Create provider account")
                }
            }
        }
    }
}

// ── Dashboard Tab: Performance Metrics ─────────────────────────────────────────

private data class WgParsedStatus(
    val download: String = "--",
    val upload: String = "--",
    val latency: String = "--",
    val raw: String = "",
)

private fun parseWgStatus(wgLikeStatus: String): WgParsedStatus {
    val lines = wgLikeStatus.lines()
    var download = ""
    var upload = ""
    var latency = ""

    for (line in lines) {
        val lower = line.lowercase().trim()
        // Transfer line: "transfer: X received, Y sent"
        if (lower.startsWith("transfer:") || lower.contains("rx:") || lower.contains("received")) {
            val parts = line.split(",")
            for (part in parts) {
                val p = part.lowercase().trim()
                if (p.contains("received") || p.contains("rx:") || p.contains("download")) {
                    download = part.trim()
                        .removePrefix("transfer:")
                        .replace(Regex("(?i)received|rx:|download:?"), "")
                        .trim()
                }
                if (p.contains("sent") || p.contains("tx:") || p.contains("upload")) {
                    upload = part.trim()
                        .replace(Regex("(?i)sent|tx:|upload:?"), "")
                        .trim()
                }
            }
        }
        // Latency from handshake
        if (lower.contains("latest handshake") || lower.contains("handshake")) {
            latency = line.substringAfter(":").trim()
        }
        // Direct latency indication
        if (lower.contains("ms") && latency.isBlank()) {
            val match = Regex("(\\d+\\.?\\d*)\\s*ms").find(line)
            if (match != null) {
                latency = match.value
            }
        }
    }

    return WgParsedStatus(
        download = download.ifBlank { "--" },
        upload = upload.ifBlank { "--" },
        latency = latency.ifBlank { "--" },
        raw = wgLikeStatus,
    )
}

@Composable
private fun PerformanceMetricsPanel(wgLikeStatus: String, activeServer: String) {
    val parsed = remember(wgLikeStatus) { parseWgStatus(wgLikeStatus) }
    val showParsed = parsed.download != "--" || parsed.upload != "--" || parsed.latency != "--"

    StitchPanel {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = "Performance Metrics",
                style = MaterialTheme.typography.titleMedium,
                color = StitchText,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = "Live traffic monitoring",
                style = MaterialTheme.typography.bodySmall,
                color = StitchMuted,
            )
            if (showParsed) {
                // 2x2 grid
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    MetricBlock(
                        title = "Download",
                        value = parsed.download,
                        accent = StitchSuccess,
                        modifier = Modifier.weight(1f),
                    )
                    MetricBlock(
                        title = "Upload",
                        value = parsed.upload,
                        accent = StitchPrimary,
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    MetricBlock(
                        title = "Latency",
                        value = parsed.latency,
                        modifier = Modifier.weight(1f),
                    )
                    MetricBlock(
                        title = "Active Node",
                        value = activeServer.ifBlank { "--" },
                        modifier = Modifier.weight(1f),
                    )
                }
            } else {
                // Fallback raw display
                Surface(
                    color = StitchSurfaceLow,
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text(
                        text = wgLikeStatus,
                        fontFamily = FontFamily.Monospace,
                        color = StitchMuted,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(14.dp),
                    )
                }
            }
        }
    }
}

// ── Dashboard Tab: Operation Modes ─────────────────────────────────────────────

@Composable
private fun OperationModesPanel(
    appMode: String,
    onSetAppMode: (String) -> Unit,
) {
    StitchPanel {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = "Operation Modes",
                style = MaterialTheme.typography.titleMedium,
                color = StitchText,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = "Select logic architecture",
                style = MaterialTheme.typography.bodySmall,
                color = StitchMuted,
            )
            ModeCard(
                title = "Global VPN",
                description = "Route 100% of system egress traffic through encrypted tunnel.",
                selected = appMode == "vpn",
                onClick = { onSetAppMode("vpn") },
            )
            ModeCard(
                title = "HTTP/SOCKS",
                description = "Local listener proxy. Manual browser configuration required.",
                selected = appMode == "proxy",
                onClick = { onSetAppMode("proxy") },
            )
        }
    }
}

@Composable
private fun ModeCard(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (selected) Modifier.border(
                    width = 1.dp,
                    color = StitchPrimary.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(12.dp),
                ) else Modifier
            )
            .clickable(onClick = onClick),
        color = if (selected) StitchPrimaryDeep.copy(alpha = 0.2f) else StitchSurfaceHigh,
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (selected) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                contentDescription = null,
                tint = if (selected) StitchPrimary else StitchMuted,
                modifier = Modifier.size(22.dp),
            )
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, color = StitchText, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(description, color = StitchMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ── Dashboard Tab: Favorite Tunnels ────────────────────────────────────────────

@Composable
private fun FavoriteTunnelsSection(
    isLoggedIn: Boolean,
    connectionState: ConnectionState,
    servers: List<String>,
    favoriteServers: List<String>,
    activeServer: String,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onSetServerFavorite: (String, Boolean) -> Unit,
) {
    val favoriteSet = remember(favoriteServers) { favoriteServers.map { it.lowercase() }.toSet() }
    val favorites = remember(servers, favoriteSet) { servers.filter { favoriteSet.contains(it.lowercase()) } }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = "Quick Providers",
            style = MaterialTheme.typography.titleMedium,
            color = StitchText,
            fontWeight = FontWeight.SemiBold,
        )
        if (!isLoggedIn) {
            BannerMessage("Login to manage favorites and browse available tunnel endpoints.", StitchMuted)
            return
        }
        if (favorites.isEmpty()) {
            BannerMessage("No starred tunnels yet. Open Servers to build your quick-connect shortlist.", StitchMuted)
            return
        }
        favorites.take(8).forEach { server ->
            ServerCard(
                server = server,
                subtitle = "Favorite endpoint",
                favorite = true,
                connected = connectionState == ConnectionState.Connected && activeServer == server,
                onConnect = { onConnect(server) },
                onDisconnect = onDisconnect,
                onToggleFavorite = { onSetServerFavorite(server, false) },
            )
        }
    }
}

// ── Dashboard Tab: Process Stream ──────────────────────────────────────────────

@Composable
private fun ProcessStreamPanel(wgLikeStatus: String) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "Process Stream",
            style = MaterialTheme.typography.titleMedium,
            color = StitchText,
            fontWeight = FontWeight.SemiBold,
        )
        Surface(
            color = StitchSurfaceLow,
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(
                text = wgLikeStatus,
                fontFamily = FontFamily.Monospace,
                color = StitchMuted,
                style = MaterialTheme.typography.bodySmall,
                lineHeight = 18.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
            )
        }
    }
}

// ── Servers Tab ────────────────────────────────────────────────────────────────

@Composable
private fun TunnelDashboardSection(
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
    var countryFilter by remember { mutableStateOf("All") }
    val favoriteSet = remember(favoriteServers) { favoriteServers.map { it.lowercase() }.toSet() }
    val countries = remember(servers) {
        buildList {
            add("All")
            addAll(servers.map(::stitchExtractCountryCode).filter { it != "--" }.distinct().sorted())
        }
    }
    LaunchedEffect(countries) {
        if (countryFilter !in countries) countryFilter = "All"
    }
    val filteredServers = remember(servers, favoriteSet, searchQuery, countryFilter) {
        servers
            .filter { searchQuery.isBlank() || it.contains(searchQuery, ignoreCase = true) }
            .filter { countryFilter == "All" || stitchExtractCountryCode(it) == countryFilter }
            .sortedWith(compareByDescending<String> { favoriteSet.contains(it.lowercase()) }.thenBy { it.lowercase() })
    }
    val groupedServers = remember(filteredServers) {
        filteredServers.groupBy { stitchExtractCountryCode(it) }
            .toSortedMap()
    }

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        // Header
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = "Select Location",
                style = MaterialTheme.typography.headlineMedium,
                color = StitchText,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Choose a secure entry point from our global nodes.",
                style = MaterialTheme.typography.bodyMedium,
                color = StitchMuted,
            )
        }

        if (!isLoggedIn) {
            BannerMessage("Login required before tunnel inventory can be loaded.", StitchMuted)
            return
        }

        // Smart Location
        StitchPanel {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "Smart Location",
                        style = MaterialTheme.typography.titleMedium,
                        color = StitchText,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = "Auto-connect to the lowest latency node",
                        style = MaterialTheme.typography.bodySmall,
                        color = StitchMuted,
                    )
                }
                Button(
                    onClick = {
                        val target = servers.firstOrNull { favoriteSet.contains(it.lowercase()) }
                            ?: servers.firstOrNull()
                        if (target != null) onConnect(target)
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StitchPrimary,
                        contentColor = Color(0xFF00315F),
                    ),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("CONNECT", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                }
            }
        }

        // Search
        StitchField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            label = "Search tunnels",
            leadingIcon = {
                Icon(Icons.Filled.Search, contentDescription = null, tint = StitchMuted, modifier = Modifier.size(20.dp))
            },
        )

        // Country filter chips
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            countries.take(14).forEach { country ->
                FilterChip(
                    selected = country == countryFilter,
                    onClick = { countryFilter = country },
                    label = { Text(if (country == "All") "All" else country, style = MaterialTheme.typography.labelMedium) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = StitchPrimaryDeep,
                        selectedLabelColor = StitchPrimary,
                        containerColor = StitchSurfaceHigh,
                        labelColor = StitchMuted,
                    ),
                    shape = RoundedCornerShape(999.dp),
                )
            }
        }

        Text(
            text = "${filteredServers.size} available endpoints",
            color = StitchMuted,
            style = MaterialTheme.typography.bodySmall,
        )

        // Grouped server list
        groupedServers.forEach { (countryCode, serversInGroup) ->
            val countryName = countryCodeToName(countryCode)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                // Country group header
                Surface(
                    color = StitchSurfaceHigh.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = countryName,
                            style = MaterialTheme.typography.titleSmall,
                            color = StitchText,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = "${serversInGroup.size} Servers Available",
                            style = MaterialTheme.typography.bodySmall,
                            color = StitchMuted,
                        )
                    }
                }
                serversInGroup.take(40).forEach { server ->
                    val favorite = favoriteSet.contains(server.lowercase())
                    ServerCard(
                        server = server,
                        subtitle = countryName,
                        favorite = favorite,
                        connected = connectionState == ConnectionState.Connected && activeServer == server,
                        onConnect = { onConnect(server) },
                        onDisconnect = onDisconnect,
                        onToggleFavorite = { onSetServerFavorite(server, !favorite) },
                    )
                }
            }
        }
    }
}

// ── Settings Tab: Account Section ──────────────────────────────────────────────

@Composable
private fun AccountSection(
    provider: String,
    loggedInUsername: String,
    onLogout: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "Account",
            style = MaterialTheme.typography.headlineMedium,
            color = StitchText,
            fontWeight = FontWeight.Bold,
        )
        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Filled.Shield, contentDescription = null, tint = StitchPrimary, modifier = Modifier.size(20.dp))
                        Text(
                            text = provider.uppercase(),
                            style = MaterialTheme.typography.titleMedium,
                            color = StitchText,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    Surface(
                        color = StitchSuccess.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(999.dp),
                    ) {
                        Text(
                            text = "Active",
                            color = StitchSuccess,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        )
                    }
                }
                Text(
                    text = loggedInUsername.ifBlank { "Authenticated" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = StitchMuted,
                )
                OutlinedButton(
                    onClick = onLogout,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchDanger),
                ) {
                    Text("Log Out")
                }
            }
        }
    }
}

// ── Settings Tab: Provider Configuration ───────────────────────────────────────

@Composable
private fun ConfigDashboardSection(
    provider: String,
    config: AppConfigModel,
    airvpnKeys: List<AirvpnKey>,
    selectedAirvpnKey: String,
    airvpnDevices: List<AirvpnDevice>,
    providerCurrentKeys: Map<String, String>,
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
                airvpn = AirvpnConfig(defaultCountry = airvpnCountry.trim(), defaultDevice = airvpnDevice.trim()),
                mullvad = ProviderConfig(defaultCountry = mullvadCountry.trim()),
                ivpn = ProviderConfig(defaultCountry = ivpnCountry.trim()),
            )
        )
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionHeading("Provider Configuration", "Default countries, device keys, and provider management.")

        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                StitchField(value = protonCountry, onValueChange = { protonCountry = it }, label = "Proton default country")
                StitchField(value = airvpnCountry, onValueChange = { airvpnCountry = it }, label = "AirVPN default country")
                StitchField(value = airvpnDevice, onValueChange = { airvpnDevice = it }, label = "AirVPN default device")
                StitchField(value = mullvadCountry, onValueChange = { mullvadCountry = it }, label = "Mullvad default country")
                StitchField(value = ivpnCountry, onValueChange = { ivpnCountry = it }, label = "IVPN default country")
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = saveConfig,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = StitchPrimary,
                            contentColor = Color(0xFF00315F),
                        ),
                        shape = RoundedCornerShape(12.dp),
                    ) { Text("Save defaults", fontWeight = FontWeight.SemiBold) }
                    if (provider == "airvpn") {
                        OutlinedButton(
                            onClick = onRefreshAirvpn,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                        ) { Text("Refresh AirVPN") }
                    }
                }
            }
        }

        // Current keys
        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Current key by provider", style = MaterialTheme.typography.titleMedium, color = StitchText, fontWeight = FontWeight.SemiBold)
                listOf("proton", "airvpn", "mullvad", "ivpn").forEach { name ->
                    val fallback = if (name == "airvpn") config.airvpn.defaultDevice else ""
                    MetricRow(name.uppercase(), providerCurrentKeys[name].orEmpty().ifBlank { fallback.ifBlank { "none" } })
                }
            }
        }

        // AirVPN key/device management
        if (provider == "airvpn") {
            StitchPanel {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("AirVPN Keys & Devices", style = MaterialTheme.typography.titleMedium, color = StitchText, fontWeight = FontWeight.SemiBold)
                    Text("Selected key: ${selectedAirvpnKey.ifBlank { "none" }}", color = StitchMuted, style = MaterialTheme.typography.bodySmall)
                    airvpnKeys.ifEmpty {
                        listOf(AirvpnKey("No keys loaded", "", ""))
                    }.forEach { key ->
                        Surface(
                            color = StitchSurfaceHigh,
                            shape = RoundedCornerShape(12.dp),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(key.name, color = StitchText, style = MaterialTheme.typography.bodyMedium)
                                    if (key.ipv4.isNotBlank()) {
                                        Text(key.ipv4, color = StitchMuted, style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                                if (key.ipv4.isNotBlank() || key.ipv6.isNotBlank()) {
                                    OutlinedButton(
                                        onClick = { onSelectAirvpnKey(key.name) },
                                        shape = RoundedCornerShape(12.dp),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                                    ) { Text("Select") }
                                }
                            }
                        }
                    }
                    HorizontalDivider(color = StitchOutline.copy(alpha = 0.15f))
                    StitchField(value = addDeviceName, onValueChange = { addDeviceName = it }, label = "Create device")
                    Button(
                        onClick = { onAddAirvpnDevice(addDeviceName); addDeviceName = "" },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = StitchPrimaryDeep, contentColor = StitchPrimary),
                        shape = RoundedCornerShape(12.dp),
                    ) { Text("Create device") }
                    StitchField(value = renameFrom, onValueChange = { renameFrom = it }, label = "Rename from")
                    StitchField(value = renameTo, onValueChange = { renameTo = it }, label = "Rename to")
                    OutlinedButton(
                        onClick = { onRenameAirvpnDevice(renameFrom, renameTo); renameFrom = ""; renameTo = "" },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                    ) { Text("Rename device") }
                    StitchField(value = deleteName, onValueChange = { deleteName = it }, label = "Delete device")
                    OutlinedButton(
                        onClick = { onDeleteAirvpnDevice(deleteName); deleteName = "" },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchDanger),
                    ) { Text("Delete device") }
                    Text(
                        text = "Known devices: ${airvpnDevices.joinToString { it.name }.ifBlank { "none" }}",
                        color = StitchMuted,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

// ── Settings Tab: Application Parameters ───────────────────────────────────────

@Composable
private fun ApplicationParametersSection(
    config: AppConfigModel,
    autoConfig: AutoTunnelConfig,
    onSetAutoEnabled: (Boolean) -> Unit,
    onSetStopOnNoInternet: (Boolean) -> Unit,
    onSetAppMode: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionHeading("Application Parameters", "Core behavior and security settings.")

        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                ToggleLine(
                    title = "Auto-connect",
                    subtitle = "Auto-connect on untrusted networks",
                    checked = autoConfig.enabled,
                    onToggle = onSetAutoEnabled,
                )
                ToggleLine(
                    title = "Kill Switch",
                    subtitle = "Block traffic if connection drops",
                    checked = autoConfig.stopOnNoInternet,
                    onToggle = onSetStopOnNoInternet,
                )
                // Preferred Protocol (read-only)
                Surface(
                    color = StitchSurfaceHigh,
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Preferred Protocol", color = StitchText, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Text("Tunneling protocol for all connections", color = StitchMuted, style = MaterialTheme.typography.bodySmall)
                        }
                        Surface(
                            color = StitchPrimaryDeep.copy(alpha = 0.4f),
                            shape = RoundedCornerShape(999.dp),
                        ) {
                            Text(
                                text = "WireGuard",
                                color = StitchPrimary,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                            )
                        }
                    }
                }
                // App Mode chips
                Surface(
                    color = StitchSurfaceHigh,
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Text("App Mode", color = StitchText, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("vpn" to "VPN", "proxy" to "Proxy").forEach { (mode, label) ->
                                FilterChip(
                                    selected = config.general.appMode == mode,
                                    onClick = { onSetAppMode(mode) },
                                    label = { Text(label) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = StitchPrimaryDeep,
                                        selectedLabelColor = StitchPrimary,
                                        containerColor = StitchSurfaceBright,
                                        labelColor = StitchMuted,
                                    ),
                                    shape = RoundedCornerShape(999.dp),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Settings Tab: App Filter ───────────────────────────────────────────────────

@Composable
private fun AppFilterSection(
    config: AppConfigModel,
    splitTunnelApps: List<SplitTunnelApp>,
    onSetSplitTunnelOnlyAllowSelected: (Boolean) -> Unit,
    onSetSplitTunnelApp: (String, Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionHeading("App Filter", "Define per-app routing rules for the secure tunnel.")

        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Whitelist / Blacklist chips
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = config.general.splitTunnelOnlyAllowSelected,
                        onClick = { onSetSplitTunnelOnlyAllowSelected(true) },
                        label = { Text("Whitelist") },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = StitchPrimaryDeep,
                            selectedLabelColor = StitchPrimary,
                            containerColor = StitchSurfaceHigh,
                            labelColor = StitchMuted,
                        ),
                        shape = RoundedCornerShape(999.dp),
                    )
                    FilterChip(
                        selected = !config.general.splitTunnelOnlyAllowSelected,
                        onClick = { onSetSplitTunnelOnlyAllowSelected(false) },
                        label = { Text("Blacklist") },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = StitchPrimaryDeep,
                            selectedLabelColor = StitchPrimary,
                            containerColor = StitchSurfaceHigh,
                            labelColor = StitchMuted,
                        ),
                        shape = RoundedCornerShape(999.dp),
                    )
                }

                // Active mode label
                Surface(
                    color = StitchSurfaceHigh,
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            text = "Active: ${if (config.general.splitTunnelOnlyAllowSelected) "Whitelist" else "Blacklist"}",
                            color = StitchPrimary,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = if (config.general.splitTunnelOnlyAllowSelected)
                                "Only selected applications will be routed through the TUNMUX tunnel. All other traffic will bypass and use the direct network interface."
                            else
                                "Selected applications will bypass the TUNMUX tunnel. All other traffic will be routed through the secure connection.",
                            color = StitchMuted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }

                // App list
                if (splitTunnelApps.isEmpty()) {
                    Text("No Android applications discovered yet.", color = StitchMuted, style = MaterialTheme.typography.bodyMedium)
                } else {
                    splitTunnelApps.take(40).forEach { app ->
                        val enabled = config.general.splitTunnelApps.any { it == app.packageName }
                        ToggleLine(
                            title = app.label,
                            subtitle = app.packageName,
                            checked = enabled,
                            onToggle = { onSetSplitTunnelApp(app.packageName, it) },
                        )
                    }
                }
            }
        }
    }
}

// ── Settings Tab: Auto-Tunnel ──────────────────────────────────────────────────

@Composable
private fun AutoDashboardSection(
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
    var wifiSsidInput by remember(autoConfig.wifiSsids) { mutableStateOf(autoConfig.wifiSsids.joinToString(", ")) }
    val locationWarning = when {
        !locationPermissionGranted && !locationServicesEnabled -> "SSID matching requires location permission and location services."
        !locationPermissionGranted -> "SSID matching requires location permission."
        !locationServicesEnabled -> "SSID matching requires location services."
        else -> ""
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionHeading("Auto-Tunnel", "Automated connection policy for Wi-Fi, mobile, and startup.")

        StitchPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                ToggleLine("Auto tunnel", "Run policy evaluation automatically.", autoConfig.enabled, onSetAutoEnabled)
                ToggleLine("On Wi-Fi", "Apply tunnel policy on wireless networks.", autoConfig.onWifi, onSetAutoWifi)
                ToggleLine("On mobile", "Apply tunnel policy on cellular data.", autoConfig.onMobile, onSetAutoMobile)
                ToggleLine("On ethernet", "Apply tunnel policy on wired connections.", autoConfig.onEthernet, onSetAutoEthernet)
                ToggleLine("Stop on no internet", "Pause route if upstream internet disappears.", autoConfig.stopOnNoInternet, onSetStopOnNoInternet)
                ToggleLine("Start on boot", "Start automation after device boot.", autoConfig.startOnBoot, onSetStartOnBoot)
            }
        }

        if (autoConfig.onWifi) {
            StitchPanel {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Wi-Fi Policy", style = MaterialTheme.typography.titleMedium, color = StitchText, fontWeight = FontWeight.SemiBold)
                    MetricRow("Current SSID", connectedWifiSsid.ifBlank { "Unknown" })
                    MetricRow("Detection", autoConfig.wifiDetectionMethod.name)
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        WifiDetectionMethod.entries.forEach { method ->
                            FilterChip(
                                selected = autoConfig.wifiDetectionMethod == method,
                                onClick = { onSetAutoWifiDetectionMethod(method) },
                                label = { Text(method.name) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = StitchPrimaryDeep,
                                    selectedLabelColor = StitchPrimary,
                                    containerColor = StitchSurfaceHigh,
                                    labelColor = StitchMuted,
                                ),
                                shape = RoundedCornerShape(999.dp),
                            )
                        }
                    }
                    if (locationWarning.isNotBlank()) {
                        BannerMessage(locationWarning, StitchDanger)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (!locationPermissionGranted) {
                                OutlinedButton(
                                    onClick = onRequestLocationPermissions,
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                                ) { Text("Grant location") }
                            }
                            if (!locationServicesEnabled) {
                                OutlinedButton(
                                    onClick = onOpenLocationSettings,
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                                ) { Text("Open settings") }
                            }
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = onAddCurrentWifi,
                            enabled = connectedWifiSsid.isNotBlank(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                        ) { Text("Add current") }
                        OutlinedButton(
                            onClick = onRefreshKnownWifi,
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                        ) { Text("Refresh known") }
                    }
                    ToggleLine(
                        title = "Disconnect on matched Wi-Fi",
                        subtitle = "When enabled, listed SSIDs disable the tunnel instead of enabling it.",
                        checked = autoConfig.disconnectOnMatchedWifi,
                        onToggle = onSetAutoDisconnectOnMatchedWifi,
                    )
                    StitchField(
                        value = wifiSsidInput,
                        onValueChange = { wifiSsidInput = it; onSetAutoWifiSsids(it) },
                        label = "Wi-Fi SSIDs (comma separated)",
                        singleLine = false,
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        knownWifiSsids.take(20).forEach { ssid ->
                            FilterChip(
                                selected = false,
                                onClick = { onAddKnownWifi(ssid) },
                                label = { Text(ssid) },
                                colors = FilterChipDefaults.filterChipColors(
                                    containerColor = StitchSurfaceHigh,
                                    labelColor = StitchMuted,
                                ),
                                shape = RoundedCornerShape(999.dp),
                            )
                        }
                    }
                    MetricRow("Debounce", "${autoConfig.debounceDelaySeconds}s")
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        listOf(0, 1, 3, 5, 10).forEach { seconds ->
                            FilterChip(
                                selected = autoConfig.debounceDelaySeconds == seconds,
                                onClick = { onSetAutoDebounceDelaySeconds(seconds) },
                                label = { Text("${seconds}s") },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = StitchPrimaryDeep,
                                    selectedLabelColor = StitchPrimary,
                                    containerColor = StitchSurfaceHigh,
                                    labelColor = StitchMuted,
                                ),
                                shape = RoundedCornerShape(999.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── Settings Tab: Danger Zone ──────────────────────────────────────────────────

@Composable
private fun DangerZoneSection(
    isLoggedIn: Boolean,
    onLogout: () -> Unit,
    onOpenLogin: () -> Unit,
) {
    StitchPanel {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Danger Zone", style = MaterialTheme.typography.titleMedium, color = StitchDanger, fontWeight = FontWeight.SemiBold)
            if (isLoggedIn) {
                OutlinedButton(
                    onClick = onLogout,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchDanger),
                ) { Text("Sign Out of Device") }
            } else {
                OutlinedButton(
                    onClick = onOpenLogin,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StitchPrimary),
                ) { Text("Switch Provider Account") }
            }
        }
    }
}

// ── Shared Components ──────────────────────────────────────────────────────────

@Composable
private fun ServerCard(
    server: String,
    subtitle: String,
    favorite: Boolean,
    connected: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onToggleFavorite: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = StitchSurface),
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = if (connected) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                contentDescription = null,
                tint = if (connected) StitchSuccess else StitchMuted,
                modifier = Modifier.size(20.dp),
            )
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(server, color = StitchText, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                Text(subtitle, color = StitchMuted, style = MaterialTheme.typography.bodySmall)
            }
            IconButton(onClick = onToggleFavorite, modifier = Modifier.size(36.dp)) {
                Icon(
                    imageVector = if (favorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                    contentDescription = null,
                    tint = if (favorite) StitchPrimary else StitchMuted,
                    modifier = Modifier.size(20.dp),
                )
            }
            OutlinedButton(
                onClick = { if (connected) onDisconnect() else onConnect() },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = if (connected) StitchDanger else StitchPrimary,
                ),
            ) {
                Text(
                    if (connected) "Stop" else "Route",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun StitchPanel(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = StitchSurfaceBright.copy(alpha = 0.6f),
        shape = RoundedCornerShape(12.dp),
        tonalElevation = 0.dp,
        shadowElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content,
        )
    }
}

@Composable
private fun SectionHeading(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = StitchText, fontWeight = FontWeight.Bold)
        Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = StitchMuted)
    }
}

@Composable
private fun BannerMessage(message: String, tone: Color) {
    Surface(
        color = StitchSurfaceHigh,
        shape = RoundedCornerShape(12.dp),
    ) {
        Text(
            text = message,
            color = tone,
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun MetricBlock(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: Color = StitchPrimary,
) {
    Surface(
        modifier = modifier,
        color = StitchSurfaceHigh,
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(title, style = MaterialTheme.typography.bodySmall, color = StitchMuted)
            Text(
                value,
                style = MaterialTheme.typography.titleMedium,
                color = accent,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
            )
        }
    }
}

@Composable
private fun MetricRow(title: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, color = StitchMuted, style = MaterialTheme.typography.bodyMedium)
        Text(value, color = StitchText, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun ToggleLine(
    title: String,
    subtitle: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Surface(
        color = StitchSurfaceHigh,
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, color = StitchText, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(subtitle, color = StitchMuted, style = MaterialTheme.typography.bodySmall)
            }
            Switch(
                checked = checked,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = StitchBackground,
                    checkedTrackColor = StitchSuccess,
                    uncheckedThumbColor = StitchMuted,
                    uncheckedTrackColor = StitchSurfaceBright,
                ),
            )
        }
    }
}

@Composable
private fun ProviderPill(provider: String, detail: String) {
    Surface(
        color = StitchSurfaceHigh,
        shape = RoundedCornerShape(999.dp),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.Shield, contentDescription = null, tint = StitchPrimary, modifier = Modifier.size(20.dp))
            Column {
                Text(provider.uppercase(), color = StitchText, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                Text(detail, color = StitchMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun StitchField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    password: Boolean = false,
    singleLine: Boolean = true,
    leadingIcon: @Composable (() -> Unit)? = null,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = singleLine,
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        modifier = Modifier.fillMaxWidth(),
        leadingIcon = leadingIcon,
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = StitchPrimary,
            unfocusedBorderColor = StitchOutline.copy(alpha = 0.5f),
            focusedLabelColor = StitchPrimary,
            unfocusedLabelColor = StitchMuted,
            cursorColor = StitchPrimary,
            focusedTextColor = StitchText,
            unfocusedTextColor = StitchText,
        ),
        shape = RoundedCornerShape(12.dp),
    )
}

@Composable
private fun StatusDot(connectionState: ConnectionState) {
    val dotColor = when (connectionState) {
        ConnectionState.Connected -> StitchSuccess
        ConnectionState.Connecting -> StitchPrimary
        ConnectionState.Disconnected -> StitchOutline
    }
    Box(
        modifier = Modifier
            .size(14.dp)
            .clip(CircleShape)
            .background(dotColor),
    )
}

// ── Utility functions ──────────────────────────────────────────────────────────

private fun stitchBackdropBrush(): Brush {
    return Brush.radialGradient(
        colors = listOf(
            Color(0xFF004C8F).copy(alpha = 0.35f),
            StitchBackground,
        ),
        center = androidx.compose.ui.geometry.Offset(0f, 0f),
        radius = 1200f,
    )
}

private fun providerDescription(provider: String): String {
    return when (provider) {
        "proton" -> "Secure account login with optional 2FA."
        "airvpn" -> "Provider login and device-key provisioning."
        "mullvad" -> "Account-number based route provisioning."
        "ivpn" -> "Account-number based route provisioning."
        else -> "Secure route provisioning."
    }
}

private fun connectionHeadline(state: ConnectionState): String {
    return when (state) {
        ConnectionState.Connected -> "System Secure"
        ConnectionState.Connecting -> "Negotiating Route"
        ConnectionState.Disconnected -> "System Online"
    }
}

private fun stitchExtractCountryCode(server: String): String {
    val match = "\\[([A-Za-z]{2})\\]".toRegex().find(server) ?: return "--"
    return match.groupValues.getOrNull(1)?.uppercase().orEmpty().ifBlank { "--" }
}

private fun countryCodeToName(code: String): String = when (code.uppercase()) {
    "US" -> "United States"
    "DE" -> "Germany"
    "JP" -> "Japan"
    "GB", "UK" -> "United Kingdom"
    "CA" -> "Canada"
    "AU" -> "Australia"
    "NL" -> "Netherlands"
    "SE" -> "Sweden"
    "CH" -> "Switzerland"
    "FR" -> "France"
    "IT" -> "Italy"
    "ES" -> "Spain"
    "AT" -> "Austria"
    "BE" -> "Belgium"
    "CZ" -> "Czech Republic"
    "DK" -> "Denmark"
    "FI" -> "Finland"
    "HU" -> "Hungary"
    "IE" -> "Ireland"
    "NO" -> "Norway"
    "PL" -> "Poland"
    "PT" -> "Portugal"
    "RO" -> "Romania"
    "SG" -> "Singapore"
    "KR" -> "South Korea"
    "HK" -> "Hong Kong"
    "BR" -> "Brazil"
    "IN" -> "India"
    "MX" -> "Mexico"
    "ZA" -> "South Africa"
    "IL" -> "Israel"
    "BG" -> "Bulgaria"
    "HR" -> "Croatia"
    "LV" -> "Latvia"
    "LU" -> "Luxembourg"
    "MD" -> "Moldova"
    "RS" -> "Serbia"
    "SK" -> "Slovakia"
    "UA" -> "Ukraine"
    "IS" -> "Iceland"
    "PA" -> "Panama"
    "NZ" -> "New Zealand"
    else -> code.uppercase()
}

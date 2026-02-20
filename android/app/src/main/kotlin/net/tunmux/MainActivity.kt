package net.tunmux

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import net.tunmux.model.AirvpnDevice
import net.tunmux.model.AirvpnKey
import net.tunmux.model.AirvpnConfig
import net.tunmux.model.AppConfigModel
import net.tunmux.model.ConnectionState
import net.tunmux.model.GeneralConfig
import net.tunmux.model.ProviderConfig
import net.tunmux.model.Screen
import net.tunmux.model.VpnViewModel

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
            MaterialTheme {
                TunmuxApp()
            }
        }
    }
}

@Composable
fun TunmuxApp(vm: VpnViewModel = viewModel()) {
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val activity = context as? MainActivity

    when (state.screen) {
        Screen.ProviderSelect -> ProviderScreen(
            onSelect = { vm.selectProvider(it) },
            onSettings = { vm.openSettings() },
        )
        Screen.Login -> LoginScreen(
            provider = state.selectedProvider,
            error = state.errorMessage,
            onLogin = { u, p, t -> vm.login(u, p, t) },
            onBack = { vm.navigateBack() },
            onSettings = { vm.openSettings() },
        )
        Screen.ServerList -> ServerListScreen(
            servers = state.serverList,
            error = state.errorMessage,
            onConnect = { serverJson ->
                activity?.requestVpnPermissionAndConnect {
                    vm.connect(context, serverJson)
                }
            },
            onLogout = { vm.logout() },
            onBack = { vm.navigateBack() },
            onSettings = { vm.openSettings() },
        )
        Screen.Home -> HomeScreen(
            connectionState = state.connectionState,
            provider = state.selectedProvider,
            onDisconnect = { vm.disconnect(context) },
            onSettings = { vm.openSettings() },
        )
        Screen.Settings -> SettingsScreen(
            provider = state.selectedProvider,
            config = state.config,
            airvpnKeys = state.airvpnKeys,
            selectedAirvpnKey = state.selectedAirvpnKey,
            airvpnDevices = state.airvpnDevices,
            message = state.settingsMessage,
            onSave = { vm.saveConfig(it) },
            onSelectAirvpnKey = { vm.selectAirvpnKey(it) },
            onRefreshAirvpn = { vm.refreshAirvpnSettingsData() },
            onAddAirvpnDevice = { vm.addAirvpnDevice(it) },
            onRenameAirvpnDevice = { from, to -> vm.renameAirvpnDevice(from, to) },
            onDeleteAirvpnDevice = { vm.deleteAirvpnDevice(it) },
            onBack = { vm.closeSettings() },
        )
    }
}

@Composable
fun ProviderScreen(onSelect: (String) -> Unit, onSettings: () -> Unit) {
    val providers = listOf("proton", "airvpn", "mullvad", "ivpn")
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("tunmux", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(20.dp))
        OutlinedButton(onClick = onSettings) { Text("Settings") }
        Spacer(Modifier.height(12.dp))
        Text("Select VPN Provider", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(16.dp))
        for (p in providers) {
            Button(
                onClick = { onSelect(p) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
            ) {
                Text(p)
            }
        }
    }
}

@Composable
fun LoginScreen(
    provider: String,
    error: String,
    onLogin: (String, String, String) -> Unit,  // username, password, twoFa
    onBack: () -> Unit,
    onSettings: () -> Unit,
) {
    val needsPassword = provider == "proton" || provider == "airvpn"
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var twoFa by remember { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Login to $provider", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
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
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
            )
        }
        if (provider == "proton") {
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = twoFa,
                onValueChange = { twoFa = it },
                label = { Text("2FA Code (leave blank if disabled)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
        if (error.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(error, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            OutlinedButton(onClick = onSettings) { Text("Settings") }
            Button(onClick = { onLogin(username, password, twoFa) }) { Text("Login") }
        }
    }
}

@Composable
fun ServerListScreen(
    servers: List<String>,
    error: String,
    onConnect: (String) -> Unit,
    onLogout: () -> Unit,
    onBack: () -> Unit,
    onSettings: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            OutlinedButton(onClick = onSettings) { Text("Settings") }
            Text(
                "Select Server",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = onLogout) { Text("Logout") }
        }
        if (error.isNotEmpty()) {
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
        if (servers.isEmpty()) {
            Text("No servers available")
        } else {
            LazyColumn {
                items(servers) { server ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        onClick = { onConnect(server) },
                    ) {
                        Text(
                            text = server,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun HomeScreen(
    connectionState: ConnectionState,
    provider: String,
    onDisconnect: () -> Unit,
    onSettings: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("tunmux", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(24.dp))
        Text(
            text = when (connectionState) {
                ConnectionState.Connected -> "Connected"
                ConnectionState.Connecting -> "Connecting..."
                ConnectionState.Disconnected -> "Disconnected"
            },
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(8.dp))
        Text("Provider: $provider", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(24.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onSettings) { Text("Settings") }
            Button(
                onClick = onDisconnect,
                enabled = connectionState == ConnectionState.Connected,
            ) {
                Text("Disconnect")
            }
        }
    }
}

@Composable
fun SettingsScreen(
    provider: String,
    config: AppConfigModel,
    airvpnKeys: List<AirvpnKey>,
    selectedAirvpnKey: String,
    airvpnDevices: List<AirvpnDevice>,
    message: String,
    onSave: (AppConfigModel) -> Unit,
    onSelectAirvpnKey: (String) -> Unit,
    onRefreshAirvpn: () -> Unit,
    onAddAirvpnDevice: (String) -> Unit,
    onRenameAirvpnDevice: (String, String) -> Unit,
    onDeleteAirvpnDevice: (String) -> Unit,
    onBack: () -> Unit,
) {
    var backend by remember(config) { mutableStateOf(config.general.backend) }
    var credentialStore by remember(config) { mutableStateOf(config.general.credentialStore) }
    var proxy by remember(config) { mutableStateOf(config.general.proxy) }
    var socksPort by remember(config) { mutableStateOf(config.general.socksPort?.toString() ?: "") }
    var httpPort by remember(config) { mutableStateOf(config.general.httpPort?.toString() ?: "") }
    var proxyAccessLog by remember(config) { mutableStateOf(config.general.proxyAccessLog) }
    var privilegedTransport by remember(config) { mutableStateOf(config.general.privilegedTransport) }
    var privilegedAutostart by remember(config) { mutableStateOf(config.general.privilegedAutostart) }
    var privilegedAutostartTimeoutMs by remember(config) {
        mutableStateOf(config.general.privilegedAutostartTimeoutMs.toString())
    }
    var privilegedAuthorizedGroup by remember(config) {
        mutableStateOf(config.general.privilegedAuthorizedGroup)
    }
    var privilegedAutostopMode by remember(config) { mutableStateOf(config.general.privilegedAutostopMode) }
    var privilegedAutostopTimeoutMs by remember(config) {
        mutableStateOf(config.general.privilegedAutostopTimeoutMs.toString())
    }

    var protonCountry by remember(config) { mutableStateOf(config.proton.defaultCountry) }
    var airvpnCountry by remember(config) { mutableStateOf(config.airvpn.defaultCountry) }
    var airvpnDevice by remember(config) { mutableStateOf(config.airvpn.defaultDevice) }
    var mullvadCountry by remember(config) { mutableStateOf(config.mullvad.defaultCountry) }
    var ivpnCountry by remember(config) { mutableStateOf(config.ivpn.defaultCountry) }

    var addDeviceName by remember { mutableStateOf("") }
    var renameFrom by remember { mutableStateOf("") }
    var renameTo by remember { mutableStateOf("") }
    var deleteName by remember { mutableStateOf("") }

    val saveAction = {
        val updated = AppConfigModel(
            general = GeneralConfig(
                backend = backend.trim(),
                credentialStore = credentialStore.trim(),
                proxy = proxy,
                socksPort = parseIntOrNull(socksPort),
                httpPort = parseIntOrNull(httpPort),
                proxyAccessLog = proxyAccessLog,
                privilegedTransport = privilegedTransport.trim(),
                privilegedAutostart = privilegedAutostart,
                privilegedAutostartTimeoutMs = parseLongOrDefault(privilegedAutostartTimeoutMs, 5000L),
                privilegedAuthorizedGroup = privilegedAuthorizedGroup.trim(),
                privilegedAutostopMode = privilegedAutostopMode.trim(),
                privilegedAutostopTimeoutMs = parseLongOrDefault(privilegedAutostopTimeoutMs, 30000L),
            ),
            proton = ProviderConfig(defaultCountry = protonCountry.trim()),
            airvpn = AirvpnConfig(
                defaultCountry = airvpnCountry.trim(),
                defaultDevice = airvpnDevice.trim(),
            ),
            mullvad = ProviderConfig(defaultCountry = mullvadCountry.trim()),
            ivpn = ProviderConfig(defaultCountry = ivpnCountry.trim()),
        )
        onSave(updated)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Button(onClick = saveAction) { Text("Save") }
            if (provider == "airvpn") {
                OutlinedButton(onClick = onRefreshAirvpn) { Text("Refresh") }
            }
        }

        if (message.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(message, color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(12.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item {
                Text("Global", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = backend,
                    onValueChange = { backend = it },
                    label = { Text("general.backend") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = credentialStore,
                    onValueChange = { credentialStore = it },
                    label = { Text("general.credential_store") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = privilegedTransport,
                    onValueChange = { privilegedTransport = it },
                    label = { Text("general.privileged_transport") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = privilegedAuthorizedGroup,
                    onValueChange = { privilegedAuthorizedGroup = it },
                    label = { Text("general.privileged_authorized_group") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = privilegedAutostopMode,
                    onValueChange = { privilegedAutostopMode = it },
                    label = { Text("general.privileged_autostop_mode") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = privilegedAutostartTimeoutMs,
                    onValueChange = { privilegedAutostartTimeoutMs = it },
                    label = { Text("general.privileged_autostart_timeout_ms") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = privilegedAutostopTimeoutMs,
                    onValueChange = { privilegedAutostopTimeoutMs = it },
                    label = { Text("general.privileged_autostop_timeout_ms") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = socksPort,
                    onValueChange = { socksPort = it },
                    label = { Text("general.socks_port") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = httpPort,
                    onValueChange = { httpPort = it },
                    label = { Text("general.http_port") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("general.proxy")
                    Spacer(Modifier.weight(1f))
                    Switch(checked = proxy, onCheckedChange = { proxy = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("general.proxy_access_log")
                    Spacer(Modifier.weight(1f))
                    Switch(checked = proxyAccessLog, onCheckedChange = { proxyAccessLog = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("general.privileged_autostart")
                    Spacer(Modifier.weight(1f))
                    Switch(checked = privilegedAutostart, onCheckedChange = { privilegedAutostart = it })
                }
            }

            item {
                Text("Provider Defaults", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = protonCountry,
                    onValueChange = { protonCountry = it },
                    label = { Text("proton.default_country") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = airvpnCountry,
                    onValueChange = { airvpnCountry = it },
                    label = { Text("airvpn.default_country") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = airvpnDevice,
                    onValueChange = { airvpnDevice = it },
                    label = { Text("airvpn.default_device") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = mullvadCountry,
                    onValueChange = { mullvadCountry = it },
                    label = { Text("mullvad.default_country") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = ivpnCountry,
                    onValueChange = { ivpnCountry = it },
                    label = { Text("ivpn.default_country") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }

            if (provider == "airvpn") {
                item {
                    Text("AirVPN Device Keys", style = MaterialTheme.typography.titleLarge)
                    Text("Selected: $selectedAirvpnKey")
                }

                if (airvpnKeys.isEmpty()) {
                    item { Text("No AirVPN keys available") }
                } else {
                    items(airvpnKeys) { key ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(key.name, style = MaterialTheme.typography.titleMedium)
                                if (key.ipv4.isNotBlank()) Text("IPv4: ${key.ipv4}")
                                if (key.ipv6.isNotBlank()) Text("IPv6: ${key.ipv6}")
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(onClick = { onSelectAirvpnKey(key.name) }) {
                                    Text("Select")
                                }
                            }
                        }
                    }
                }

                item {
                    Spacer(Modifier.height(6.dp))
                    Text("Create/Rename/Delete", style = MaterialTheme.typography.titleMedium)

                    OutlinedTextField(
                        value = addDeviceName,
                        onValueChange = { addDeviceName = it },
                        label = { Text("New device name (optional)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            onAddAirvpnDevice(addDeviceName)
                            addDeviceName = ""
                        }) { Text("Create") }
                    }

                    OutlinedTextField(
                        value = renameFrom,
                        onValueChange = { renameFrom = it },
                        label = { Text("Rename from") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = renameTo,
                        onValueChange = { renameTo = it },
                        label = { Text("Rename to") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            onRenameAirvpnDevice(renameFrom, renameTo)
                            renameFrom = ""
                            renameTo = ""
                        }) { Text("Rename") }
                    }

                    OutlinedTextField(
                        value = deleteName,
                        onValueChange = { deleteName = it },
                        label = { Text("Delete device") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            onDeleteAirvpnDevice(deleteName)
                            deleteName = ""
                        }) { Text("Delete") }
                    }

                    Spacer(Modifier.height(8.dp))
                    Text("Current devices: ${airvpnDevices.joinToString { it.name }}")
                }
            }
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

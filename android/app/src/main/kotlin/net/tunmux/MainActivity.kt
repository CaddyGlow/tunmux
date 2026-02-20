package net.tunmux

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import net.tunmux.model.Screen
import net.tunmux.model.VpnViewModel
import net.tunmux.model.ConnectionState

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
            onSelect = { vm.selectProvider(it) }
        )
        Screen.Login -> LoginScreen(
            provider = state.selectedProvider,
            error = state.errorMessage,
            onLogin = { vm.login(it) },
            onBack = { vm.navigateBack() },
        )
        Screen.ServerList -> ServerListScreen(
            servers = state.serverList,
            onConnect = { serverJson ->
                activity?.requestVpnPermissionAndConnect {
                    vm.connect(context, serverJson)
                }
            },
            onBack = { vm.navigateBack() },
        )
        Screen.Home -> HomeScreen(
            connectionState = state.connectionState,
            provider = state.selectedProvider,
            onDisconnect = { vm.disconnect(context) },
        )
    }
}

@Composable
fun ProviderScreen(onSelect: (String) -> Unit) {
    val providers = listOf("proton", "airvpn", "mullvad", "ivpn")
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("tunmux", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(32.dp))
        Text("Select VPN Provider", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(16.dp))
        for (p in providers) {
            Button(
                onClick = { onSelect(p) },
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
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
    onLogin: (String) -> Unit,
    onBack: () -> Unit,
) {
    var credential by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Login to $provider", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = credential,
            onValueChange = { credential = it },
            label = { Text(if (provider == "mullvad" || provider == "ivpn") "Account Number" else "Username / Email") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        if (error.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(error, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Button(onClick = { onLogin(credential) }) { Text("Login") }
        }
    }
}

@Composable
fun ServerListScreen(
    servers: List<String>,
    onConnect: (String) -> Unit,
    onBack: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 16.dp),
        ) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Spacer(Modifier.width(8.dp))
            Text("Select Server", style = MaterialTheme.typography.titleLarge)
        }
        if (servers.isEmpty()) {
            Text("No servers available")
        } else {
            LazyColumn {
                items(servers) { server ->
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
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
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
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
        Button(
            onClick = onDisconnect,
            enabled = connectionState == ConnectionState.Connected,
        ) {
            Text("Disconnect")
        }
    }
}

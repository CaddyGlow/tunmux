package net.tunmux.model

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import net.tunmux.RustBridge
import net.tunmux.TunmuxVpnService
import org.json.JSONObject

enum class Screen { ProviderSelect, Login, ServerList, Home }
enum class ConnectionState { Disconnected, Connecting, Connected }

data class UiState(
    val screen: Screen = Screen.ProviderSelect,
    val selectedProvider: String = "",
    val connectionState: ConnectionState = ConnectionState.Disconnected,
    val serverList: List<String> = emptyList(),
    val statusMessage: String = "",
    val errorMessage: String = "",
)

class VpnViewModel : ViewModel() {
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    fun selectProvider(provider: String) {
        _state.value = _state.value.copy(
            selectedProvider = provider,
            screen = Screen.Login,
        )
    }

    fun login(credential: String) {
        val provider = _state.value.selectedProvider
        viewModelScope.launch(Dispatchers.IO) {
            val result = RustBridge.login(provider, credential)
            val json = JSONObject(result)
            val status = json.optString("status", "error")
            if (status == "ok") {
                fetchServers()
                _state.value = _state.value.copy(screen = Screen.ServerList)
            } else {
                val error = json.optString("error", "login failed")
                _state.value = _state.value.copy(errorMessage = error)
            }
        }
    }

    fun fetchServers() {
        val provider = _state.value.selectedProvider
        viewModelScope.launch(Dispatchers.IO) {
            val json = RustBridge.fetchServers(provider)
            // Simplified: just store raw JSON for now
            _state.value = _state.value.copy(serverList = listOf(json))
        }
    }

    fun connect(context: Context, serverJson: String) {
        val provider = _state.value.selectedProvider
        _state.value = _state.value.copy(connectionState = ConnectionState.Connecting)
        val intent = Intent(context, TunmuxVpnService::class.java).apply {
            action = TunmuxVpnService.ACTION_CONNECT
            putExtra(TunmuxVpnService.EXTRA_PROVIDER, provider)
            putExtra(TunmuxVpnService.EXTRA_SERVER_JSON, serverJson)
        }
        context.startService(intent)
        _state.value = _state.value.copy(
            connectionState = ConnectionState.Connected,
            screen = Screen.Home,
        )
    }

    fun disconnect(context: Context) {
        val intent = Intent(context, TunmuxVpnService::class.java).apply {
            action = TunmuxVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
        _state.value = _state.value.copy(connectionState = ConnectionState.Disconnected)
    }

    fun navigateBack() {
        _state.value = when (_state.value.screen) {
            Screen.Login -> _state.value.copy(screen = Screen.ProviderSelect)
            Screen.ServerList -> _state.value.copy(screen = Screen.Login)
            Screen.Home -> _state.value.copy(screen = Screen.ServerList)
            Screen.ProviderSelect -> _state.value
        }
    }
}

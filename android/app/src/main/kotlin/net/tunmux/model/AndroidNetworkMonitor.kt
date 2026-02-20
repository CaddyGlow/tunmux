package net.tunmux.model

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class AndroidNetworkMonitor(
    private val context: Context,
) {
    companion object {
        private const val TAG = "tunmux"
    }

    private val appContext = context.applicationContext
    private val connectivityManager = appContext.getSystemService(ConnectivityManager::class.java)

    private val _state = MutableStateFlow(resolveNetworkSnapshot(appContext, WifiDetectionMethod.DEFAULT))
    val state: StateFlow<NetworkSnapshot> = _state.asStateFlow()

    private var currentDetectionMethod: WifiDetectionMethod = WifiDetectionMethod.DEFAULT
    private var isStarted = false

    private val defaultNetworkCallback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                refreshState("default_onAvailable")
            }

            override fun onLost(network: Network) {
                refreshState("default_onLost")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                refreshState("default_onCapabilitiesChanged")
            }
        }

    private val wifiNetworkCallback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                refreshState("wifi_onAvailable")
            }

            override fun onLost(network: Network) {
                refreshState("wifi_onLost")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                refreshState("wifi_onCapabilitiesChanged")
            }
        }

    fun start(detectionMethod: WifiDetectionMethod) {
        currentDetectionMethod = detectionMethod
        if (!isStarted) {
            registerCallbacks()
            isStarted = true
        }
        refreshState("start")
    }

    fun updateDetectionMethod(detectionMethod: WifiDetectionMethod) {
        if (currentDetectionMethod == detectionMethod) return
        currentDetectionMethod = detectionMethod
        refreshState("detection_method_changed")
    }

    fun refreshPermissions() {
        refreshState("permissions_refresh")
    }

    fun stop() {
        if (!isStarted) return
        runCatching { connectivityManager?.unregisterNetworkCallback(defaultNetworkCallback) }
        runCatching { connectivityManager?.unregisterNetworkCallback(wifiNetworkCallback) }
        isStarted = false
    }

    private fun registerCallbacks() {
        runCatching { connectivityManager?.registerDefaultNetworkCallback(defaultNetworkCallback) }
            .onFailure { Log.w(TAG, "default network callback registration failed", it) }

        val wifiRequest =
            NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build()
        runCatching { connectivityManager?.registerNetworkCallback(wifiRequest, wifiNetworkCallback) }
            .onFailure { Log.w(TAG, "wifi network callback registration failed", it) }
    }

    private fun refreshState(reason: String) {
        val snapshot = resolveNetworkSnapshot(appContext, currentDetectionMethod)
        if (_state.value != snapshot) {
            _state.value = snapshot
            Log.d(TAG, "network_snapshot_updated reason=$reason profile=${snapshot.profile} ssid=${snapshot.wifiSsid}")
        }
    }
}

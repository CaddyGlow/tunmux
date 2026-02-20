package net.tunmux

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.launch
import net.tunmux.model.AndroidNetworkMonitor
import net.tunmux.model.AppConfigStore
import net.tunmux.model.AutoTunnelConfig
import net.tunmux.model.NetworkProfile

class TunmuxVpnService : LifecycleVpnService() {

    companion object {
        const val ACTION_CONNECT = "net.tunmux.action.CONNECT"
        const val ACTION_DISCONNECT = "net.tunmux.action.DISCONNECT"
        const val EXTRA_PROVIDER = "net.tunmux.extra.PROVIDER"
        const val EXTRA_SERVER_JSON = "net.tunmux.extra.SERVER_JSON"
        const val EXTRA_APP_MODE = "net.tunmux.extra.APP_MODE"
        const val EXTRA_SPLIT_TUNNEL_APPS = "net.tunmux.extra.SPLIT_TUNNEL_APPS"
        const val EXTRA_SPLIT_TUNNEL_ONLY_ALLOW_SELECTED = "net.tunmux.extra.SPLIT_TUNNEL_ONLY_ALLOW_SELECTED"
        private const val NOTIF_ID = 1
        private const val TAG = "tunmux"

        init {
            System.loadLibrary("tunmux_android")
        }
    }

    private var activeTunPfd: ParcelFileDescriptor? = null
    private var appMode: String = "vpn"
    private var splitTunnelApps: Set<String> = emptySet()
    private var splitTunnelOnlyAllowSelected: Boolean = false
    private val notifChannelId by lazy { getString(R.string.vpn_channel_id) }
    private val networkMonitor by lazy { AndroidNetworkMonitor(this) }
    private var networkMonitorJob: Job? = null
    private var tunnelStartedByService: Boolean = false

    // Called from Rust via JNI
    fun openTun(addresses: List<String>, routes: List<String>, dnsServers: List<String>, mtu: Int): Int {
        return try {
            Log.i(TAG, "openTun addresses=${addresses.size} routes=${routes.size} dns=${dnsServers.size} mtu=$mtu")
            activeTunPfd?.close()
            val builder = Builder()
                .setMtu(mtu)
                .setBlocking(false)
            for (addr in addresses) {
                val parts = addr.split("/")
                if (parts.size == 2) {
                    builder.addAddress(parts[0], parts[1].toInt())
                }
            }
            for (route in routes) {
                val parts = route.split("/")
                if (parts.size == 2) {
                    builder.addRoute(parts[0], parts[1].toInt())
                }
            }
            for (dns in dnsServers) {
                builder.addDnsServer(dns)
            }
            applyAppMode(builder)
            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "openTun establish returned null")
                -1
            } else {
                activeTunPfd = pfd
                pfd.detachFd()
            }
        } catch (e: Exception) {
            Log.e(TAG, "openTun failed", e)
            -1
        }
    }

    private fun applyAppMode(builder: Builder) {
        if (!appMode.equals("split", ignoreCase = true)) return
        if (splitTunnelApps.isEmpty()) return
        var applied = 0
        for (packageName in splitTunnelApps) {
            try {
                if (splitTunnelOnlyAllowSelected) {
                    builder.addAllowedApplication(packageName)
                } else {
                    builder.addDisallowedApplication(packageName)
                }
                applied += 1
            } catch (_: Exception) {
                // Ignore stale/uninstalled app entries.
            }
        }
        if (applied > 0) {
            Log.i(
                TAG,
                "split-tunnel enabled mode=${if (splitTunnelOnlyAllowSelected) "allow-selected" else "exclude-selected"} apps=$applied",
            )
        }
    }

    // Called from Rust via JNI
    fun bypass(fd: Int): Boolean = protect(fd)

    // Called from Rust via JNI
    fun closeTun() {
        activeTunPfd?.close()
        activeTunPfd = null
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        nativeInitialize(this, filesDir.absolutePath)
        startConnectivityListener()
    }

    override fun onDestroy() {
        networkMonitorJob?.cancel()
        networkMonitor.stop()
        nativeShutdown()
        activeTunPfd?.close()
        activeTunPfd = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification(getString(R.string.tunnel_running)))
        when (intent?.action) {
            ACTION_CONNECT -> {
                val provider = intent.getStringExtra(EXTRA_PROVIDER) ?: return START_STICKY
                val serverJson = intent.getStringExtra(EXTRA_SERVER_JSON) ?: "{}"
                appMode = intent.getStringExtra(EXTRA_APP_MODE) ?: "vpn"
                splitTunnelApps = intent.getStringArrayListExtra(EXTRA_SPLIT_TUNNEL_APPS)?.toSet()
                    ?: emptySet()
                splitTunnelOnlyAllowSelected = intent.getBooleanExtra(
                    EXTRA_SPLIT_TUNNEL_ONLY_ALLOW_SELECTED,
                    false,
                )
                nativeConnect(provider, serverJson)
                tunnelStartedByService = true
            }
            ACTION_DISCONNECT -> {
                nativeDisconnect()
                tunnelStartedByService = false
                stopSelf()
            }
        }
        return START_STICKY
    }

    @OptIn(FlowPreview::class)
    private fun startConnectivityListener() {
        val auto = AppConfigStore.load(this).auto
        networkMonitor.start(auto.wifiDetectionMethod)
        networkMonitorJob?.cancel()
        networkMonitorJob = lifecycleScope.launch {
            networkMonitor.state
                .debounce(300)
                .collectLatest { snapshot ->
                    if (!tunnelStartedByService) return@collectLatest
                    val latestAuto = AppConfigStore.load(this@TunmuxVpnService).auto
                    if (!latestAuto.enabled) return@collectLatest
                    networkMonitor.updateDetectionMethod(latestAuto.wifiDetectionMethod)

                    val shouldTunnel = shouldTunnel(latestAuto, snapshot.profile, snapshot.wifiSsid)
                    if (!shouldTunnel) {
                        Log.i(
                            TAG,
                            "service auto-tunnel disconnect profile=${snapshot.profile} ssid=${snapshot.wifiSsid}",
                        )
                        nativeDisconnect()
                        tunnelStartedByService = false
                        stopSelf()
                    }
                }
        }
    }

    private fun shouldTunnel(auto: AutoTunnelConfig, profile: NetworkProfile, ssid: String): Boolean {
        return when (profile) {
            NetworkProfile.Wifi -> shouldTunnelOnWifi(auto, ssid)
            NetworkProfile.Mobile -> auto.onMobile
            NetworkProfile.Ethernet -> auto.onEthernet
            NetworkProfile.None -> !auto.stopOnNoInternet
            NetworkProfile.Other -> false
        }
    }

    private fun shouldTunnelOnWifi(auto: AutoTunnelConfig, ssid: String): Boolean {
        if (!auto.onWifi) return false
        if (auto.wifiSsids.isEmpty()) return true
        val matched = ssid.isNotBlank() && auto.wifiSsids.any { it.equals(ssid, ignoreCase = true) }
        return if (auto.disconnectOnMatchedWifi) !matched else matched
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            notifChannelId,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        channel.description = getString(R.string.vpn_channel_description)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification =
        Notification.Builder(this, notifChannelId)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .build()

    private external fun nativeInitialize(service: TunmuxVpnService, filesDir: String)
    private external fun nativeShutdown()
    private external fun nativeConnect(provider: String, serverJson: String): Boolean
    private external fun nativeDisconnect()
}

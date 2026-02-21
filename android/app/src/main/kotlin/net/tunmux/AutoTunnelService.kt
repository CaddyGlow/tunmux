package net.tunmux

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.getSystemService
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import net.tunmux.model.AndroidNetworkMonitor
import net.tunmux.model.AppConfigStore
import net.tunmux.model.AutoRuntimeStore
import net.tunmux.model.shouldTunnelOnNetwork
import org.json.JSONObject

class AutoTunnelService : LifecycleService() {
    companion object {
        const val ACTION_START = "net.tunmux.action.AUTOTUNNEL_START"
        const val ACTION_STOP = "net.tunmux.action.AUTOTUNNEL_STOP"
        const val ACTION_REFRESH = "net.tunmux.action.AUTOTUNNEL_REFRESH"

        private const val TAG = "tunmux"
        private const val NOTIF_ID = 2
    }

    private val monitor by lazy { AndroidNetworkMonitor(this) }
    private var monitorJob: Job? = null
    private var evaluateJob: Job? = null
    private val notifChannelId by lazy { getString(R.string.auto_tunnel_channel_id) }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopMonitor()
                stopForeground(Service.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START,
            ACTION_REFRESH,
            null -> {
                startForeground(NOTIF_ID, buildNotification(getString(R.string.auto_tunnel_running)))
                startMonitor()
                scheduleEvaluate("service-start")
            }
            else -> Unit
        }
        return START_STICKY
    }

    override fun onDestroy() {
        evaluateJob?.cancel()
        stopMonitor()
        super.onDestroy()
    }

    private fun startMonitor() {
        val auto = AppConfigStore.load(this).auto
        if (!auto.enabled) {
            stopSelf()
            return
        }
        monitor.start(auto.wifiDetectionMethod)
        if (monitorJob != null) return
        monitorJob =
            lifecycleScope.launch {
                monitor.state.collectLatest {
                    scheduleEvaluate("network-changed")
                }
            }
    }

    private fun stopMonitor() {
        monitorJob?.cancel()
        monitorJob = null
        monitor.stop()
    }

    private fun scheduleEvaluate(reason: String) {
        evaluateJob?.cancel()
        evaluateJob =
            lifecycleScope.launch {
                val auto = AppConfigStore.load(this@AutoTunnelService).auto
                val debounceMs = auto.debounceDelaySeconds.coerceIn(0, 60) * 1000L
                if (debounceMs > 0) delay(debounceMs)
                evaluate(reason)
            }
    }

    private fun evaluate(reason: String) {
        val config = AppConfigStore.load(this)
        val auto = config.auto
        if (!auto.enabled) {
            stopSelf()
            return
        }

        if (VpnService.prepare(this) != null) {
            Log.w(TAG, "auto-tunnel skipped: vpn permission missing")
            return
        }

        val runtime = AutoRuntimeStore.load(this)
        if (runtime.provider.isBlank() || runtime.server.isBlank()) {
            Log.i(TAG, "auto-tunnel skipped: missing provider/server")
            return
        }

        monitor.updateDetectionMethod(auto.wifiDetectionMethod)
        val snapshot = monitor.state.value
        val shouldTunnel = shouldTunnelOnNetwork(auto, snapshot.profile, snapshot.wifiSsid)
        val status = currentConnectionState()

        if (shouldTunnel && status != "connected") {
            Log.i(
                TAG,
                "auto-tunnel connect reason=$reason profile=${snapshot.profile} ssid=${snapshot.wifiSsid}",
            )
            val connectIntent = Intent(this, TunmuxVpnService::class.java).apply {
                action = TunmuxVpnService.ACTION_CONNECT
                putExtra(TunmuxVpnService.EXTRA_PROVIDER, runtime.provider)
                putExtra(TunmuxVpnService.EXTRA_SERVER_JSON, runtime.server)
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
            startService(connectIntent)
            return
        }

        val shouldDisconnect =
            !shouldTunnel &&
                (status == "connected" || (status == "connecting" && auto.stopOnNoInternet))

        if (shouldDisconnect) {
            Log.i(
                TAG,
                "auto-tunnel disconnect reason=$reason profile=${snapshot.profile} ssid=${snapshot.wifiSsid}",
            )
            startService(
                Intent(this, TunmuxVpnService::class.java).apply {
                    action = TunmuxVpnService.ACTION_DISCONNECT
                }
            )
        }
    }

    private fun currentConnectionState(): String {
        return try {
            JSONObject(RustBridge.getConnectionStatus()).optString("state", "disconnected")
        } catch (_: Throwable) {
            "disconnected"
        }
    }

    private fun createNotificationChannel() {
        val channel =
            NotificationChannel(
                notifChannelId,
                getString(R.string.auto_tunnel_channel_name),
                NotificationManager.IMPORTANCE_MIN,
            )
        channel.description = getString(R.string.auto_tunnel_channel_description)
        getSystemService<NotificationManager>()?.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        return Notification.Builder(this, notifChannelId)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .build()
    }
}

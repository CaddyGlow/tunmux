package net.tunmux

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import net.tunmux.model.AppConfigStore
import net.tunmux.model.AutoRuntimeStore

class BootCompletedReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "tunmux"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val bootAction = intent?.action ?: return
        if (bootAction != Intent.ACTION_BOOT_COMPLETED && bootAction != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        val config = AppConfigStore.load(context)
        val auto = config.auto
        if (!auto.enabled || !auto.startOnBoot) return

        val runtime = AutoRuntimeStore.load(context)
        if (runtime.provider.isBlank() || runtime.server.isBlank()) {
            Log.i(TAG, "boot auto-tunnel skipped: missing provider/server")
            return
        }
        if (!shouldTunnelNow(context, auto.onWifi, auto.onMobile, auto.onEthernet)) {
            Log.i(TAG, "boot auto-tunnel skipped: current network not selected")
            return
        }

        if (VpnService.prepare(context) != null) {
            Log.w(TAG, "boot auto-tunnel skipped: VPN permission not granted yet")
            return
        }

        val serviceIntent = Intent(context, TunmuxVpnService::class.java).apply {
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
        context.startService(serviceIntent)
        Log.i(TAG, "boot auto-tunnel start requested provider=${runtime.provider}")
    }

    private fun shouldTunnelNow(
        context: Context,
        onWifi: Boolean,
        onMobile: Boolean,
        onEthernet: Boolean,
    ): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> onWifi
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> onMobile
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> onEthernet
            else -> false
        }
    }
}

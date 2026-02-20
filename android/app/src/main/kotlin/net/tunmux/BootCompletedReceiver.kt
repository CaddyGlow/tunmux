package net.tunmux

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiInfo
import android.os.Build
import android.util.Log
import net.tunmux.model.AppConfigStore
import net.tunmux.model.AutoTunnelConfig
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
        if (!shouldTunnelNow(context, auto)) {
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
        auto: AutoTunnelConfig,
    ): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> shouldTunnelOnWifi(auto, caps)
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> auto.onMobile
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> auto.onEthernet
            else -> false
        }
    }

    private fun shouldTunnelOnWifi(auto: AutoTunnelConfig, caps: NetworkCapabilities): Boolean {
        if (!auto.onWifi) return false
        if (auto.wifiSsids.isEmpty()) return true
        val ssid = readWifiSsid(caps)
        val matched = ssid.isNotBlank() && auto.wifiSsids.any { it.equals(ssid, ignoreCase = true) }
        return if (auto.disconnectOnMatchedWifi) !matched else matched
    }

    private fun readWifiSsid(caps: NetworkCapabilities): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return ""
        val info = caps.transportInfo as? WifiInfo ?: return ""
        return normalizeSsid(info.ssid)
    }

    private fun normalizeSsid(value: String?): String {
        val trimmed = value?.trim().orEmpty().removePrefix("\"").removeSuffix("\"")
        if (trimmed.equals("<unknown ssid>", ignoreCase = true)) return ""
        return trimmed
    }
}

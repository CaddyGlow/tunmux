package net.tunmux

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import net.tunmux.model.AppConfigStore

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

        val serviceIntent = Intent(context, AutoTunnelService::class.java).apply {
            action = AutoTunnelService.ACTION_START
        }
        context.startForegroundService(serviceIntent)
        Log.i(TAG, "boot auto-tunnel monitor start requested")
    }
}

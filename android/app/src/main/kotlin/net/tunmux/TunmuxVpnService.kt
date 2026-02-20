package net.tunmux

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class TunmuxVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "net.tunmux.action.CONNECT"
        const val ACTION_DISCONNECT = "net.tunmux.action.DISCONNECT"
        const val EXTRA_PROVIDER = "net.tunmux.extra.PROVIDER"
        const val EXTRA_SERVER_JSON = "net.tunmux.extra.SERVER_JSON"
        private const val NOTIF_CHANNEL_ID = "tunmux_vpn"
        private const val NOTIF_ID = 1
        private const val TAG = "tunmux"

        init {
            System.loadLibrary("tunmux_android")
        }
    }

    private var activeTunPfd: ParcelFileDescriptor? = null

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
    }

    override fun onDestroy() {
        nativeShutdown()
        activeTunPfd?.close()
        activeTunPfd = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification("tunmux VPN"))
        when (intent?.action) {
            ACTION_CONNECT -> {
                val provider = intent.getStringExtra(EXTRA_PROVIDER) ?: return START_STICKY
                val serverJson = intent.getStringExtra(EXTRA_SERVER_JSON) ?: "{}"
                nativeConnect(provider, serverJson)
            }
            ACTION_DISCONNECT -> {
                nativeDisconnect()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIF_CHANNEL_ID,
            "VPN Status",
            NotificationManager.IMPORTANCE_LOW
        )
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification =
        Notification.Builder(this, NOTIF_CHANNEL_ID)
            .setContentTitle("tunmux")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .build()

    private external fun nativeInitialize(service: TunmuxVpnService, filesDir: String)
    private external fun nativeShutdown()
    private external fun nativeConnect(provider: String, serverJson: String): Boolean
    private external fun nativeDisconnect()
}

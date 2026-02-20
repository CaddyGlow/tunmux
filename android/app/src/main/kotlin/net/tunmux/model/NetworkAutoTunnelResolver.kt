package net.tunmux.model

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

enum class NetworkProfile {
    None,
    Wifi,
    Mobile,
    Ethernet,
    Other,
}

data class NetworkSnapshot(
    val profile: NetworkProfile,
    val wifiSsid: String = "",
    val locationPermissionGranted: Boolean,
    val locationServicesEnabled: Boolean,
)

private const val UNKNOWN_SSID = "<unknown ssid>"

fun normalizeSsid(value: String?): String {
    val trimmed = value?.trim().orEmpty().removePrefix("\"").removeSuffix("\"")
    if (trimmed.equals(UNKNOWN_SSID, ignoreCase = true)) return ""
    return trimmed
}

fun hasRequiredLocationPermissions(context: Context): Boolean {
    val fineLocationGranted =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
    val coarseLocationGranted =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
    return fineLocationGranted || coarseLocationGranted
}

fun isLocationServicesEnabled(context: Context): Boolean {
    val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
    return try {
        val gpsEnabled = locationManager?.isProviderEnabled(LocationManager.GPS_PROVIDER) ?: false
        val networkEnabled =
            locationManager?.isProviderEnabled(LocationManager.NETWORK_PROVIDER) ?: false
        gpsEnabled || networkEnabled
    } catch (_: Throwable) {
        false
    }
}

fun resolveNetworkSnapshot(context: Context, detectionMethod: WifiDetectionMethod): NetworkSnapshot {
    val cm = context.getSystemService(ConnectivityManager::class.java)
    val wifiManager = context.applicationContext.getSystemService(WifiManager::class.java)

    val locationPermissionGranted = hasRequiredLocationPermissions(context)
    val locationServicesEnabled = isLocationServicesEnabled(context)

    val activeNetwork = cm?.activeNetwork
    val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }

    val profile =
        when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> NetworkProfile.Wifi
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> NetworkProfile.Mobile
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> NetworkProfile.Ethernet
            caps == null -> NetworkProfile.None
            else -> NetworkProfile.Other
        }

    val wifiSsid =
        if (profile == NetworkProfile.Wifi) {
            readWifiSsid(
                caps = caps,
                wifiManager = wifiManager,
                detectionMethod = detectionMethod,
            )
        } else {
            ""
        }

    return NetworkSnapshot(
        profile = profile,
        wifiSsid = wifiSsid,
        locationPermissionGranted = locationPermissionGranted,
        locationServicesEnabled = locationServicesEnabled,
    )
}

private fun readWifiSsid(
    caps: NetworkCapabilities?,
    wifiManager: WifiManager?,
    detectionMethod: WifiDetectionMethod,
): String {
    val fromTransportInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && detectionMethod == WifiDetectionMethod.DEFAULT) {
            normalizeSsid((caps?.transportInfo as? WifiInfo)?.ssid)
        } else {
            ""
        }

    if (fromTransportInfo.isNotBlank()) return fromTransportInfo

    @Suppress("DEPRECATION")
    return normalizeSsid(wifiManager?.connectionInfo?.ssid)
}

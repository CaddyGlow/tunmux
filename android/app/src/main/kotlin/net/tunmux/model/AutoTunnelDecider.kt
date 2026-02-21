package net.tunmux.model

fun shouldTunnelOnNetwork(
    auto: AutoTunnelConfig,
    profile: NetworkProfile,
    wifiSsid: String,
): Boolean {
    return when (profile) {
        NetworkProfile.Wifi -> shouldTunnelOnWifi(auto, wifiSsid)
        NetworkProfile.Mobile -> auto.onMobile
        NetworkProfile.Ethernet -> auto.onEthernet
        NetworkProfile.None -> false
        NetworkProfile.Other -> false
    }
}

fun shouldTunnelOnWifi(auto: AutoTunnelConfig, ssid: String): Boolean {
    if (!auto.onWifi) return false
    if (auto.wifiSsids.isEmpty()) return true
    val matched = ssid.isNotBlank() && auto.wifiSsids.any { it.equals(ssid, ignoreCase = true) }
    return if (auto.disconnectOnMatchedWifi) !matched else matched
}

package net.tunmux

object RustBridge {
    init {
        System.loadLibrary("tunmux_android")
    }

    external fun login(provider: String, credential: String): String
    external fun logout(provider: String)
    external fun fetchServers(provider: String): String
    external fun airvpnListKeys(): String
    external fun airvpnSelectKey(keyName: String): String
    external fun airvpnListDevices(): String
    external fun airvpnAddDevice(name: String): String
    external fun airvpnRenameDevice(device: String, name: String): String
    external fun airvpnDeleteDevice(device: String): String
    external fun getConnectionStatus(): String
    external fun createAccount(provider: String): String
    external fun startLocalProxy(provider: String, serverJson: String, socksPort: Int, httpPort: Int): String
    external fun stopLocalProxy(): String
}

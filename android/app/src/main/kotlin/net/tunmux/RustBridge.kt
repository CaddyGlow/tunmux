package net.tunmux

object RustBridge {
    init {
        System.loadLibrary("tunmux_android")
    }

    external fun login(provider: String, credential: String): String
    external fun logout(provider: String)
    external fun fetchServers(provider: String): String
    external fun getConnectionStatus(): String
}

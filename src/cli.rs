use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tunmux", about = "Multi-provider VPN CLI", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopCommand,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum TopCommand {
    /// Proton VPN commands
    Proton {
        #[command(subcommand)]
        command: ProtonCommand,
    },

    /// AirVPN commands
    Airvpn {
        #[command(subcommand)]
        command: AirVpnCommand,
    },

    /// Show active VPN connections and proxy instances
    Status,

    /// Internal: proxy daemon process (hidden)
    #[command(hide = true)]
    ProxyDaemon {
        #[arg(long)]
        netns: String,
        #[arg(long)]
        socks_port: u16,
        #[arg(long)]
        http_port: u16,
        #[arg(long)]
        pid_file: String,
        #[arg(long)]
        log_file: String,
    },
}

#[derive(Subcommand)]
pub enum ProtonCommand {
    /// Sign in with Proton VPN credentials
    Login {
        /// Proton account username
        username: String,
    },

    /// Sign out and remove credentials
    Logout,

    /// Display account information
    Info,

    /// List available VPN servers
    Servers {
        /// Filter by country code (e.g., US, CH, JP)
        #[arg(short, long)]
        country: Option<String>,

        /// Show only free servers
        #[arg(short, long)]
        free: bool,
    },

    /// Connect to a VPN server
    Connect {
        /// Server name (e.g., US#1, CH#5)
        server: Option<String>,

        /// Connect to a server in this country
        #[arg(short, long)]
        country: Option<String>,

        /// Prefer P2P-capable servers
        #[arg(long)]
        p2p: bool,

        /// WireGuard backend: auto, wg-quick, kernel
        #[arg(long)]
        backend: Option<String>,

        /// Start a SOCKS5/HTTP proxy (VPN traffic isolated in network namespace)
        #[arg(long)]
        proxy: bool,

        /// SOCKS5 proxy port (default: auto-assign from 1080)
        #[arg(long)]
        socks_port: Option<u16>,

        /// HTTP proxy port (default: auto-assign from 8118)
        #[arg(long)]
        http_port: Option<u16>,
    },

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum AirVpnCommand {
    /// Sign in with AirVPN credentials
    Login {
        /// AirVPN username
        username: String,
    },

    /// Sign out and remove credentials
    Logout,

    /// Display account information
    Info,

    /// List available VPN servers
    Servers {
        /// Filter by country code (e.g., US, CH, JP)
        #[arg(short, long)]
        country: Option<String>,
    },

    /// Connect to a VPN server
    Connect {
        /// Server name (e.g., Castor, Vega)
        server: Option<String>,

        /// Connect to a server in this country
        #[arg(short, long)]
        country: Option<String>,

        /// WireGuard key name (see `airvpn info` for available keys)
        #[arg(short, long)]
        key: Option<String>,

        /// WireGuard backend: auto, wg-quick, kernel
        #[arg(long)]
        backend: Option<String>,

        /// Start a SOCKS5/HTTP proxy (VPN traffic isolated in network namespace)
        #[arg(long)]
        proxy: bool,

        /// SOCKS5 proxy port (default: auto-assign from 1080)
        #[arg(long)]
        socks_port: Option<u16>,

        /// HTTP proxy port (default: auto-assign from 8118)
        #[arg(long)]
        http_port: Option<u16>,
    },

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(long)]
        all: bool,
    },

    /// Show active VPN sessions
    Sessions,

    /// Generate a config file via the AirVPN API
    Generate {
        /// Server name or country code (repeatable, e.g., -s be -s nl)
        #[arg(short, long, required = true)]
        server: Vec<String>,

        /// Protocol (repeatable). Options:
        ///   wg-1637 (default), wg-47107, wg-51820,
        ///   openvpn-udp-443, openvpn-udp-80, openvpn-udp-53, openvpn-udp-1194,
        ///   openvpn-tcp-443, openvpn-tcp-80,
        ///   openvpn-ssh-22, openvpn-ssl-443.
        /// Raw format also accepted: wireguard_3_udp_PORT, openvpn_1_tcp_PORT
        #[arg(short, long, verbatim_doc_comment)]
        protocol: Vec<String>,

        /// Device/key name (default: first device)
        #[arg(short, long)]
        device: Option<String>,

        /// Entry IP layer: ipv4, ipv6
        #[arg(long, default_value = "ipv4")]
        entry: String,

        /// Exit IP layer: both, ipv4, ipv6
        #[arg(long, default_value = "both")]
        exit: String,

        /// WireGuard MTU
        #[arg(long, default_value = "1320")]
        mtu: u16,

        /// WireGuard persistent keepalive (seconds)
        #[arg(long, default_value = "15")]
        keepalive: u16,

        /// Output file (default: stdout for single combo)
        #[arg(short, long)]
        output: Option<String>,

        /// Archive format when multiple files: zip, 7z, tar, tar.gz, tar.bz2, tar.xz
        #[arg(short, long, default_value = "zip")]
        format: String,
    },

    /// Manage forwarded ports
    Ports {
        #[command(subcommand)]
        action: PortAction,
    },

    /// Manage devices (WireGuard keys)
    Devices {
        #[command(subcommand)]
        action: DeviceAction,
    },

    /// Manage API keys
    #[command(visible_alias = "api")]
    ApiKeys {
        #[command(subcommand)]
        action: ApiKeyAction,
    },
}

#[derive(Subcommand)]
pub enum PortAction {
    /// List forwarded ports
    List,

    /// Add a port forward
    Add {
        /// Port number to forward (0 = auto-assign)
        port: u16,

        /// Protocol: tcp, udp, or both
        #[arg(short, long, default_value = "both")]
        protocol: String,

        /// Local port to map to (default: same as remote port)
        #[arg(short, long)]
        local: Option<u16>,

        /// DDNS name (e.g., myhost -- becomes myhost.airdns.org)
        #[arg(short, long)]
        ddns: Option<String>,
    },

    /// Remove a port forward
    Remove {
        /// Port number to remove
        port: u16,
    },

    /// Show active sessions for a forwarded port
    Info {
        /// Port number to inspect
        port: u16,
    },

    /// Test if a forwarded port is reachable
    Check {
        /// Port number to test
        port: u16,
    },

    /// Edit settings on an existing forwarded port
    #[command(visible_alias = "edit")]
    Set {
        /// Port number to edit
        port: u16,

        /// Protocol: tcp, udp, or both
        #[arg(short, long)]
        protocol: Option<String>,

        /// Local port to map to
        #[arg(short, long)]
        local: Option<u16>,

        /// DDNS name (e.g., myhost -- becomes myhost.airdns.org)
        #[arg(short, long)]
        ddns: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DeviceAction {
    /// List all devices (WireGuard keys)
    List,

    /// Add a new device
    Add {
        /// Name for the new device
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Rename a device
    Rename {
        /// Current device name
        device: String,

        /// New name
        name: String,
    },

    /// Delete a device
    Delete {
        /// Device name
        device: String,
    },
}

#[derive(Subcommand)]
pub enum ApiKeyAction {
    /// List API keys
    List,

    /// Generate a new API key
    Add {
        /// Name for the new key
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Rename an API key
    Rename {
        /// Current key name
        key: String,

        /// New name
        name: String,
    },

    /// Delete an API key
    Delete {
        /// Key name
        key: String,
    },
}

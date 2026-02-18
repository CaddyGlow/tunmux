use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vpncli", about = "Multi-provider VPN CLI", version)]
pub struct Cli {
    #[command(subcommand)]
    pub provider: ProviderCommand,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum ProviderCommand {
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
        #[arg(long, default_value = "auto")]
        backend: String,
    },

    /// Disconnect from VPN
    Disconnect,
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
        #[arg(long, default_value = "auto")]
        backend: String,
    },

    /// Disconnect from VPN
    Disconnect,

    /// Show active VPN sessions
    Sessions,

    /// Generate a WireGuard config file via the AirVPN API
    Generate {
        /// Server name or country code (repeatable, e.g., -s be -s nl)
        #[arg(short, long, required = true)]
        server: Vec<String>,

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

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
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

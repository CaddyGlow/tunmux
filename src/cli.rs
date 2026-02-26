use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "tunmux",
    about = "Multi-provider VPN CLI",
    version = env!("TUNMUX_BUILD_VERSION")
)]
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

    /// Mullvad VPN commands
    Mullvad {
        #[command(subcommand)]
        command: MullvadCommand,
    },

    /// IVPN commands
    Ivpn {
        #[command(subcommand)]
        command: IvpnCommand,
    },

    /// WireGuard config file/profile commands
    Wgconf {
        #[command(subcommand)]
        command: WgconfCommand,
    },

    /// Connect to a VPN server (`tunmux connect <provider> ...`)
    Connect {
        #[command(subcommand)]
        provider: ConnectProviderCommand,
    },

    /// Disconnect VPN connection(s)
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`)
        instance: Option<String>,

        /// Provider to scope disconnect operations
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Disconnect all active connections (all providers unless --provider is set)
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },

    /// Show active VPN connections and proxy instances
    Status,

    /// Show WireGuard tunnel state for active direct connection(s)
    Wg,

    /// Hook utilities
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },

    /// Internal: proxy daemon process (hidden)
    #[command(hide = true)]
    ProxyDaemon {
        #[arg(long)]
        netns: String,
        #[arg(long)]
        interface: String,
        #[arg(long)]
        socks_port: u16,
        #[arg(long)]
        http_port: u16,
        #[arg(long)]
        proxy_access_log: bool,
        #[arg(long)]
        pid_file: String,
        #[arg(long)]
        log_file: String,
        #[arg(long)]
        startup_status_file: String,
    },

    /// Internal: userspace WireGuard local-proxy daemon (hidden)
    #[command(hide = true)]
    LocalProxyDaemon {
        #[arg(long)]
        socks_port: u16,
        #[arg(long)]
        http_port: u16,
        #[arg(long)]
        proxy_access_log: bool,
        #[arg(long)]
        pid_file: String,
        #[arg(long)]
        log_file: String,
        /// base64(JSON(LocalProxyConfig))
        #[arg(long)]
        config_b64: String,
    },

    /// Internal privileged service mode (hidden)
    #[command(hide = true)]
    Privileged {
        #[arg(long)]
        serve: bool,

        /// Use stdin/stdout request transport instead of Unix socket.
        #[arg(long, hide = true)]
        stdio: bool,

        /// Optional group name for privileged socket authorization.
        #[arg(long)]
        authorized_group: Option<String>,

        /// Exit after this many idle milliseconds without requests.
        #[arg(long)]
        idle_timeout_ms: Option<u64>,

        /// Internal marker: daemon was launched by client autostart logic.
        #[arg(long, hide = true)]
        autostarted: bool,
    },
}

#[derive(Subcommand)]
pub enum HookCommand {
    /// Run a predefined hook check now
    Run {
        /// Builtin hook entry
        #[arg(value_enum)]
        builtin: HookBuiltinArg,
    },

    /// Print the hook environment payload for an active instance
    Debug {
        /// Instance name (from `tunmux status`)
        instance: Option<String>,

        /// Provider to scope instance selection when `instance` is omitted
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Hook event payload to print
        #[arg(long, value_enum, default_value = "ifup")]
        event: HookEventArg,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookEventArg {
    Ifup,
    Ifdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookBuiltinArg {
    Connectivity,
    ExternalIp,
    DnsDetection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProviderArg {
    Proton,
    Airvpn,
    Mullvad,
    Ivpn,
    Wgconf,
}

#[derive(Subcommand)]
pub enum ConnectProviderCommand {
    /// Connect using Proton VPN
    Proton(ProtonConnectArgs),

    /// Connect using AirVPN
    Airvpn(AirVpnConnectArgs),

    /// Connect using Mullvad VPN
    Mullvad(MullvadConnectArgs),

    /// Connect using IVPN
    Ivpn(IvpnConnectArgs),

    /// Connect using a WireGuard config file/profile
    Wgconf(WgconfConnectArgs),
}

#[derive(Args, Clone)]
pub struct ProtonConnectArgs {
    /// Server name (e.g., US#1, CH#5)
    pub server: Option<String>,

    /// Connect to a server in this country
    #[arg(short, long)]
    pub country: Option<String>,

    /// Prefer P2P-capable servers
    #[arg(long)]
    pub p2p: bool,

    /// Server selection order when auto-selecting
    #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
    pub sort: String,

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long)]
    pub proxy: bool,

    /// Start a userspace SOCKS5/HTTP proxy without root or VpnService
    #[arg(long)]
    pub local_proxy: bool,

    /// Disable host IPv6 egress while connected (direct kernel mode, IPv4-only profile)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct mode)
    #[arg(long)]
    pub mtu: Option<u16>,

    /// SOCKS5 proxy port (default: auto-assign from 1080)
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// HTTP proxy port (default: auto-assign from 8118)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Enable proxy access logging to the instance log file
    #[arg(long)]
    pub proxy_access_log: bool,
}

#[derive(Args, Clone)]
pub struct AirVpnConnectArgs {
    /// Server name (e.g., Castor, Vega)
    pub server: Option<String>,

    /// Connect to a server in this country
    #[arg(short, long)]
    pub country: Option<String>,

    /// WireGuard key name (see `airvpn info` for available keys)
    #[arg(short, long)]
    pub key: Option<String>,

    /// Server selection order when auto-selecting
    #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
    pub sort: String,

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long)]
    pub proxy: bool,

    /// Start a userspace SOCKS5/HTTP proxy without root or VpnService
    #[arg(long)]
    pub local_proxy: bool,

    /// Disable host IPv6 egress while connected (direct kernel mode, IPv4-only profile)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct mode)
    #[arg(long)]
    pub mtu: Option<u16>,

    /// SOCKS5 proxy port (default: auto-assign from 1080)
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// HTTP proxy port (default: auto-assign from 8118)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Enable proxy access logging to the instance log file
    #[arg(long)]
    pub proxy_access_log: bool,
}

#[derive(Args, Clone)]
pub struct MullvadConnectArgs {
    /// Server hostname (e.g., us-nyc-wg-401)
    pub server: Option<String>,

    /// Connect to a server in this country
    #[arg(short, long)]
    pub country: Option<String>,

    /// Server selection order when auto-selecting
    #[arg(short = 's', long, default_value = "name", value_parser = ["name", "latency"])]
    pub sort: String,

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long)]
    pub proxy: bool,

    /// Start a userspace SOCKS5/HTTP proxy without root or VpnService
    #[arg(long)]
    pub local_proxy: bool,

    /// Disable host IPv6 egress while connected (direct kernel mode, IPv4-only profile)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct mode)
    #[arg(long)]
    pub mtu: Option<u16>,

    /// SOCKS5 proxy port (default: auto-assign from 1080)
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// HTTP proxy port (default: auto-assign from 8118)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Enable proxy access logging to the instance log file
    #[arg(long)]
    pub proxy_access_log: bool,
}

#[derive(Args, Clone)]
pub struct IvpnConnectArgs {
    /// Server hostname or gateway (e.g., us-ny4.wg.ivpn.net, us.wg.ivpn.net)
    pub server: Option<String>,

    /// Connect to a server in this country
    #[arg(short, long)]
    pub country: Option<String>,

    /// Server selection order when auto-selecting
    #[arg(short = 's', long, default_value = "load", value_parser = ["load", "name", "latency"])]
    pub sort: String,

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long)]
    pub proxy: bool,

    /// Start a userspace SOCKS5/HTTP proxy without root or VpnService
    #[arg(long)]
    pub local_proxy: bool,

    /// Disable host IPv6 egress while connected (direct kernel mode, IPv4-only profile)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct mode)
    #[arg(long)]
    pub mtu: Option<u16>,

    /// SOCKS5 proxy port (default: auto-assign from 1080)
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// HTTP proxy port (default: auto-assign from 8118)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Enable proxy access logging to the instance log file
    #[arg(long)]
    pub proxy_access_log: bool,
}

#[derive(Args, Clone)]
pub struct WgconfConnectArgs {
    /// WireGuard .conf file path
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub file: Option<String>,

    /// Saved profile name
    #[arg(long, required_unless_present = "file", conflicts_with = "file")]
    pub profile: Option<String>,

    /// Save loaded config as a reusable profile name
    #[arg(long)]
    pub save_as: Option<String>,

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long, conflicts_with = "local_proxy")]
    pub proxy: bool,

    /// Start a userspace SOCKS5/HTTP proxy without root or VpnService
    #[arg(long, conflicts_with = "proxy")]
    pub local_proxy: bool,

    /// Disable host IPv6 egress while connected (only valid for direct kernel mode with IPv4-only config)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct kernel mode)
    #[arg(long)]
    pub mtu: Option<u16>,
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

    /// Renew VPN certificate using saved session credentials
    Renew,

    /// List available VPN servers
    Servers {
        /// Filter by country code (e.g., US, CH, JP)
        #[arg(short, long)]
        country: Option<String>,

        /// Show only free servers
        #[arg(short, long)]
        free: bool,

        /// Filter by server feature tag (repeatable or comma-separated): secure-core, tor, p2p, streaming, ipv6
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Sort order for server listing
        #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(ProtonConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long)]
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

        /// Filter by keyword tag (repeatable or comma-separated)
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Sort order for server listing
        #[arg(short = 's', long, default_value = "name", value_parser = ["name", "score", "load", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(AirVpnConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long)]
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
pub enum MullvadCommand {
    /// Sign in with Mullvad account number
    Login {
        /// Mullvad account number
        account: String,

        /// Overwrite existing saved account ID without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Create a new Mullvad account and sign in
    CreateAccount {
        /// Output result as JSON
        #[arg(long)]
        json: bool,

        /// Overwrite existing saved account ID without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Payment-related commands
    Payment {
        #[command(subcommand)]
        action: MullvadPaymentCommand,
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

        /// Filter by keyword tag (repeatable or comma-separated)
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Sort order for server listing
        #[arg(short = 's', long, default_value = "name", value_parser = ["name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(MullvadConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum IvpnCommand {
    /// Sign in with IVPN account ID
    Login {
        /// IVPN account ID (for example: i-XXXX-XXXX-XXXX)
        account: String,

        /// Overwrite existing saved account ID without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Create a new IVPN account
    CreateAccount {
        /// Product: standard or pro
        #[arg(long, default_value = "standard", value_parser = ["standard", "pro"])]
        product: String,

        /// Overwrite existing saved account ID without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Payment-related commands
    Payment {
        #[command(subcommand)]
        action: IvpnPaymentCommand,
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

        /// Filter by keyword tag (repeatable or comma-separated)
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Sort order for server listing
        #[arg(short = 's', long, default_value = "load", value_parser = ["load", "name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(IvpnConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum WgconfCommand {
    /// Connect from a WireGuard config file or saved profile
    Connect(WgconfConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long)]
        all: bool,
    },

    /// Save a WireGuard config file as a named profile
    Save {
        /// WireGuard .conf file path
        #[arg(long)]
        file: String,

        /// Profile name
        #[arg(long)]
        name: String,
    },

    /// List saved profiles
    List,

    /// Remove a saved profile
    Remove {
        /// Profile name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum MullvadPaymentCommand {
    /// Fetch Mullvad Monero payment details from the web account flow
    Monero {
        /// Mullvad account number (defaults to saved session account)
        #[arg(long)]
        account: Option<String>,

        /// Output result as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum IvpnPaymentCommand {
    /// Fetch Monero payment details for an IVPN account
    Monero {
        /// IVPN account ID (for example: i-XXXX-XXXX-XXXX). If omitted, uses saved account ID.
        account: Option<String>,

        /// Billing duration: 7d, 1m, 1y
        #[arg(long, default_value = "1m", value_parser = ["7d", "1m", "1y"])]
        duration: String,
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

#[cfg(test)]
mod tests {
    use super::{
        AirVpnCommand, Cli, ConnectProviderCommand, HookBuiltinArg, HookCommand, ProtonCommand,
        ProviderArg, TopCommand, WgconfCommand,
    };
    use clap::Parser;

    #[test]
    fn parse_connect_wgconf_with_file() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/test.conf",
            "--backend",
            "userspace",
            "--disable-ipv6",
        ])
        .expect("parse connect wgconf file");

        match cli.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => assert!(args.disable_ipv6),
            other => panic!("unexpected command: {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn parse_connect_wgconf_with_profile() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--profile",
            "work",
            "--save-as",
            "saved-work",
        ])
        .expect("parse connect wgconf profile");

        match cli.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => {
                assert_eq!(args.profile.as_deref(), Some("work"));
                assert_eq!(args.save_as.as_deref(), Some("saved-work"));
            }
            _ => panic!("expected wgconf connect provider"),
        }
    }

    #[test]
    fn parse_connect_wgconf_requires_exactly_one_source() {
        let missing = Cli::try_parse_from(["tunmux", "connect", "wgconf"]);
        assert!(missing.is_err());

        let both = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/a.conf",
            "--profile",
            "a",
        ]);
        assert!(both.is_err());
    }

    #[test]
    fn parse_provider_prefixed_wgconf_commands() {
        let cli = Cli::try_parse_from(["tunmux", "wgconf", "connect", "--profile", "home"])
            .expect("parse wgconf connect");
        match cli.command {
            TopCommand::Wgconf {
                command: WgconfCommand::Connect(args),
            } => assert_eq!(args.profile.as_deref(), Some("home")),
            _ => panic!("expected wgconf connect command"),
        }

        let cli = Cli::try_parse_from(["tunmux", "disconnect", "--provider", "wgconf"])
            .expect("parse disconnect provider wgconf");
        match cli.command {
            TopCommand::Disconnect {
                provider: Some(ProviderArg::Wgconf),
                ..
            } => {}
            _ => panic!("expected disconnect provider wgconf"),
        }
    }

    #[test]
    fn parse_disable_ipv6_for_all_provider_connect_commands() {
        let proton = Cli::try_parse_from(["tunmux", "connect", "proton", "--disable-ipv6"])
            .expect("parse proton");
        match proton.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Proton(args),
            } => assert!(args.disable_ipv6),
            _ => panic!("expected proton connect provider"),
        }

        let airvpn = Cli::try_parse_from(["tunmux", "connect", "airvpn", "--disable-ipv6"])
            .expect("parse airvpn");
        match airvpn.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Airvpn(args),
            } => assert!(args.disable_ipv6),
            _ => panic!("expected airvpn connect provider"),
        }

        let mullvad = Cli::try_parse_from(["tunmux", "connect", "mullvad", "--disable-ipv6"])
            .expect("parse mullvad");
        match mullvad.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Mullvad(args),
            } => assert!(args.disable_ipv6),
            _ => panic!("expected mullvad connect provider"),
        }

        let ivpn = Cli::try_parse_from(["tunmux", "connect", "ivpn", "--disable-ipv6"])
            .expect("parse ivpn");
        match ivpn.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Ivpn(args),
            } => assert!(args.disable_ipv6),
            _ => panic!("expected ivpn connect provider"),
        }
    }

    #[test]
    fn parse_mtu_for_connect_commands() {
        let proton = Cli::try_parse_from(["tunmux", "connect", "proton", "--mtu", "1280"])
            .expect("parse proton mtu");
        match proton.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Proton(args),
            } => assert_eq!(args.mtu, Some(1280)),
            _ => panic!("expected proton connect provider"),
        }

        let wgconf = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/test.conf",
            "--backend",
            "kernel",
            "--mtu",
            "1360",
        ])
        .expect("parse wgconf mtu");
        match wgconf.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => assert_eq!(args.mtu, Some(1360)),
            _ => panic!("expected wgconf connect provider"),
        }
    }

    #[test]
    fn parse_proton_renew_command() {
        let cli = Cli::try_parse_from(["tunmux", "proton", "renew"]).expect("parse proton renew");
        match cli.command {
            TopCommand::Proton {
                command: ProtonCommand::Renew,
            } => {}
            _ => panic!("expected proton renew command"),
        }
    }

    #[test]
    fn parse_airvpn_connect_default_sort_score() {
        let cli = Cli::try_parse_from(["tunmux", "connect", "airvpn"]).expect("parse airvpn");
        match cli.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Airvpn(args),
            } => assert_eq!(args.sort, "score"),
            _ => panic!("expected airvpn connect provider"),
        }
    }

    #[test]
    fn parse_airvpn_servers_sort_score() {
        let cli = Cli::try_parse_from(["tunmux", "airvpn", "servers", "--sort", "score"])
            .expect("parse airvpn servers score");
        match cli.command {
            TopCommand::Airvpn {
                command: AirVpnCommand::Servers { sort, .. },
            } => assert_eq!(sort, "score"),
            _ => panic!("expected airvpn servers command"),
        }
    }

    #[test]
    fn parse_hook_debug_command() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "hook",
            "debug",
            "test-instance",
            "--event",
            "ifdown",
        ])
        .expect("parse hook debug");

        match cli.command {
            TopCommand::Hook {
                command:
                    HookCommand::Debug {
                        instance, provider, ..
                    },
            } => {
                assert_eq!(instance.as_deref(), Some("test-instance"));
                assert!(provider.is_none());
            }
            _ => panic!("expected hook debug command"),
        }
    }

    #[test]
    fn parse_hook_run_builtin_command() {
        let cli = Cli::try_parse_from(["tunmux", "hook", "run", "external-ip"])
            .expect("parse hook run builtin");

        match cli.command {
            TopCommand::Hook {
                command: HookCommand::Run { builtin },
            } => assert_eq!(builtin, HookBuiltinArg::ExternalIp),
            _ => panic!("expected hook run command"),
        }

        let cli = Cli::try_parse_from(["tunmux", "hook", "run", "dns-detection"])
            .expect("parse hook run dns-detection builtin");

        match cli.command {
            TopCommand::Hook {
                command: HookCommand::Run { builtin },
            } => assert_eq!(builtin, HookBuiltinArg::DnsDetection),
            _ => panic!("expected hook run command"),
        }
    }
}

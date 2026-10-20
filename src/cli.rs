use clap::{Args, Parser, Subcommand, ValueEnum};

/// Common connect options shared across VPN providers.
#[derive(Args, Clone, Debug)]
pub struct ConnectOptions {
    /// Succeed without reconnecting when this exact source is already active
    #[arg(long)]
    pub if_missing: bool,

    /// Bypass directly attached LAN networks (macOS helper direct mode only)
    #[arg(long)]
    pub allow_lan: bool,

    /// Select the WireGuard implementation for this connection
    ///
    /// Accepts kernel, userspace, or wg-quick. Overrides general.backend in config.toml; the
    /// platform default is kernel on Linux and userspace on macOS. Kernel mode uses native
    /// WireGuard, userspace uses the embedded helper, and wg-quick invokes the installed wg-quick
    /// tool. --proxy requires kernel mode.
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Expose the VPN through a Linux namespace SOCKS5/HTTP proxy
    ///
    /// Requires Linux, the proxy build feature, and the kernel backend. Routes proxy traffic
    /// through an isolated network namespace rather than changing the host default route.
    /// Mutually exclusive with --local-proxy.
    #[arg(long, conflicts_with = "local_proxy")]
    pub proxy: bool,

    /// Expose a rootless userspace SOCKS5/HTTP proxy
    ///
    /// Runs WireGuard inside the proxy process without a host tunnel interface, root privileges,
    /// or Android VpnService. Only applications configured to use the proxy send traffic through
    /// it. Mutually exclusive with --proxy.
    #[arg(long, conflicts_with = "proxy")]
    pub local_proxy: bool,

    /// Block host IPv6 egress during an IPv4-only direct kernel tunnel
    ///
    /// Valid only with the kernel backend, an IPv4-only profile, and neither proxy mode. Adds
    /// IPv6 blocking routes while connected and removes them on disconnect; it does not disable
    /// IPv6 globally or rewrite the profile.
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Override the WireGuard interface MTU in bytes
    ///
    /// Accepts 576 through 65535. Overrides the profile MTU; when omitted, the profile value or
    /// backend default applies. Used for direct tunnels and kernel namespace proxies. Rootless
    /// local-proxy mode has no host interface MTU to set.
    #[arg(long)]
    pub mtu: Option<u16>,

    /// Choose the local SOCKS5 listening port for proxy mode
    ///
    /// Applies with --proxy or --local-proxy. When omitted, selects an available port starting at
    /// 1080. Use tunmux status to find the assigned port; an explicit port must be available.
    #[arg(long)]
    pub socks_port: Option<u16>,

    /// Choose the local HTTP proxy listening port
    ///
    /// Applies with --proxy or --local-proxy. When omitted, selects an available port starting at
    /// 8118. Use tunmux status to find the assigned port; an explicit port must be available.
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Record proxy request activity in the instance log
    ///
    /// Applies to --proxy and --local-proxy instances. Enables access logging even when
    /// general.proxy_access_log is disabled. Logs are written to the instance log file.
    #[arg(long)]
    pub proxy_access_log: bool,
}

#[derive(Parser)]
#[command(
    name = "tunmux",
    about = "Multi-provider VPN CLI",
    version = env!("TUNMUX_BUILD_VERSION")
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopCommand,

    /// Enable debug-level tunmux logs; --debug is an alias
    ///
    /// The default is info-level tunmux logs and warnings from dependencies. Explicit RUST_LOG
    /// directives take precedence over this flag. For example: RUST_LOG=tunmux=debug,gotatun=warn
    /// tunmux status. Newly spawned services inherit the resolved filter; existing daemons keep
    /// their startup filter.
    #[arg(short, long, alias = "debug", global = true)]
    pub verbose: bool,

    /// Set explicit target-aware tracing directives for this process
    ///
    /// Overrides RUST_LOG and --verbose. Accepts directives such as tunmux=debug,gotatun=warn.
    /// The resolved filter is forwarded to newly spawned services; this internal option does not
    /// reconfigure an already running daemon.
    #[arg(long, global = true, hide = true)]
    pub log_filter: Option<String>,
}

#[derive(Subcommand)]
pub enum TopCommand {
    /// Install and manage the privileged service
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Manage opt-in desired connections
    Autoconnect {
        #[command(subcommand)]
        command: AutoconnectCommand,
    },
    /// Proton VPN commands
    #[cfg(feature = "proton")]
    Proton {
        #[command(subcommand)]
        command: ProtonCommand,
    },

    /// AirVPN commands
    #[cfg(feature = "airvpn")]
    Airvpn {
        #[command(subcommand)]
        command: AirVpnCommand,
    },

    /// Mullvad VPN commands
    #[cfg(feature = "mullvad")]
    Mullvad {
        #[command(subcommand)]
        command: MullvadCommand,
    },

    /// IVPN commands
    #[cfg(feature = "ivpn")]
    Ivpn {
        #[command(subcommand)]
        command: IvpnCommand,
    },

    /// WireGuard config file/profile commands
    #[cfg(feature = "wgconf")]
    Wgconf {
        #[command(subcommand)]
        command: WgconfCommand,
    },

    /// Connect to a VPN server (`tunmux connect <provider> ...`)
    #[cfg(any(
        feature = "proton",
        feature = "airvpn",
        feature = "mullvad",
        feature = "ivpn",
        feature = "wgconf"
    ))]
    Connect {
        #[command(subcommand)]
        provider: ConnectProviderCommand,
    },

    /// Disconnect VPN connection(s)
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Restrict the operation to one enabled VPN provider
        ///
        /// Only providers compiled into this build are accepted. Omit to consider connections
        /// across providers; combine with an instance name to verify that it belongs to the
        /// selected provider.
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Disconnect all saved connections, optionally scoped by --provider
        ///
        /// Without --provider, considers every provider. With --provider, disconnects only that
        /// provider's sessions. Cannot be combined with an instance name; cleanup failures are
        /// reported rather than silently retiring the session.
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
        /// Use this existing Linux network namespace for the proxy daemon
        ///
        /// Internal daemon option. The privileged setup code creates the namespace and its tunnel
        /// before starting this process.
        #[arg(long)]
        netns: String,

        /// Use this WireGuard interface inside the proxy namespace
        ///
        /// Internal daemon option identifying the tunnel created by privileged setup. It is not a
        /// request to create a new interface.
        #[arg(long)]
        interface: String,

        /// Choose the local SOCKS5 listening port for proxy mode
        ///
        /// Internal daemon option supplied by the parent for this instance. The parent resolves
        /// the listening port before launch; this value is not auto-assigned by the daemon.
        #[arg(long)]
        socks_port: u16,

        /// Choose the local HTTP proxy listening port
        ///
        /// Internal daemon option supplied by the parent for this instance. The parent resolves
        /// the listening port before launch; this value is not auto-assigned by the daemon.
        #[arg(long)]
        http_port: u16,

        /// Record proxy request activity in the instance log
        ///
        /// Applies to --proxy and --local-proxy instances. Enables access logging even when
        /// general.proxy_access_log is disabled. Logs are written to the instance log file.
        #[arg(long)]
        proxy_access_log: bool,

        /// Write the daemon process ID to this runtime file
        ///
        /// Internal daemon bookkeeping used for lifecycle tracking and stop requests. The
        /// launching client supplies the instance-specific path.
        #[arg(long)]
        pid_file: String,

        /// Append daemon logs to this instance log file
        ///
        /// Internal daemon option. The parent supplies the runtime path; log filtering comes from
        /// the inherited logging configuration.
        #[arg(long)]
        log_file: String,

        /// Report proxy daemon readiness or startup failure in this file
        ///
        /// Internal startup acknowledgment consumed by the launching client. The client supplies
        /// a per-instance runtime path.
        #[arg(long)]
        startup_status_file: String,
    },

    /// Internal: userspace WireGuard local-proxy daemon (hidden)
    #[command(hide = true)]
    LocalProxyDaemon {
        /// Choose the local SOCKS5 listening port for proxy mode
        ///
        /// Internal compatibility argument supplied by the parent. The effective listening port
        /// comes from --config-b64; this value does not override the serialized configuration.
        #[arg(long)]
        socks_port: u16,

        /// Choose the local HTTP proxy listening port
        ///
        /// Internal compatibility argument supplied by the parent. The effective listening port
        /// comes from --config-b64; this value does not override the serialized configuration.
        #[arg(long)]
        http_port: u16,

        /// Record proxy request activity in the instance log
        ///
        /// Internal compatibility argument supplied by the parent. The effective access-log setting
        /// is read from --config-b64 and controls per-request proxy activity logging.
        #[arg(long)]
        proxy_access_log: bool,

        /// Write the daemon process ID to this runtime file
        ///
        /// Internal daemon bookkeeping used for lifecycle tracking and stop requests. The
        /// launching client supplies the instance-specific path.
        #[arg(long)]
        pid_file: String,

        /// Append daemon logs to this instance log file
        ///
        /// Internal daemon option. The parent supplies the runtime path; log filtering comes from
        /// the inherited logging configuration.
        #[arg(long)]
        log_file: String,

        /// Read the local-proxy configuration as base64-encoded JSON
        ///
        /// Internal serialization of LocalProxyConfig, including WireGuard credentials. Supplied
        /// by the launching process; do not include this value in diagnostic logs.
        #[arg(long)]
        config_b64: String,
    },

    /// Internal privileged service mode (hidden)
    #[command(hide = true)]
    Privileged {
        /// Run the privileged request service
        ///
        /// Required to enter privileged service mode. Normally started through the client or a
        /// service manager rather than invoked directly.
        #[arg(long)]
        serve: bool,

        /// Exchange privileged requests over stdin/stdout instead of a Unix socket
        ///
        /// Internal transport used by an elevated client subprocess. Keep stdout reserved for
        /// protocol responses. Cannot be combined with --detach.
        #[arg(long, hide = true)]
        stdio: bool,

        /// Detach the privileged socket service into the background
        ///
        /// Used by client autostart. The detached process serves requests independently of the
        /// launching terminal. Cannot be combined with --stdio.
        #[arg(long, hide = true, conflicts_with = "stdio")]
        detach: bool,

        /// Allow members of this group to use the privileged control socket
        ///
        /// Overrides TUNMUX_PRIVILEGED_GROUP; otherwise the default group is tunmux. Root remains
        /// authorized. The group must exist for group-based socket authorization to be
        /// configured.
        #[arg(long)]
        authorized_group: Option<String>,

        /// Set the privileged service idle timeout in milliseconds
        ///
        /// Socket service idle timeouts are bounded below by 100 milliseconds. When omitted, no
        /// explicit CLI idle deadline is installed. Active control leases prevent idle shutdown.
        #[arg(long)]
        idle_timeout_ms: Option<u64>,

        /// Mark the privileged service as launched by client autostart
        ///
        /// Internal lifecycle marker used by the client; service-manager launches should normally
        /// omit it.
        #[arg(long, hide = true)]
        autostarted: bool,
    },
}

#[derive(Subcommand)]
pub enum HookCommand {
    /// Run a predefined hook check now
    Run {
        /// Choose a builtin diagnostic check to run for an active connection
        ///
        /// connectivity checks connectivity, external-ip reports the observed public IP, and dns-
        /// detection checks DNS behavior. Requires an unambiguous saved connection. These checks
        /// can generate outbound network traffic.
        #[arg(value_enum)]
        builtin: HookBuiltinArg,
    },

    /// Print the hook environment payload for an active instance
    Debug {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Restrict the operation to one enabled VPN provider
        ///
        /// Only providers compiled into this build are accepted. Omit to consider connections
        /// across providers; combine with an instance name to verify that it belongs to the
        /// selected provider.
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Choose which hook event environment to print
        ///
        /// ifup shows the connection-start payload; ifdown shows the disconnect payload. This
        /// changes the displayed event environment and does not connect, disconnect, or execute
        /// configured hooks.
        #[arg(long, value_enum, default_value = "ifup")]
        event: HookEventArg,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookEventArg {
    /// Environment for connection-start hooks
    Ifup,
    /// Environment for disconnect hooks
    Ifdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookBuiltinArg {
    /// Probe connectivity through the selected connection
    Connectivity,
    /// Query and display the observed public IP address
    ExternalIp,
    /// Run the DNS detection check for the selected connection
    DnsDetection,
}

pub type ProviderArg = crate::config::Provider;

#[cfg(any(
    feature = "proton",
    feature = "airvpn",
    feature = "mullvad",
    feature = "ivpn",
    feature = "wgconf"
))]
#[derive(Subcommand)]
pub enum ConnectProviderCommand {
    /// Connect using Proton VPN
    #[cfg(feature = "proton")]
    Proton(ProtonConnectArgs),

    /// Connect using AirVPN
    #[cfg(feature = "airvpn")]
    Airvpn(AirVpnConnectArgs),

    /// Connect using Mullvad VPN
    #[cfg(feature = "mullvad")]
    Mullvad(MullvadConnectArgs),

    /// Connect using IVPN
    #[cfg(feature = "ivpn")]
    Ivpn(IvpnConnectArgs),

    /// Connect using a WireGuard config file/profile
    #[cfg(feature = "wgconf")]
    Wgconf(WgconfConnectArgs),
}

#[cfg(feature = "proton")]
#[derive(Args, Clone)]
pub struct ProtonConnectArgs {
    /// Connect to a specific server, such as US#1 or CH#5
    ///
    /// Use a server name from this provider's servers command. When omitted, selects a candidate
    /// using --country or the configured country default, then --sort. Quote names containing
    /// shell metacharacters, for example 'US#1'.
    pub server: Option<String>,

    /// Filter servers by a two-letter country code, such as US or CH
    ///
    /// Country codes are case-insensitive. For automatic connection selection, this overrides the
    /// provider default_country setting in config.toml. An explicitly named server takes
    /// precedence over automatic country-based selection.
    #[arg(short, long)]
    pub country: Option<String>,

    /// Limit automatic Proton selection to P2P-capable servers
    ///
    /// Applies when no server is explicitly named. Uses the same P2P eligibility filter as
    /// --port-forwarding, without enabling port-forwarding certificate features.
    #[arg(long)]
    pub p2p: bool,

    /// Enable Proton port-forwarding certificate features
    ///
    /// Refreshes the VPN certificate when needed and limits automatic selection to P2P-capable
    /// servers. After connecting, request a forwarded port with tunmux proton ports request; this
    /// flag alone does not create a port mapping.
    #[arg(long)]
    pub port_forwarding: bool,

    /// Choose how to rank candidate servers
    ///
    /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable servers
    /// by measured latency, which can take longer. Where supported, load prefers lower reported
    /// load and score uses the provider-specific ranking. An explicitly named connection server
    /// bypasses automatic ranking.
    #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
    pub sort: String,

    #[command(flatten)]
    pub opts: ConnectOptions,
}

#[cfg(feature = "airvpn")]
#[derive(Args, Clone)]
pub struct AirVpnConnectArgs {
    /// Connect to a specific server, such as Castor or Vega
    ///
    /// Use a server name from this provider's servers command. When omitted, selects a candidate
    /// using --country or the configured country default, then --sort. An explicitly named
    /// server bypasses automatic country filtering and ranking.
    pub server: Option<String>,

    /// Filter servers by a two-letter country code, such as US or CH
    ///
    /// Country codes are case-insensitive. For automatic connection selection, this overrides the
    /// provider default_country setting in config.toml. An explicitly named server takes
    /// precedence over automatic country-based selection.
    #[arg(short, long)]
    pub country: Option<String>,

    /// Select the AirVPN WireGuard key to use for this connection
    ///
    /// Names are matched case-insensitively. Overrides airvpn.default_device in config.toml;
    /// otherwise uses the first saved WireGuard key. Run airvpn info to see available keys.
    #[arg(short, long)]
    pub key: Option<String>,

    /// Choose how to rank candidate servers
    ///
    /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable servers
    /// by measured latency, which can take longer. Where supported, load prefers lower reported
    /// load and score uses the provider-specific ranking. An explicitly named connection server
    /// bypasses automatic ranking.
    #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
    pub sort: String,

    #[command(flatten)]
    pub opts: ConnectOptions,
}

#[cfg(feature = "mullvad")]
#[derive(Args, Clone)]
pub struct MullvadConnectArgs {
    /// Connect to a specific server, such as us-nyc-wg-401
    ///
    /// Use a server name from this provider's servers command. When omitted, selects a candidate
    /// using --country or the configured country default, then --sort. An explicitly named
    /// server bypasses automatic country filtering and ranking.
    pub server: Option<String>,

    /// Filter servers by a two-letter country code, such as US or CH
    ///
    /// Country codes are case-insensitive. For automatic connection selection, this overrides the
    /// provider default_country setting in config.toml. An explicitly named server takes
    /// precedence over automatic country-based selection.
    #[arg(short, long)]
    pub country: Option<String>,

    /// Choose how to rank candidate servers
    ///
    /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable servers
    /// by measured latency, which can take longer. Where supported, load prefers lower reported
    /// load and score uses the provider-specific ranking. An explicitly named connection server
    /// bypasses automatic ranking.
    #[arg(short = 's', long, default_value = "name", value_parser = ["name", "latency"])]
    pub sort: String,

    #[command(flatten)]
    pub opts: ConnectOptions,
}

#[cfg(feature = "ivpn")]
#[derive(Args, Clone)]
pub struct IvpnConnectArgs {
    /// Connect to a specific server, such as us-ny4.wg.ivpn.net or us.wg.ivpn.net
    ///
    /// Use a server name from this provider's servers command. When omitted, selects a candidate
    /// using --country or the configured country default, then --sort. An explicitly named
    /// server bypasses automatic country filtering and ranking.
    pub server: Option<String>,

    /// Filter servers by a two-letter country code, such as US or CH
    ///
    /// Country codes are case-insensitive. For automatic connection selection, this overrides the
    /// provider default_country setting in config.toml. An explicitly named server takes
    /// precedence over automatic country-based selection.
    #[arg(short, long)]
    pub country: Option<String>,

    /// Choose how to rank candidate servers
    ///
    /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable servers
    /// by measured latency, which can take longer. Where supported, load prefers lower reported
    /// load and score uses the provider-specific ranking. An explicitly named connection server
    /// bypasses automatic ranking.
    #[arg(short = 's', long, default_value = "load", value_parser = ["load", "name", "latency"])]
    pub sort: String,

    #[command(flatten)]
    pub opts: ConnectOptions,
}

#[cfg(feature = "wgconf")]
#[derive(Args, Clone)]
pub struct WgconfConnectArgs {
    /// Stable SOCKS5 port for proxy mode
    #[arg(long)]
    pub socks_port: Option<u16>,
    /// Stable HTTP port for proxy mode
    #[arg(long)]
    pub http_port: Option<u16>,
    /// Succeed when this exact source is already active
    #[arg(long)]
    pub if_missing: bool,

    /// Bypass directly attached LAN networks (macOS helper direct mode only)
    #[arg(long)]
    pub allow_lan: bool,

    /// Read a WireGuard .conf file from this path
    ///
    /// For connect, supply exactly one of --file and --profile. The file is read from disk
    /// without changing its source contents. Use --save-as with connect, or wgconf save, to keep
    /// a reusable named copy.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub file: Option<String>,

    /// Load a saved WireGuard profile by name
    ///
    /// Supply exactly one of --profile and --file. Profiles are stored in the wgconf/profiles
    /// directory under the tunmux configuration directory; use wgconf list to see saved names.
    #[arg(long, required_unless_present = "file", conflicts_with = "file")]
    pub profile: Option<String>,

    /// Save the loaded configuration under this reusable profile name
    ///
    /// Stores a copy for later use with --profile, including an explicit MTU override when
    /// supplied. Existing profiles with this name are overwritten. Names may contain lowercase
    /// letters, digits, dots, underscores, and hyphens, up to 64 characters.
    #[arg(long)]
    pub save_as: Option<String>,

    /// Select the WireGuard implementation for this connection
    ///
    /// Accepts kernel, userspace, or wg-quick. Overrides general.backend in config.toml; the
    /// platform default is kernel on Linux and userspace on macOS. Kernel mode uses native
    /// WireGuard, userspace uses the embedded helper, and wg-quick invokes the installed wg-quick
    /// tool. --proxy requires kernel mode.
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Expose the VPN through a Linux namespace SOCKS5/HTTP proxy
    ///
    /// Requires Linux, the proxy build feature, and the kernel backend. Routes proxy traffic
    /// through an isolated network namespace rather than changing the host default route.
    /// Mutually exclusive with --local-proxy.
    #[arg(long, conflicts_with = "local_proxy")]
    pub proxy: bool,

    /// Expose a rootless userspace SOCKS5/HTTP proxy
    ///
    /// Runs WireGuard inside the proxy process without a host tunnel interface, root privileges,
    /// or Android VpnService. Only applications configured to use the proxy send traffic through
    /// it. Mutually exclusive with --proxy.
    #[arg(long, conflicts_with = "proxy")]
    pub local_proxy: bool,

    /// Block host IPv6 egress during an IPv4-only direct kernel tunnel
    ///
    /// Valid only with the kernel backend, an IPv4-only profile, and neither proxy mode. Adds
    /// IPv6 blocking routes while connected and removes them on disconnect; it does not disable
    /// IPv6 globally or rewrite the profile.
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Override the WireGuard interface MTU in bytes
    ///
    /// Accepts 576 through 65535. Overrides the profile MTU; when omitted, the profile value or
    /// backend default applies. Used for direct tunnels and kernel namespace proxies. Rootless
    /// local-proxy mode has no host interface MTU to set. An explicit --mtu is rejected with
    /// --local-proxy.
    #[arg(long)]
    pub mtu: Option<u16>,
}

#[cfg(feature = "proton")]
#[derive(Subcommand)]
pub enum ProtonCommand {
    /// Sign in with Proton VPN credentials
    Login {
        /// Sign in with the Proton account username
        ///
        /// The password is requested interactively rather than supplied as a command-line
        /// argument. Successful login saves credentials using the configured credential store.
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
        /// Filter servers by a two-letter country code, such as US or CH
        ///
        /// Country codes are case-insensitive. For example, --country CH lists servers in
        /// Switzerland. Omit to list all countries; this filter does not change the configured
        /// default country used by connect.
        #[arg(short, long)]
        country: Option<String>,

        /// Restrict the server list to Proton free-tier servers
        ///
        /// Only displays servers in the free tier. Omit this flag to include paid-tier servers
        /// in the listing as well.
        #[arg(short, long)]
        free: bool,

        /// Require matching server features
        ///
        /// Repeat --tag or separate values with commas; all requested tags must match. Accepts
        /// secure-core, tor, p2p, streaming, and ipv6. Unsupported feature combinations can yield
        /// no servers.
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Choose how to rank the server list
        ///
        /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable
        /// servers by measured latency, which can take longer. Where supported, load prefers
        /// lower reported load and score uses the provider-specific ranking. The accepted values
        /// and default are shown below; latency-based rankings generate outbound probes.
        #[arg(short = 's', long, default_value = "score", value_parser = ["score", "load", "name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(ProtonConnectArgs),

    /// Manage Proton NAT-PMP port forwarding
    Ports {
        #[command(subcommand)]
        action: ProtonPortAction,
    },

    /// Disconnect from VPN
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Disconnect every saved connection for this provider
        ///
        /// Includes direct tunnels and proxy instances owned by this provider. Cannot be combined
        /// with an instance name. Without --all, the command disconnects an unambiguous
        /// connection or displays the available choices.
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },
}

#[cfg(feature = "proton")]
#[derive(Subcommand)]
pub enum ProtonPortAction {
    /// Request a Proton NAT-PMP forwarded port
    Request {
        /// Choose whether to map TCP, UDP, or both protocols
        ///
        /// both creates or maintains separate TCP and UDP NAT-PMP mappings. Defaults to both;
        /// requires a direct Proton connection with port-forwarding support.
        #[arg(long, default_value = "both", value_parser = ["both", "tcp", "udp"])]
        protocol: String,

        /// Request this public NAT-PMP port, or 0 for automatic assignment
        ///
        /// The gateway chooses the effective external port, which is saved and displayed after
        /// the request. The default 0 asks it to assign an available port.
        #[arg(short = 'p', long, default_value_t = 0)]
        public_port: u16,

        /// Set the internal port number sent in the NAT-PMP request
        ///
        /// Defaults to 1. This is the local-port field of the gateway mapping request; it does
        /// not open a local listening socket or configure an application.
        #[arg(short = 'l', long, default_value_t = 1)]
        local_port: u16,

        /// Request a NAT-PMP mapping lease length in seconds
        ///
        /// Defaults to 60 seconds. The gateway returns the granted lifetime; mappings must be
        /// renewed before they expire. Use ports release to explicitly release saved mappings.
        #[arg(long, default_value_t = 60)]
        lifetime: u32,

        /// Request the port mapping without starting automatic renewal
        ///
        /// By default, a successful request starts a background renew daemon. With this flag,
        /// mappings can expire unless renewed manually with ports renew or maintained by ports
        /// daemon.
        #[arg(long)]
        no_daemon: bool,
    },

    /// List saved Proton NAT-PMP forwarded ports
    List {
        /// Show only mappings associated with the current direct Proton tunnel
        ///
        /// Filters saved mapping records by the current direct Proton connection instead of
        /// listing all saved mappings. Connect directly to Proton before using this filter.
        #[arg(long)]
        current: bool,

        /// Print the result as JSON instead of the human-readable summary
        ///
        /// Use this for scripts that need structured output. Only the command result is formatted
        /// as JSON; diagnostic logs are written separately to stderr.
        #[arg(long)]
        json: bool,
    },

    /// Renew saved Proton NAT-PMP forwarded ports
    Renew {
        /// Request a NAT-PMP mapping lease length in seconds
        ///
        /// Defaults to 60 seconds. The gateway returns the granted lifetime; mappings must be
        /// renewed before they expire. Use ports release to explicitly release saved mappings.
        #[arg(long, default_value_t = 60)]
        lifetime: u32,
    },

    /// Stop renew daemon and release saved Proton forwarded ports
    Release,

    /// Keep Proton NAT-PMP mappings alive (runs until interrupted)
    Daemon {
        /// Choose whether to map TCP, UDP, or both protocols
        ///
        /// both creates or maintains separate TCP and UDP NAT-PMP mappings. Defaults to both;
        /// requires a direct Proton connection with port-forwarding support.
        #[arg(long, default_value = "both", value_parser = ["both", "tcp", "udp"])]
        protocol: String,

        /// Request this public NAT-PMP port, or 0 for automatic assignment
        ///
        /// The gateway chooses the effective external port, which is saved and displayed after
        /// the request. The default 0 asks it to assign an available port.
        #[arg(short = 'p', long, default_value_t = 0)]
        public_port: u16,

        /// Set the internal port number sent in the NAT-PMP request
        ///
        /// Defaults to 1. This is the local-port field of the gateway mapping request; it does
        /// not open a local listening socket or configure an application.
        #[arg(short = 'l', long, default_value_t = 1)]
        local_port: u16,

        /// Request a NAT-PMP mapping lease length in seconds
        ///
        /// Defaults to 60 seconds. The gateway returns the granted lifetime; mappings must be
        /// renewed before they expire. Use ports release to explicitly release saved mappings.
        #[arg(long, default_value_t = 60)]
        lifetime: u32,

        /// Set the interval between port-mapping renewals in seconds
        ///
        /// Defaults to 45 seconds. Choose an interval shorter than the requested mapping lifetime
        /// so renewals run before the lease expires. The foreground daemon runs until
        /// interrupted.
        #[arg(long, default_value_t = 45)]
        renew_every: u64,

        /// Skip the initial mapping request and renew saved mappings only
        ///
        /// Internal option used when a successful request already established the mappings before
        /// launching the renew loop.
        #[arg(long, hide = true)]
        no_initial_request: bool,
    },
}

#[cfg(feature = "airvpn")]
#[derive(Subcommand)]
pub enum AirVpnCommand {
    /// Sign in with AirVPN credentials
    Login {
        /// Sign in with the AirVPN username
        ///
        /// The password is requested interactively rather than supplied as a command-line
        /// argument. Successful login saves credentials using the configured credential store.
        username: String,
    },

    /// Sign out and remove credentials
    Logout,

    /// Display account information
    Info,

    /// List available VPN servers
    Servers {
        /// Filter servers by a two-letter country code, such as US or CH
        ///
        /// Country codes are case-insensitive. For example, --country CH lists servers in
        /// Switzerland. Omit to list all countries; this filter does not change the configured
        /// default country used by connect.
        #[arg(short, long)]
        country: Option<String>,

        /// Require matching server keywords
        ///
        /// Repeat --tag or separate values with commas; all requested tags must match. Matches
        /// provider server metadata such as names and locations; matching is case-insensitive.
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Choose how to rank the server list
        ///
        /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable
        /// servers by measured latency, which can take longer. Where supported, load prefers
        /// lower reported load and score uses the provider-specific ranking. The accepted values
        /// and default are shown below; latency-based rankings generate outbound probes.
        #[arg(short = 's', long, default_value = "name", value_parser = ["name", "score", "load", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(AirVpnConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Disconnect every saved connection for this provider
        ///
        /// Includes direct tunnels and proxy instances owned by this provider. Cannot be combined
        /// with an instance name. Without --all, the command disconnects an unambiguous
        /// connection or displays the available choices.
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },

    /// Show active VPN sessions
    Sessions,

    /// Generate a config file via the AirVPN API
    Generate {
        /// Select servers or countries for generated configurations
        ///
        /// Required and repeatable: for example, -s be -s nl. Multiple server values or protocol
        /// values produce an archive instead of a single configuration.
        #[arg(short, long, required = true)]
        server: Vec<String>,

        /// Select one or more protocols for generated configurations
        ///
        /// Repeat --protocol for multiple outputs. Aliases include wg-1637, wg-47107, wg-51820,
        /// openvpn-udp-443, openvpn-udp-80, openvpn-udp-53, openvpn-udp-1194, openvpn-tcp-443,
        /// openvpn-tcp-80, openvpn-ssh-22, and openvpn-ssl-443. Raw API values such as
        /// wireguard_3_udp_PORT and openvpn_1_tcp_PORT are accepted. When omitted, uses the first
        /// WireGuard mode advertised in the saved manifest.
        #[arg(short, long, verbatim_doc_comment)]
        protocol: Vec<String>,

        /// Select an AirVPN device or WireGuard key by name
        ///
        /// Use airvpn devices list or airvpn info to find names. For configuration generation,
        /// omission uses the first saved device/key.
        #[arg(short, long)]
        device: Option<String>,

        /// Choose the IP family used to reach the VPN server
        ///
        /// Accepts ipv4 or ipv6; defaults to ipv4. Controls the entry endpoint family in
        /// generated configurations, rather than the IP families routed out of the VPN.
        #[arg(long, default_value = "ipv4")]
        entry: String,

        /// Choose the IP families routed through the generated VPN configuration
        ///
        /// Accepts both, ipv4, or ipv6; defaults to both. This is independent of --entry, which
        /// selects the family used to reach the server.
        #[arg(long, default_value = "both")]
        exit: String,

        /// Set the MTU written into generated WireGuard configurations
        ///
        /// Defaults to 1320 bytes. This setting is sent to the AirVPN configuration generator and
        /// does not change an active tunnel on this host.
        #[arg(long, default_value = "1320")]
        mtu: u16,

        /// Set generated WireGuard persistent keepalive in seconds
        ///
        /// Defaults to 15 seconds. Controls periodic keepalive packets in the generated
        /// configuration; use 0 to request that persistent keepalive be disabled.
        #[arg(long, default_value = "15")]
        keepalive: u16,

        /// Write the generated configuration or archive to this path
        ///
        /// For a single server/protocol combination, omission prints the configuration to stdout.
        /// Multiple combinations produce an archive, defaulting to airvpn.<format>. Existing
        /// output files are overwritten.
        #[arg(short, long)]
        output: Option<String>,

        /// Choose the archive format for multiple generated configurations
        ///
        /// Accepts zip, 7z, tar, tar.gz, tar.bz2, or tar.xz; defaults to zip. Used only when
        /// multiple servers or protocols are requested; a single combination produces plain
        /// configuration text.
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

#[cfg(feature = "mullvad")]
#[derive(Subcommand)]
pub enum MullvadCommand {
    /// Sign in with Mullvad account number
    Login {
        /// Use this Mullvad account number
        ///
        /// Uses this account to sign in and save a VPN session. If a different account is already
        /// saved, confirmation is required unless --force is set.
        account: String,

        /// Replace an existing saved account ID without asking for confirmation
        ///
        /// Applies to account login or creation for this provider. It does not disconnect an
        /// active tunnel or remove the old account at the VPN provider.
        #[arg(long)]
        force: bool,
    },

    /// Create a new Mullvad account and sign in
    CreateAccount {
        /// Print the result as JSON instead of the human-readable summary
        ///
        /// Use this for scripts that need structured output. Only the command result is formatted
        /// as JSON; diagnostic logs are written separately to stderr.
        #[arg(long)]
        json: bool,

        /// Replace an existing saved account ID without asking for confirmation
        ///
        /// Applies to account login or creation for this provider. It does not disconnect an
        /// active tunnel or remove the old account at the VPN provider.
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
        /// Filter servers by a two-letter country code, such as US or CH
        ///
        /// Country codes are case-insensitive. For example, --country CH lists servers in
        /// Switzerland. Omit to list all countries; this filter does not change the configured
        /// default country used by connect.
        #[arg(short, long)]
        country: Option<String>,

        /// Require matching server keywords
        ///
        /// Repeat --tag or separate values with commas; all requested tags must match. Matches
        /// provider server metadata such as names and locations; matching is case-insensitive.
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Choose how to rank the server list
        ///
        /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable
        /// servers by measured latency, which can take longer. Where supported, load prefers
        /// lower reported load and score uses the provider-specific ranking. The accepted values
        /// and default are shown below; latency-based rankings generate outbound probes.
        #[arg(short = 's', long, default_value = "name", value_parser = ["name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(MullvadConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Disconnect every saved connection for this provider
        ///
        /// Includes direct tunnels and proxy instances owned by this provider. Cannot be combined
        /// with an instance name. Without --all, the command disconnects an unambiguous
        /// connection or displays the available choices.
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },
}

#[cfg(feature = "ivpn")]
#[derive(Subcommand)]
pub enum IvpnCommand {
    /// Sign in with IVPN account ID
    Login {
        /// Use this IVPN account ID
        ///
        /// Uses this account to sign in and save a VPN session. If a different account is already
        /// saved, confirmation is required unless --force is set.
        account: String,

        /// Replace an existing saved account ID without asking for confirmation
        ///
        /// Applies to account login or creation for this provider. It does not disconnect an
        /// active tunnel or remove the old account at the VPN provider.
        #[arg(long)]
        force: bool,
    },

    /// Create a new IVPN account
    CreateAccount {
        /// Choose the IVPN product for the newly created account
        ///
        /// Accepts standard or pro; defaults to standard. Applies only to account creation, not
        /// to changing the product of an existing saved account.
        #[arg(long, default_value = "standard", value_parser = ["standard", "pro"])]
        product: String,

        /// Replace an existing saved account ID without asking for confirmation
        ///
        /// Applies to account login or creation for this provider. It does not disconnect an
        /// active tunnel or remove the old account at the VPN provider.
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
        /// Filter servers by a two-letter country code, such as US or CH
        ///
        /// Country codes are case-insensitive. For example, --country CH lists servers in
        /// Switzerland. Omit to list all countries; this filter does not change the configured
        /// default country used by connect.
        #[arg(short, long)]
        country: Option<String>,

        /// Require matching server keywords
        ///
        /// Repeat --tag or separate values with commas; all requested tags must match. Matches
        /// provider server metadata such as names and locations; matching is case-insensitive.
        #[arg(short = 't', long, value_delimiter = ',')]
        tag: Vec<String>,

        /// Choose how to rank the server list
        ///
        /// name sorts alphabetically; latency probes candidate endpoints and ranks reachable
        /// servers by measured latency, which can take longer. Where supported, load prefers
        /// lower reported load and score uses the provider-specific ranking. The accepted values
        /// and default are shown below; latency-based rankings generate outbound probes.
        #[arg(short = 's', long, default_value = "load", value_parser = ["load", "name", "latency"])]
        sort: String,
    },

    /// Connect to a VPN server
    Connect(IvpnConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Disconnect every saved connection for this provider
        ///
        /// Includes direct tunnels and proxy instances owned by this provider. Cannot be combined
        /// with an instance name. Without --all, the command disconnects an unambiguous
        /// connection or displays the available choices.
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },
}

#[cfg(feature = "wgconf")]
#[derive(Subcommand)]
pub enum WgconfCommand {
    /// Connect from a WireGuard config file or saved profile
    Connect(WgconfConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Select a saved connection instance from tunmux status
        ///
        /// Use the instance name printed by tunmux status. If omitted, selection uses the
        /// provider filter, when supplied, and requires an unambiguous connection; multiple
        /// candidates are listed for selection.
        instance: Option<String>,

        /// Disconnect every saved connection for this provider
        ///
        /// Includes direct tunnels and proxy instances owned by this provider. Cannot be combined
        /// with an instance name. Without --all, the command disconnects an unambiguous
        /// connection or displays the available choices.
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },

    /// Save a WireGuard config file as a named profile
    Save {
        /// Read a WireGuard .conf file from this path
        ///
        /// For connect, supply exactly one of --file and --profile. The file is read from disk
        /// without changing its source contents. Use --save-as with connect, or wgconf save, to
        /// keep a reusable named copy.
        #[arg(long)]
        file: String,

        /// Name the saved WireGuard profile
        ///
        /// Names may contain lowercase letters, digits, dots, underscores, and hyphens, up to 64
        /// characters. Saving overwrites an existing profile with this name; connect later with
        /// --profile NAME.
        #[arg(long)]
        name: String,
    },

    /// List saved profiles
    List,

    /// Remove a saved profile
    Remove {
        /// Remove the saved profile with this name
        ///
        /// Use wgconf list to find profile names. Removes the stored profile file; disconnect an
        /// active tunnel separately.
        name: String,
    },
}

#[cfg(feature = "mullvad")]
#[derive(Subcommand)]
pub enum MullvadPaymentCommand {
    /// Fetch Mullvad Monero payment details from the web account flow
    Monero {
        /// Use this Mullvad account number
        ///
        /// When omitted, uses the account from the saved session. Fetching payment details does
        /// not replace the saved login or submit a payment.
        #[arg(long)]
        account: Option<String>,

        /// Print the result as JSON instead of the human-readable summary
        ///
        /// Use this for scripts that need structured output. Only the command result is formatted
        /// as JSON; diagnostic logs are written separately to stderr.
        #[arg(long)]
        json: bool,
    },
}

#[cfg(feature = "ivpn")]
#[derive(Subcommand)]
pub enum IvpnPaymentCommand {
    /// Fetch Monero payment details for an IVPN account
    Monero {
        /// Use this IVPN account ID
        ///
        /// When omitted, uses the account from the saved session. Fetching payment details does
        /// not replace the saved login or submit a payment.
        account: Option<String>,

        /// Choose the IVPN billing period for Monero payment details
        ///
        /// 7d requests seven days, 1m one month, and 1y one year. Defaults to 1m. Fetches payment
        /// details for the selected period; it does not send a payment.
        #[arg(long, default_value = "1m", value_parser = ["7d", "1m", "1y"])]
        duration: String,
    },
}

#[cfg(feature = "airvpn")]
#[derive(Subcommand)]
pub enum PortAction {
    /// List forwarded ports
    List,

    /// Add a port forward
    Add {
        /// Select the AirVPN public forwarded port
        ///
        /// For add, 0 requests automatic assignment. For remove, info, check, or set, use an
        /// existing public port from airvpn ports list. This is the provider-side port, not a
        /// local listener.
        port: u16,

        /// Choose tcp, udp, or both for the AirVPN port forward
        ///
        /// For a new forward, defaults to both. When editing an existing forward, omission
        /// preserves its current protocol setting.
        #[arg(short, long, default_value = "both")]
        protocol: String,

        /// Set the local destination port for this AirVPN forward
        ///
        /// For a new forward, omission uses the remote port. When editing an existing forward,
        /// omission leaves its local-port setting unchanged. This changes the provider mapping
        /// and does not open a local listener.
        #[arg(short, long)]
        local: Option<u16>,

        /// Assign an AirVPN dynamic DNS hostname prefix
        ///
        /// For example, myhost becomes myhost.airdns.org. Supply the prefix rather than the full
        /// domain. When editing a forward, omit to preserve its existing DDNS setting.
        #[arg(short, long)]
        ddns: Option<String>,
    },

    /// Remove a port forward
    Remove {
        /// Select the AirVPN public forwarded port
        ///
        /// For add, 0 requests automatic assignment. For remove, info, check, or set, use an
        /// existing public port from airvpn ports list. This is the provider-side port, not a
        /// local listener.
        port: u16,
    },

    /// Show active sessions for a forwarded port
    Info {
        /// Select the AirVPN public forwarded port
        ///
        /// For add, 0 requests automatic assignment. For remove, info, check, or set, use an
        /// existing public port from airvpn ports list. This is the provider-side port, not a
        /// local listener.
        port: u16,
    },

    /// Test if a forwarded port is reachable
    Check {
        /// Select the AirVPN public forwarded port
        ///
        /// For add, 0 requests automatic assignment. For remove, info, check, or set, use an
        /// existing public port from airvpn ports list. This is the provider-side port, not a
        /// local listener.
        port: u16,
    },

    /// Edit settings on an existing forwarded port
    #[command(visible_alias = "edit")]
    Set {
        /// Select the AirVPN public forwarded port
        ///
        /// For add, 0 requests automatic assignment. For remove, info, check, or set, use an
        /// existing public port from airvpn ports list. This is the provider-side port, not a
        /// local listener.
        port: u16,

        /// Choose tcp, udp, or both for the AirVPN port forward
        ///
        /// For a new forward, defaults to both. When editing an existing forward, omission
        /// preserves its current protocol setting.
        #[arg(short, long)]
        protocol: Option<String>,

        /// Set the local destination port for this AirVPN forward
        ///
        /// For a new forward, omission uses the remote port. When editing an existing forward,
        /// omission leaves its local-port setting unchanged. This changes the provider mapping
        /// and does not open a local listener.
        #[arg(short, long)]
        local: Option<u16>,

        /// Assign an AirVPN dynamic DNS hostname prefix
        ///
        /// For example, myhost becomes myhost.airdns.org. Supply the prefix rather than the full
        /// domain. When editing a forward, omit to preserve its existing DDNS setting.
        #[arg(short, long)]
        ddns: Option<String>,
    },
}

#[cfg(feature = "airvpn")]
#[derive(Subcommand)]
pub enum DeviceAction {
    /// List all devices (WireGuard keys)
    List,

    /// Add a new device
    Add {
        /// Name the AirVPN device/WireGuard key
        ///
        /// For add, omission keeps the provider name New device. For rename, this is the
        /// replacement display name; identify the existing device with its current name.
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Rename a device
    Rename {
        /// Identify an AirVPN device by its current name
        ///
        /// Use airvpn devices list to find existing names. The command resolves that device
        /// before renaming or deleting it.
        device: String,

        /// Name the AirVPN device/WireGuard key
        ///
        /// For add, omission keeps the provider name New device. For rename, this is the
        /// replacement display name; identify the existing device with its current name.
        name: String,
    },

    /// Delete a device
    Delete {
        /// Identify an AirVPN device by its current name
        ///
        /// Use airvpn devices list to find existing names. The command resolves that device
        /// before renaming or deleting it.
        device: String,
    },
}

#[cfg(feature = "airvpn")]
#[derive(Subcommand)]
pub enum ApiKeyAction {
    /// List API keys
    List,

    /// Generate a new API key
    Add {
        /// Set the AirVPN API key display name
        ///
        /// For add, omission keeps the provider-assigned name. For rename, this is the new name
        /// for the selected key; it does not replace the secret key value.
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Rename an API key
    Rename {
        /// Identify the AirVPN API key by its current name
        ///
        /// Use airvpn api-keys list to find existing key names. This selects the key record to
        /// rename or delete; it is not the secret API key value.
        key: String,

        /// Set the AirVPN API key display name
        ///
        /// For add, omission keeps the provider-assigned name. For rename, this is the new name
        /// for the selected key; it does not replace the secret key value.
        name: String,
    },

    /// Delete an API key
    Delete {
        /// Identify the AirVPN API key by its current name
        ///
        /// Use airvpn api-keys list to find existing key names. This selects the key record to
        /// rename or delete; it is not the secret API key value.
        key: String,
    },
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "airvpn")]
    use super::AirVpnCommand;
    #[cfg(any(
        feature = "proton",
        feature = "airvpn",
        feature = "mullvad",
        feature = "ivpn",
        feature = "wgconf"
    ))]
    use super::ConnectProviderCommand;
    use super::ProviderArg;
    #[cfg(feature = "wgconf")]
    use super::WgconfCommand;
    use super::{Cli, HookBuiltinArg, HookCommand, TopCommand};
    #[cfg(feature = "proton")]
    use super::{ProtonCommand, ProtonPortAction};
    use clap::{error::ErrorKind, Parser, ValueEnum};

    #[cfg(feature = "wgconf")]
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

    #[cfg(feature = "wgconf")]
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

    #[cfg(feature = "wgconf")]
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

    #[cfg(feature = "wgconf")]
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

    #[cfg(any(
        feature = "proton",
        feature = "airvpn",
        feature = "mullvad",
        feature = "ivpn"
    ))]
    #[test]
    fn parse_disable_ipv6_for_all_provider_connect_commands() {
        #[cfg(feature = "proton")]
        {
            let cli =
                Cli::try_parse_from(["tunmux", "connect", "proton", "--disable-ipv6"]).unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Proton(args),
                } => assert!(args.opts.disable_ipv6),
                _ => panic!("expected proton connect"),
            }
        }
        #[cfg(feature = "airvpn")]
        {
            let cli =
                Cli::try_parse_from(["tunmux", "connect", "airvpn", "--disable-ipv6"]).unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Airvpn(args),
                } => assert!(args.opts.disable_ipv6),
                _ => panic!("expected airvpn connect"),
            }
        }
        #[cfg(feature = "mullvad")]
        {
            let cli =
                Cli::try_parse_from(["tunmux", "connect", "mullvad", "--disable-ipv6"]).unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Mullvad(args),
                } => assert!(args.opts.disable_ipv6),
                _ => panic!("expected mullvad connect"),
            }
        }
        #[cfg(feature = "ivpn")]
        {
            let cli = Cli::try_parse_from(["tunmux", "connect", "ivpn", "--disable-ipv6"]).unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Ivpn(args),
                } => assert!(args.opts.disable_ipv6),
                _ => panic!("expected ivpn connect"),
            }
        }
    }

    #[cfg(any(feature = "proton", feature = "wgconf"))]
    #[test]
    fn parse_mtu_for_connect_commands() {
        #[cfg(feature = "proton")]
        {
            let cli =
                Cli::try_parse_from(["tunmux", "connect", "proton", "--mtu", "1280"]).unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Proton(args),
                } => assert_eq!(args.opts.mtu, Some(1280)),
                _ => panic!("expected proton connect"),
            }
        }
        #[cfg(feature = "wgconf")]
        {
            let cli = Cli::try_parse_from([
                "tunmux",
                "connect",
                "wgconf",
                "--file",
                "/tmp/test.conf",
                "--mtu",
                "1360",
            ])
            .unwrap();
            match cli.command {
                TopCommand::Connect {
                    provider: ConnectProviderCommand::Wgconf(args),
                } => assert_eq!(args.mtu, Some(1360)),
                _ => panic!("expected wgconf connect"),
            }
        }
    }

    #[cfg(feature = "proton")]
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

    #[cfg(feature = "proton")]
    #[test]
    fn parse_proton_ports_request_command() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "proton",
            "ports",
            "request",
            "--protocol",
            "udp",
            "--public-port",
            "0",
            "--local-port",
            "1",
            "--lifetime",
            "90",
        ])
        .expect("parse proton ports request");
        match cli.command {
            TopCommand::Proton {
                command:
                    ProtonCommand::Ports {
                        action:
                            ProtonPortAction::Request {
                                protocol,
                                public_port,
                                local_port,
                                lifetime,
                                no_daemon,
                            },
                    },
            } => {
                assert_eq!(protocol, "udp");
                assert_eq!(public_port, 0);
                assert_eq!(local_port, 1);
                assert_eq!(lifetime, 90);
                assert!(!no_daemon);
            }
            _ => panic!("expected proton ports request command"),
        }
    }

    #[cfg(feature = "proton")]
    #[test]
    fn parse_proton_ports_renew_command() {
        let cli = Cli::try_parse_from(["tunmux", "proton", "ports", "renew", "--lifetime", "120"])
            .expect("parse proton ports renew");
        match cli.command {
            TopCommand::Proton {
                command:
                    ProtonCommand::Ports {
                        action: ProtonPortAction::Renew { lifetime },
                    },
            } => assert_eq!(lifetime, 120),
            _ => panic!("expected proton ports renew command"),
        }
    }

    #[cfg(feature = "proton")]
    #[test]
    fn parse_proton_ports_list_current_json_command() {
        let cli = Cli::try_parse_from(["tunmux", "proton", "ports", "list", "--current", "--json"])
            .expect("parse proton ports list --current --json");
        match cli.command {
            TopCommand::Proton {
                command:
                    ProtonCommand::Ports {
                        action: ProtonPortAction::List { current, json },
                    },
            } => {
                assert!(current);
                assert!(json);
            }
            _ => panic!("expected proton ports list command"),
        }
    }

    #[cfg(feature = "proton")]
    #[test]
    fn parse_proton_ports_daemon_command() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "proton",
            "ports",
            "daemon",
            "--protocol",
            "both",
            "--public-port",
            "0",
            "--local-port",
            "1",
            "--lifetime",
            "60",
            "--renew-every",
            "45",
        ])
        .expect("parse proton ports daemon");
        match cli.command {
            TopCommand::Proton {
                command:
                    ProtonCommand::Ports {
                        action:
                            ProtonPortAction::Daemon {
                                protocol,
                                public_port,
                                local_port,
                                lifetime,
                                renew_every,
                                no_initial_request,
                            },
                    },
            } => {
                assert_eq!(protocol, "both");
                assert_eq!(public_port, 0);
                assert_eq!(local_port, 1);
                assert_eq!(lifetime, 60);
                assert_eq!(renew_every, 45);
                assert!(!no_initial_request);
            }
            _ => panic!("expected proton ports daemon command"),
        }
    }

    #[cfg(feature = "proton")]
    #[test]
    fn parse_proton_ports_release_command() {
        let cli =
            Cli::try_parse_from(["tunmux", "proton", "ports", "release"]).expect("parse release");
        match cli.command {
            TopCommand::Proton {
                command:
                    ProtonCommand::Ports {
                        action: ProtonPortAction::Release,
                    },
            } => {}
            _ => panic!("expected proton ports release command"),
        }
    }

    #[cfg(feature = "airvpn")]
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

    #[cfg(feature = "airvpn")]
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
        for (name, expected) in [
            ("connectivity", HookBuiltinArg::Connectivity),
            ("external-ip", HookBuiltinArg::ExternalIp),
            ("dns-detection", HookBuiltinArg::DnsDetection),
        ] {
            let cli = Cli::try_parse_from(["tunmux", "hook", "run", name]).unwrap();
            match cli.command {
                TopCommand::Hook {
                    command: HookCommand::Run { builtin },
                } => assert_eq!(builtin, expected, "{name}"),
                _ => panic!("expected hook run command for {name}"),
            }
        }
    }

    #[test]
    fn parse_connect_proxy_flags_are_mutually_exclusive() {
        for provider in ProviderArg::value_variants() {
            let value = provider.to_possible_value().unwrap();
            let name = value.get_name();
            let mut args = vec!["tunmux", "connect", name, "--proxy", "--local-proxy"];
            if name == "wgconf" {
                args.extend(["--file", "/tmp/test.conf"]);
            }
            let error = Cli::try_parse_from(args)
                .err()
                .expect("conflicting proxy modes");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{name}: {error}");
        }
    }

    #[test]
    fn parse_provider_disconnect_rejects_instance_with_all() {
        for provider in ProviderArg::value_variants() {
            let value = provider.to_possible_value().unwrap();
            let name = value.get_name();
            for args in [
                vec!["tunmux", name, "disconnect", "x", "--all"],
                vec!["tunmux", "disconnect", "x", "--provider", name, "--all"],
            ] {
                let error = Cli::try_parse_from(args)
                    .err()
                    .expect("conflicting disconnect selection");
                assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{name}: {error}");
            }
        }
    }

    #[test]
    fn test_cli_exposes_only_enabled_providers() {
        use clap::{CommandFactory, ValueEnum};
        let command = Cli::command();
        command.clone().debug_assert();
        let connect = command.find_subcommand("connect");
        let providers = [
            ("proton", cfg!(feature = "proton")),
            ("airvpn", cfg!(feature = "airvpn")),
            ("mullvad", cfg!(feature = "mullvad")),
            ("ivpn", cfg!(feature = "ivpn")),
            ("wgconf", cfg!(feature = "wgconf")),
        ];
        for (name, enabled) in providers {
            assert_eq!(
                command.find_subcommand(name).is_some(),
                enabled,
                "top-level {name}"
            );
            assert_eq!(
                connect
                    .and_then(|command| command.find_subcommand(name))
                    .is_some(),
                enabled,
                "connect {name}"
            );
            let cli_value = crate::config::Provider::value_variants()
                .iter()
                .any(|provider| provider.dir_name() == name);
            assert_eq!(cli_value, enabled, "provider argument {name}");
            assert!(
                crate::config::Provider::from_dir_name(name).is_some(),
                "saved provider identity {name}"
            );
            if !enabled {
                assert!(Cli::try_parse_from(["tunmux", name, "connect"]).is_err());
                assert!(Cli::try_parse_from(["tunmux", "connect", name]).is_err());
                assert!(Cli::try_parse_from(["tunmux", "disconnect", "--provider", name]).is_err());
            }
        }
        assert_eq!(
            connect.is_some(),
            providers.iter().any(|(_, enabled)| *enabled)
        );
    }
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install the root service; requires root
    Install {
        #[arg(long, default_value = "/usr/local/libexec/tunmux")]
        binary_path: std::path::PathBuf,
        #[arg(long, default_value = if cfg!(target_os = "macos") { "admin" } else { "tunmux" })]
        authorized_group: String,
        /// Login user whose sessions are managed during reload/uninstall
        #[arg(long)]
        user: Option<u32>,
        /// User tunmux configuration directory (defaults to that user's ~/.config/tunmux)
        #[arg(long)]
        config_dir: Option<std::path::PathBuf>,
    },
    /// Disconnect managed sessions and reload the service
    Reload,
    /// Report installation, launchd, socket, and recovery state
    Diagnose,
    /// Disconnect and remove installed service artifacts; requires root
    Uninstall,
}

#[derive(Subcommand)]
pub enum AutoconnectCommand {
    /// Persist a desired connection and install the login agent
    Enable {
        name: String,
        /// Persist desired state without installing the login agent
        #[arg(long)]
        no_login_agent: bool,
        /// A connect command, for example: -- connect wgconf --profile work
        #[arg(last = true, required = true)]
        args: Vec<String>,
    },
    /// Suspend entries until explicitly resumed
    Disable {
        name: Option<String>,
        #[arg(long, conflicts_with = "name", required_unless_present = "name")]
        all: bool,
    },
    /// Resume entries and reset retry exhaustion
    Resume {
        name: Option<String>,
        #[arg(long, conflicts_with = "name", required_unless_present = "name")]
        all: bool,
    },
    Status,
    /// Run the reconnect controller in the foreground
    Run,
}

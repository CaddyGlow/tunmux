//! View types the GUI renders. They mirror the planned `tunmux::api` data
//! types so the mock backend can later be swapped for the real library.

use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Proton,
    AirVpn,
    Mullvad,
    Ivpn,
    WgConf,
}

impl From<tunmux::config::Provider> for Provider {
    fn from(p: tunmux::config::Provider) -> Self {
        match p {
            tunmux::config::Provider::Proton => Provider::Proton,
            tunmux::config::Provider::AirVpn => Provider::AirVpn,
            tunmux::config::Provider::Mullvad => Provider::Mullvad,
            tunmux::config::Provider::Ivpn => Provider::Ivpn,
            tunmux::config::Provider::Wgconf => Provider::WgConf,
        }
    }
}

impl From<Provider> for tunmux::config::Provider {
    fn from(p: Provider) -> Self {
        match p {
            Provider::Proton => tunmux::config::Provider::Proton,
            Provider::AirVpn => tunmux::config::Provider::AirVpn,
            Provider::Mullvad => tunmux::config::Provider::Mullvad,
            Provider::Ivpn => tunmux::config::Provider::Ivpn,
            Provider::WgConf => tunmux::config::Provider::Wgconf,
        }
    }
}

impl Provider {
    /// Map the provider directory name saved in `ConnectionState::provider`.
    pub fn from_dir_name(name: &str) -> Option<Self> {
        Some(match name {
            "proton" => Provider::Proton,
            "airvpn" => Provider::AirVpn,
            "mullvad" => Provider::Mullvad,
            "ivpn" => Provider::Ivpn,
            "wgconf" => Provider::WgConf,
            _ => return None,
        })
    }

    pub const ALL: [Provider; 5] = [
        Provider::Proton,
        Provider::AirVpn,
        Provider::Mullvad,
        Provider::Ivpn,
        Provider::WgConf,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Provider::Proton => "Proton",
            Provider::AirVpn => "AirVPN",
            Provider::Mullvad => "Mullvad",
            Provider::Ivpn => "IVPN",
            Provider::WgConf => "WG config",
        }
    }

    pub fn has_load(self) -> bool {
        !matches!(self, Provider::Mullvad | Provider::WgConf)
    }

    pub fn has_score(self) -> bool {
        matches!(self, Provider::Proton | Provider::AirVpn)
    }

    pub fn needs_account(self) -> bool {
        !matches!(self, Provider::WgConf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Direct,
    NetnsProxy,
    LocalProxy,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Direct => "Direct",
            Mode::NetnsProxy => "Proxy (netns)",
            Mode::LocalProxy => "Local proxy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Auto,
    Kernel,
    WgQuick,
    Userspace,
}

impl Backend {
    pub const ALL: [Backend; 4] = [
        Backend::Auto,
        Backend::Kernel,
        Backend::WgQuick,
        Backend::Userspace,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Backend::Auto => "auto",
            Backend::Kernel => "kernel",
            Backend::WgQuick => "wg-quick",
            Backend::Userspace => "userspace",
        }
    }
}

/// Non-clap counterpart of `cli::ConnectOptions`.
#[derive(Debug, Clone)]
pub struct ConnectSpec {
    pub mode: Mode,
    pub backend: Backend,
    pub disable_ipv6: bool,
    pub mtu: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub allow_lan: bool,
    pub access_log: bool,
}

impl ConnectSpec {
    /// Library connect arguments for `server`.
    pub fn to_api(&self, server: &str) -> tunmux::api::ConnectSpec {
        tunmux::api::ConnectSpec {
            server: Some(server.to_string()),
            country: None,
            mode: match self.mode {
                Mode::Direct => tunmux::api::ConnectMode::Direct,
                Mode::NetnsProxy => tunmux::api::ConnectMode::NamespaceProxy,
                Mode::LocalProxy => tunmux::api::ConnectMode::LocalProxy,
            },
            backend: (self.backend != Backend::Auto).then(|| self.backend.label().to_string()),
            disable_ipv6: self.disable_ipv6,
            mtu: self.mtu,
            socks_port: self.socks_port,
            http_port: self.http_port,
            allow_lan: self.allow_lan,
            proxy_access_log: self.access_log,
        }
    }
}

impl Default for ConnectSpec {
    fn default() -> Self {
        Self {
            mode: Mode::Direct,
            backend: Backend::Auto,
            disable_ipv6: false,
            mtu: None,
            socks_port: None,
            http_port: None,
            allow_lan: false,
            access_log: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerView {
    pub provider: Provider,
    pub name: String,
    pub country_code: String,
    pub city: String,
    pub load: Option<f32>,
    pub score: Option<f64>,
    pub tags: Vec<String>,
    pub ping_ms: Option<u32>,
}

impl From<tunmux::api::ServerInfo> for ServerView {
    fn from(s: tunmux::api::ServerInfo) -> Self {
        Self {
            provider: s.provider.into(),
            name: s.name,
            country_code: s.country_code,
            city: s.city,
            load: s.load,
            score: s.score,
            tags: s.tags,
            ping_ms: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Connecting,
    Active,
    Inactive,
    Unknown,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Health::Connecting => "connecting",
            Health::Active => "active",
            Health::Inactive => "inactive",
            Health::Unknown => "unknown",
        }
    }
}

/// One saved `ConnectionState` plus its `ConnectionHealth`.
#[derive(Debug, Clone)]
pub struct ConnectionView {
    pub instance: String,
    pub provider: Provider,
    pub server: String,
    pub country_code: String,
    pub city: String,
    pub mode: Mode,
    pub backend: String,
    pub virtual_ip: String,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub health: Health,
    pub health_reason: Option<String>,
    pub since: SystemTime,
    /// Traffic counters, when the source can report them.
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

impl ConnectionView {
    pub fn is_direct(&self) -> bool {
        self.instance == tunmux::wireguard::connection::DIRECT_INSTANCE
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginState {
    LoggedOut,
    /// Credentials accepted, waiting for a second factor.
    NeedsTwoFactor,
    LoggedIn {
        account: String,
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub struct AccountView {
    pub provider: Provider,
    pub state: LoginState,
    pub servers_cached: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Country,
    Load,
    Score,
    Ping,
}

/// Overall state shown by the tray icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Disconnected,
    Connecting,
    Direct,
    ProxiesOnly,
    Degraded,
}

impl TrayState {
    pub fn from_connections(conns: &[ConnectionView]) -> Self {
        if conns.is_empty() {
            return TrayState::Disconnected;
        }
        // Unknown is not evidence of failure (netns proxies are always
        // unknown), so only an observed inactive tunnel degrades the icon.
        if conns.iter().any(|c| c.health == Health::Inactive) {
            return TrayState::Degraded;
        }
        if conns.iter().any(|c| c.health == Health::Connecting) {
            return TrayState::Connecting;
        }
        if conns.iter().any(ConnectionView::is_direct) {
            TrayState::Direct
        } else {
            TrayState::ProxiesOnly
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TrayState::Disconnected => "Disconnected",
            TrayState::Connecting => "Connecting",
            TrayState::Direct => "Connected",
            TrayState::ProxiesOnly => "Proxies only",
            TrayState::Degraded => "Degraded",
        }
    }
}

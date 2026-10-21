//! Data the window shows. `Store::sample()` fills it with sample data for
//! reviewing the interface (`--mock`), where connections take a moment to come
//! up so the transient states are visible. In live mode `Store::empty()` is
//! filled with accounts and servers from the library.

use std::time::{Duration, Instant, SystemTime};

use crate::model::{
    AccountView, Backend, ConnectSpec, ConnectionView, Health, LoginState, Mode, Provider,
    ServerView,
};

const CONNECT_DELAY: Duration = Duration::from_millis(1500);

pub enum ConnectError {
    /// An instance with this name already runs; the caller may replace it.
    InstanceExists(String),
    NotLoggedIn(Provider),
}

pub struct AirPort {
    pub port: u16,
    pub protocol: &'static str,
    pub device: &'static str,
    pub enabled: bool,
}

pub struct ProtonForward {
    pub instance: String,
    pub port: u16,
    pub expires_in: Duration,
}

pub struct WgProfile {
    pub name: String,
    pub endpoint: String,
}

pub struct Store {
    pub accounts: Vec<AccountView>,
    pub servers: Vec<ServerView>,
    pub connections: Vec<ConnectionView>,
    pub recent: Vec<(Provider, String, Mode)>,
    pub air_ports: Vec<AirPort>,
    pub air_devices: Vec<&'static str>,
    pub air_api_keys: Vec<&'static str>,
    pub proton_forwards: Vec<ProtonForward>,
    pub wg_profiles: Vec<WgProfile>,
    pub corrupt_states: Vec<String>,
    last_tick: Instant,
}

impl Store {
    /// No sample data; live mode fills accounts and servers.
    pub fn empty() -> Self {
        Self {
            accounts: Provider::ALL
                .into_iter()
                .map(|provider| AccountView {
                    provider,
                    state: LoginState::LoggedOut,
                    servers_cached: 0,
                })
                .collect(),
            servers: Vec::new(),
            connections: Vec::new(),
            recent: Vec::new(),
            air_ports: Vec::new(),
            air_devices: Vec::new(),
            air_api_keys: Vec::new(),
            proton_forwards: Vec::new(),
            wg_profiles: Vec::new(),
            corrupt_states: Vec::new(),
            last_tick: Instant::now(),
        }
    }

    pub fn set_accounts(&mut self, infos: Vec<tunmux::api::AccountInfo>) {
        for info in infos {
            let provider = Provider::from(info.provider);
            let acc = self.account_mut(provider);
            acc.state = match info.account {
                Some(account) => LoginState::LoggedIn {
                    account,
                    detail: info.detail,
                },
                // Keep a 2FA prompt open until the user finishes or cancels.
                None if acc.state == LoginState::NeedsTwoFactor => LoginState::NeedsTwoFactor,
                None => LoginState::LoggedOut,
            };
        }
        self.refresh_counts();
    }

    pub fn set_servers(&mut self, provider: Provider, servers: Vec<ServerView>) {
        self.servers.retain(|s| s.provider != provider);
        self.servers.extend(servers);
        self.refresh_counts();
    }

    pub fn set_two_factor(&mut self, provider: Provider) {
        self.account_mut(provider).state = LoginState::NeedsTwoFactor;
    }

    pub fn add_recent(&mut self, provider: Provider, server: &str, mode: Mode) {
        self.recent
            .retain(|(p, s, m)| !(*p == provider && s == server && *m == mode));
        self.recent.insert(0, (provider, server.to_string(), mode));
        self.recent.truncate(5);
    }

    pub fn sample() -> Self {
        let mut me = Self {
            accounts: vec![
                logged_in(
                    Provider::Proton,
                    "rick@proton.me",
                    "Plus, expires 2027-03-01",
                ),
                logged_in(Provider::AirVpn, "rick", "Premium, 214 days left"),
                AccountView {
                    provider: Provider::Mullvad,
                    state: LoginState::LoggedOut,
                    servers_cached: 0,
                },
                AccountView {
                    provider: Provider::Ivpn,
                    state: LoginState::LoggedOut,
                    servers_cached: 0,
                },
                logged_in(Provider::WgConf, "local", "2 saved profiles"),
            ],
            servers: fake_servers(),
            connections: Vec::new(),
            recent: vec![
                (Provider::AirVpn, "Hydrus".into(), Mode::Direct),
                (Provider::Proton, "CH#12".into(), Mode::LocalProxy),
            ],
            air_ports: vec![
                AirPort {
                    port: 41337,
                    protocol: "tcp+udp",
                    device: "laptop",
                    enabled: true,
                },
                AirPort {
                    port: 51820,
                    protocol: "udp",
                    device: "default",
                    enabled: false,
                },
            ],
            air_devices: vec!["default", "laptop", "phone"],
            air_api_keys: vec!["tunmux-gui (read)", "homelab"],
            proton_forwards: Vec::new(),
            wg_profiles: vec![
                WgProfile {
                    name: "home".into(),
                    endpoint: "vpn.example.net:51820".into(),
                },
                WgProfile {
                    name: "office".into(),
                    endpoint: "203.0.113.7:51820".into(),
                },
            ],
            corrupt_states: Vec::new(),
            last_tick: Instant::now(),
        };
        me.refresh_counts();
        // Start with something on screen: one direct tunnel and one proxy.
        let hydrus = me.find_server(Provider::AirVpn, "Hydrus").cloned();
        if let Some(s) = hydrus {
            let _ = me.connect(&s, &ConnectSpec::default(), false);
        }
        let ch = me.find_server(Provider::Proton, "CH#12").cloned();
        if let Some(s) = ch {
            let spec = ConnectSpec {
                mode: Mode::LocalProxy,
                ..ConnectSpec::default()
            };
            let _ = me.connect(&s, &spec, false);
        }
        for c in &mut me.connections {
            c.health = Health::Active;
            c.since = SystemTime::now() - Duration::from_secs(4333);
        }
        me
    }

    fn refresh_counts(&mut self) {
        for acc in &mut self.accounts {
            acc.servers_cached = if matches!(acc.state, LoginState::LoggedIn { .. }) {
                self.servers
                    .iter()
                    .filter(|s| s.provider == acc.provider)
                    .count()
            } else {
                0
            };
        }
    }

    pub fn account(&self, provider: Provider) -> &AccountView {
        self.accounts
            .iter()
            .find(|a| a.provider == provider)
            .expect("every provider has an account entry")
    }

    fn account_mut(&mut self, provider: Provider) -> &mut AccountView {
        self.accounts
            .iter_mut()
            .find(|a| a.provider == provider)
            .expect("every provider has an account entry")
    }

    pub fn is_logged_in(&self, provider: Provider) -> bool {
        matches!(self.account(provider).state, LoginState::LoggedIn { .. })
    }

    pub fn find_server(&self, provider: Provider, name: &str) -> Option<&ServerView> {
        self.servers
            .iter()
            .find(|s| s.provider == provider && s.name == name)
    }

    /// Advance simulated connections and traffic counters.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64();
        self.last_tick = now;
        for c in &mut self.connections {
            let age = c.since.elapsed().unwrap_or_default();
            if c.health == Health::Connecting && age >= CONNECT_DELAY {
                c.health = Health::Active;
                c.since = SystemTime::now();
            }
            if c.health == Health::Active {
                c.rx_bytes = Some(c.rx_bytes.unwrap_or(0) + (dt * 380_000.0) as u64);
                c.tx_bytes = Some(c.tx_bytes.unwrap_or(0) + (dt * 42_000.0) as u64);
            }
        }
    }

    pub fn is_busy(&self) -> bool {
        self.connections
            .iter()
            .any(|c| c.health == Health::Connecting)
    }

    pub fn instance_name(server: &ServerView, mode: Mode) -> String {
        match mode {
            Mode::Direct => "_direct".into(),
            Mode::NetnsProxy | Mode::LocalProxy => server
                .name
                .to_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(12)
                .collect(),
        }
    }

    pub fn connect(
        &mut self,
        server: &ServerView,
        spec: &ConnectSpec,
        replace: bool,
    ) -> Result<String, ConnectError> {
        if server.provider.needs_account() && !self.is_logged_in(server.provider) {
            return Err(ConnectError::NotLoggedIn(server.provider));
        }
        let instance = Self::instance_name(server, spec.mode);
        if self.connections.iter().any(|c| c.instance == instance) {
            if !replace {
                return Err(ConnectError::InstanceExists(instance));
            }
            self.disconnect(&instance);
        }
        let (socks_port, http_port) = if spec.mode == Mode::Direct {
            (None, None)
        } else {
            (
                Some(
                    spec.socks_port
                        .unwrap_or_else(|| self.free_port(1080, |c| c.socks_port)),
                ),
                Some(
                    spec.http_port
                        .unwrap_or_else(|| self.free_port(8118, |c| c.http_port)),
                ),
            )
        };
        let n = self.connections.len() as u8 + 2;
        self.connections.push(ConnectionView {
            instance: instance.clone(),
            provider: server.provider,
            server: server.name.clone(),
            country_code: server.country_code.clone(),
            city: server.city.clone(),
            mode: spec.mode,
            backend: if spec.mode == Mode::LocalProxy {
                "local-proxy"
            } else if spec.backend == Backend::Auto {
                Backend::Kernel.label()
            } else {
                spec.backend.label()
            }
            .into(),
            virtual_ip: format!("10.{}.0.{}", 64 + n, n),
            socks_port,
            http_port,
            health: Health::Connecting,
            health_reason: None,
            since: SystemTime::now(),
            rx_bytes: None,
            tx_bytes: None,
        });
        // Direct first, then proxies in connect order.
        self.connections.sort_by_key(|c| !c.is_direct());
        self.add_recent(server.provider, &server.name, spec.mode);
        Ok(instance)
    }

    fn free_port(&self, start: u16, get: impl Fn(&ConnectionView) -> Option<u16>) -> u16 {
        (start..)
            .find(|p| !self.connections.iter().any(|c| get(c) == Some(*p)))
            .unwrap_or(start)
    }

    pub fn disconnect(&mut self, instance: &str) {
        self.connections.retain(|c| c.instance != instance);
    }

    pub fn disconnect_all(&mut self) {
        self.connections.clear();
    }

    /// Simulate a tunnel whose health can no longer be confirmed.
    pub fn degrade_first(&mut self, health: Health, reason: &str) {
        if let Some(c) = self.connections.first_mut() {
            c.health = health;
            c.health_reason = Some(reason.into());
        }
    }

    pub fn degrade_last(&mut self, health: Health, reason: &str) {
        if let Some(c) = self.connections.last_mut() {
            c.health = health;
            c.health_reason = Some(reason.into());
        }
    }

    pub fn recover(&mut self, instance: &str) {
        if let Some(c) = self.connections.iter_mut().find(|c| c.instance == instance) {
            c.health = Health::Connecting;
            c.health_reason = None;
            c.since = SystemTime::now();
        }
    }

    pub fn probe_pings(&mut self, provider: Provider) {
        for (i, s) in self
            .servers
            .iter_mut()
            .filter(|s| s.provider == provider)
            .enumerate()
        {
            let base: u32 = match s.country_code.as_str() {
                "CH" | "DE" | "NL" | "FR" => 8,
                "SE" | "GB" => 25,
                "US" | "CA" => 95,
                _ => 160,
            };
            s.ping_ms = Some(base + (i as u32 * 7) % 19);
        }
    }

    /// Returns `true` when the provider wants a second factor next.
    pub fn login(&mut self, provider: Provider, user: &str, secret: &str) -> Result<bool, String> {
        if user.trim().is_empty() {
            return Err("account is required".into());
        }
        if matches!(provider, Provider::Proton | Provider::AirVpn) && secret.is_empty() {
            return Err("password is required".into());
        }
        if secret == "wrong" {
            return Err("authentication failed: invalid credentials".into());
        }
        if matches!(provider, Provider::Proton | Provider::Ivpn) {
            self.account_mut(provider).state = LoginState::NeedsTwoFactor;
            return Ok(true);
        }
        self.finish_login(provider, user);
        Ok(false)
    }

    pub fn submit_two_factor(
        &mut self,
        provider: Provider,
        user: &str,
        code: &str,
    ) -> Result<(), String> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err("enter the 6-digit code".into());
        }
        self.finish_login(provider, user);
        Ok(())
    }

    fn finish_login(&mut self, provider: Provider, user: &str) {
        let detail = match provider {
            Provider::Mullvad => "Paid until 2026-12-30",
            Provider::Ivpn => "Pro, 5 devices",
            _ => "Plan active",
        };
        self.account_mut(provider).state = LoginState::LoggedIn {
            account: user.to_string(),
            detail: detail.into(),
        };
        self.refresh_counts();
    }

    pub fn cancel_login(&mut self, provider: Provider) {
        self.account_mut(provider).state = LoginState::LoggedOut;
    }

    pub fn logout(&mut self, provider: Provider) {
        self.connections.retain(|c| c.provider != provider);
        self.account_mut(provider).state = LoginState::LoggedOut;
        self.refresh_counts();
    }

    pub fn proton_forward(&mut self) {
        if let Some(c) = self
            .connections
            .iter()
            .find(|c| c.provider == Provider::Proton)
        {
            let instance = c.instance.clone();
            self.proton_forwards.push(ProtonForward {
                instance,
                port: 47000 + self.proton_forwards.len() as u16 * 13,
                expires_in: Duration::from_secs(60),
            });
        }
    }
}

fn logged_in(provider: Provider, account: &str, detail: &str) -> AccountView {
    AccountView {
        provider,
        state: LoginState::LoggedIn {
            account: account.into(),
            detail: detail.into(),
        },
        servers_cached: 0,
    }
}

fn fake_servers() -> Vec<ServerView> {
    #[allow(clippy::type_complexity)]
    let rows: &[(
        Provider,
        &str,
        &str,
        &str,
        Option<f32>,
        Option<f64>,
        &[&str],
    )] = &[
        (
            Provider::AirVpn,
            "Hydrus",
            "CH",
            "Zurich",
            Some(23.0),
            Some(0.41),
            &[],
        ),
        (
            Provider::AirVpn,
            "Alchiba",
            "CH",
            "Zurich",
            Some(41.0),
            Some(0.58),
            &[],
        ),
        (
            Provider::AirVpn,
            "Castor",
            "NL",
            "Amsterdam",
            Some(64.0),
            Some(0.77),
            &[],
        ),
        (
            Provider::AirVpn,
            "Mirfak",
            "DE",
            "Frankfurt",
            Some(12.0),
            Some(0.30),
            &["ipv6"],
        ),
        (
            Provider::AirVpn,
            "Elnath",
            "US",
            "New York",
            Some(55.0),
            Some(0.69),
            &["ipv6"],
        ),
        (
            Provider::AirVpn,
            "Sargas",
            "SE",
            "Stockholm",
            Some(8.0),
            Some(0.22),
            &[],
        ),
        (
            Provider::Proton,
            "CH#12",
            "CH",
            "Zurich",
            Some(31.0),
            Some(1.08),
            &["p2p", "streaming"],
        ),
        (
            Provider::Proton,
            "CH#3-SC",
            "CH",
            "Zurich",
            Some(18.0),
            Some(2.41),
            &["secure-core"],
        ),
        (
            Provider::Proton,
            "NL#88",
            "NL",
            "Amsterdam",
            Some(47.0),
            Some(1.33),
            &["p2p"],
        ),
        (
            Provider::Proton,
            "DE#204",
            "DE",
            "Berlin",
            Some(72.0),
            Some(1.90),
            &["streaming"],
        ),
        (
            Provider::Proton,
            "US-NY#61",
            "US",
            "New York",
            Some(29.0),
            Some(1.12),
            &["p2p", "tor"],
        ),
        (
            Provider::Proton,
            "JP#9",
            "JP",
            "Tokyo",
            Some(15.0),
            Some(1.04),
            &[],
        ),
        (
            Provider::Mullvad,
            "ch-zrh-wg-001",
            "CH",
            "Zurich",
            None,
            None,
            &[],
        ),
        (
            Provider::Mullvad,
            "se-got-wg-002",
            "SE",
            "Gothenburg",
            None,
            None,
            &["owned"],
        ),
        (
            Provider::Mullvad,
            "nl-ams-wg-004",
            "NL",
            "Amsterdam",
            None,
            None,
            &[],
        ),
        (
            Provider::Mullvad,
            "us-nyc-wg-301",
            "US",
            "New York",
            None,
            None,
            &[],
        ),
        (
            Provider::Ivpn,
            "ch1.wg.ivpn.net",
            "CH",
            "Zurich",
            Some(35.0),
            None,
            &[],
        ),
        (
            Provider::Ivpn,
            "nl4.wg.ivpn.net",
            "NL",
            "Amsterdam",
            Some(22.0),
            None,
            &[],
        ),
        (
            Provider::Ivpn,
            "ca-qc1.wg.ivpn.net",
            "CA",
            "Montreal",
            Some(9.0),
            None,
            &[],
        ),
        (
            Provider::WgConf,
            "home",
            "--",
            "vpn.example.net",
            None,
            None,
            &[],
        ),
        (
            Provider::WgConf,
            "office",
            "--",
            "203.0.113.7",
            None,
            None,
            &[],
        ),
    ];
    rows.iter()
        .map(
            |&(provider, name, cc, city, load, score, tags)| ServerView {
                provider,
                name: name.into(),
                country_code: cc.into(),
                city: city.into(),
                load,
                score,
                tags: tags.iter().map(|t| t.to_string()).collect(),
                ping_ms: None,
            },
        )
        .collect()
}

//! Data-returning entry points for front-ends such as the desktop GUI.
//!
//! The CLI prompts and prints around the same provider code. Functions here
//! never read from the terminal. Connect, disconnect, logout and AirVPN login
//! run the CLI paths, so their progress lines still go to stdout.

mod system;
mod tools;

pub use system::*;
pub use tools::*;

use crate::cli::ConnectOptions;
use crate::config::{AppConfig, Provider};
use crate::wireguard::connection::ConnectionState;

/// One server as offered to the user.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub provider: Provider,
    /// Name accepted by `connect` (`ConnectSpec::server`).
    pub name: String,
    pub country_code: String,
    pub city: String,
    /// Load in percent, when the provider reports it.
    pub load: Option<f32>,
    /// Provider score, lower is better, when the provider reports it.
    pub score: Option<f64>,
    pub tags: Vec<String>,
}

/// Saved login state of one provider, read without network access.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub provider: Provider,
    /// Account shown to the user; `None` when logged out.
    pub account: Option<String>,
    /// Plan or expiry details.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    LoggedIn {
        account: String,
        detail: String,
    },
    /// The provider asked for a TOTP code; call `login` again with it.
    NeedsTwoFactor,
}

#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// Username, account number or account ID.
    pub account: String,
    /// Password, for providers that use one; empty otherwise.
    pub password: String,
    /// TOTP code, once `login` returned `NeedsTwoFactor`.
    pub two_factor: Option<String>,
    /// Mullvad: replace a different saved account ID (the CLI asks).
    pub replace_saved_account: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectMode {
    #[default]
    Direct,
    /// Kernel WireGuard in a network namespace with SOCKS5/HTTP (`--proxy`).
    NamespaceProxy,
    /// Rootless userspace tunnel with SOCKS5/HTTP (`--local-proxy`).
    LocalProxy,
}

/// Non-clap counterpart of the provider connect arguments.
#[derive(Debug, Clone, Default)]
pub struct ConnectSpec {
    /// Server name from `servers`; `None` picks one like the CLI does.
    pub server: Option<String>,
    pub country: Option<String>,
    pub mode: ConnectMode,
    pub backend: Option<String>,
    pub disable_ipv6: bool,
    pub mtu: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub allow_lan: bool,
    pub proxy_access_log: bool,
}

impl ConnectSpec {
    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            if_missing: false,
            allow_lan: self.allow_lan,
            backend: self.backend.clone(),
            proxy: self.mode == ConnectMode::NamespaceProxy,
            local_proxy: self.mode == ConnectMode::LocalProxy,
            disable_ipv6: self.disable_ipv6,
            mtu: self.mtu,
            socks_port: self.socks_port,
            http_port: self.http_port,
            proxy_access_log: self.proxy_access_log,
        }
    }
}

/// Providers compiled into this build.
#[must_use]
pub fn providers() -> Vec<Provider> {
    [
        Provider::Proton,
        Provider::AirVpn,
        Provider::Mullvad,
        Provider::Ivpn,
        Provider::Wgconf,
    ]
    .into_iter()
    .filter(|p| match p {
        Provider::Proton => cfg!(feature = "proton"),
        Provider::AirVpn => cfg!(feature = "airvpn"),
        Provider::Mullvad => cfg!(feature = "mullvad"),
        Provider::Ivpn => cfg!(feature = "ivpn"),
        Provider::Wgconf => cfg!(feature = "wgconf"),
    })
    .collect()
}

/// Saved login state of every compiled provider.
#[must_use]
pub fn accounts(config: &AppConfig) -> Vec<AccountInfo> {
    providers()
        .into_iter()
        .map(|provider| account(provider, config))
        .collect()
}

fn account(provider: Provider, config: &AppConfig) -> AccountInfo {
    if provider == Provider::Wgconf {
        #[cfg(feature = "wgconf")]
        let profiles = crate::wgconf::handlers::profile_names()
            .map(|p| p.len())
            .unwrap_or(0);
        #[cfg(not(feature = "wgconf"))]
        let profiles = 0;
        return AccountInfo {
            provider,
            account: Some("local".into()),
            detail: format!("{profiles} saved profile(s)"),
        };
    }
    // Sessions are read as plain JSON so private session types stay private.
    let Ok(session) = crate::config::load_session::<serde_json::Value>(provider, config) else {
        return AccountInfo {
            provider,
            account: None,
            detail: String::new(),
        };
    };
    let field = |name: &str| {
        session
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (account, detail) = match provider {
        Provider::Proton => (field("vpn_username"), field("plan_title")),
        Provider::AirVpn => (field("username"), String::new()),
        Provider::Mullvad => (
            field("account_number"),
            format!("expires {}", field("account_expiry")),
        ),
        Provider::Ivpn => {
            let active = session
                .get("account_active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            (
                field("account_id"),
                if active { "active" } else { "inactive" }.into(),
            )
        }
        Provider::Wgconf => unreachable!("handled above"),
    };
    AccountInfo {
        provider,
        account: Some(account),
        detail,
    }
}

fn not_compiled(provider: Provider) -> anyhow::Error {
    anyhow::anyhow!("{} support is not compiled in", provider.label())
}

/// Servers from the cached list, fetching it when the provider allows.
pub async fn servers(provider: Provider, config: &AppConfig) -> anyhow::Result<Vec<ServerInfo>> {
    match provider {
        #[cfg(feature = "proton")]
        Provider::Proton => crate::proton::handlers::server_list(config).await,
        #[cfg(feature = "airvpn")]
        Provider::AirVpn => crate::airvpn::handlers::server_list(),
        #[cfg(feature = "mullvad")]
        Provider::Mullvad => crate::mullvad::handlers::server_list().await,
        #[cfg(feature = "ivpn")]
        Provider::Ivpn => crate::ivpn::handlers::server_list().await,
        #[cfg(feature = "wgconf")]
        Provider::Wgconf => crate::wgconf::handlers::server_list(),
        #[allow(unreachable_patterns)]
        _ => {
            let _ = config;
            Err(not_compiled(provider))
        }
    }
}

/// Log in without prompting. Proton and IVPN may answer `NeedsTwoFactor`.
pub async fn login(
    provider: Provider,
    credentials: &Credentials,
    config: &AppConfig,
) -> anyhow::Result<LoginOutcome> {
    let code = credentials.two_factor.clone();
    let mut two_factor = move || -> anyhow::Result<Option<String>> { Ok(code.clone()) };
    match provider {
        #[cfg(feature = "proton")]
        Provider::Proton => {
            crate::proton::handlers::login(
                &credentials.account,
                &credentials.password,
                &mut two_factor,
                config,
            )
            .await
        }
        #[cfg(feature = "airvpn")]
        Provider::AirVpn => {
            crate::airvpn::handlers::login(&credentials.account, &credentials.password, config)
                .await
        }
        #[cfg(feature = "mullvad")]
        Provider::Mullvad => {
            crate::mullvad::handlers::login(
                &credentials.account,
                credentials.replace_saved_account,
                config,
            )
            .await
        }
        #[cfg(feature = "ivpn")]
        Provider::Ivpn => {
            crate::ivpn::handlers::login(&credentials.account, &mut two_factor, config).await
        }
        Provider::Wgconf => anyhow::bail!("WireGuard config profiles need no login"),
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (&mut two_factor, config);
            Err(not_compiled(provider))
        }
    }
}

/// Log out, disconnecting the provider's tunnels like the CLI does.
pub async fn logout(provider: Provider, config: &AppConfig) -> anyhow::Result<()> {
    match provider {
        #[cfg(feature = "proton")]
        Provider::Proton => {
            crate::proton::handlers::dispatch(crate::cli::ProtonCommand::Logout, config).await
        }
        #[cfg(feature = "airvpn")]
        Provider::AirVpn => {
            crate::airvpn::handlers::dispatch(crate::cli::AirVpnCommand::Logout, config).await
        }
        #[cfg(feature = "mullvad")]
        Provider::Mullvad => {
            crate::mullvad::handlers::dispatch(crate::cli::MullvadCommand::Logout, config).await
        }
        #[cfg(feature = "ivpn")]
        Provider::Ivpn => {
            crate::ivpn::handlers::dispatch(crate::cli::IvpnCommand::Logout, config).await
        }
        Provider::Wgconf => anyhow::bail!("WireGuard config profiles need no login"),
        #[allow(unreachable_patterns)]
        _ => {
            let _ = config;
            Err(not_compiled(provider))
        }
    }
}

/// Connect through the same path as `tunmux connect <provider>`.
pub async fn connect(
    provider: Provider,
    spec: &ConnectSpec,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let opts = spec.options();
    match provider {
        #[cfg(feature = "proton")]
        Provider::Proton => {
            let args = crate::cli::ProtonConnectArgs {
                server: spec.server.clone(),
                country: spec.country.clone(),
                p2p: false,
                port_forwarding: false,
                sort: "score".into(),
                opts,
            };
            crate::proton::handlers::dispatch(crate::cli::ProtonCommand::Connect(args), config)
                .await
        }
        #[cfg(feature = "airvpn")]
        Provider::AirVpn => {
            let args = crate::cli::AirVpnConnectArgs {
                server: spec.server.clone(),
                country: spec.country.clone(),
                key: None,
                sort: "score".into(),
                opts,
            };
            crate::airvpn::handlers::dispatch(crate::cli::AirVpnCommand::Connect(args), config)
                .await
        }
        #[cfg(feature = "mullvad")]
        Provider::Mullvad => {
            let args = crate::cli::MullvadConnectArgs {
                server: spec.server.clone(),
                country: spec.country.clone(),
                sort: "name".into(),
                opts,
            };
            crate::mullvad::handlers::dispatch(crate::cli::MullvadCommand::Connect(args), config)
                .await
        }
        #[cfg(feature = "ivpn")]
        Provider::Ivpn => {
            let args = crate::cli::IvpnConnectArgs {
                server: spec.server.clone(),
                country: spec.country.clone(),
                sort: "load".into(),
                opts,
            };
            crate::ivpn::handlers::dispatch(crate::cli::IvpnCommand::Connect(args), config).await
        }
        #[cfg(feature = "wgconf")]
        Provider::Wgconf => {
            let profile = spec
                .server
                .clone()
                .ok_or_else(|| anyhow::anyhow!("choose a WireGuard profile"))?;
            let args = crate::cli::WgconfConnectArgs {
                socks_port: opts.socks_port,
                http_port: opts.http_port,
                if_missing: false,
                allow_lan: opts.allow_lan,
                file: None,
                profile: Some(profile),
                save_as: None,
                backend: opts.backend,
                proxy: opts.proxy,
                local_proxy: opts.local_proxy,
                disable_ipv6: opts.disable_ipv6,
                mtu: opts.mtu,
            };
            crate::wgconf::handlers::dispatch(crate::cli::WgconfCommand::Connect(args), config)
                .await
        }
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (opts, config);
            Err(not_compiled(provider))
        }
    }
}

/// Disconnect one saved instance through its provider's CLI path.
pub async fn disconnect(instance: &str, config: &AppConfig) -> anyhow::Result<()> {
    let state = ConnectionState::load(instance)?
        .ok_or_else(|| anyhow::anyhow!("no connection with instance {instance:?}"))?;
    let provider = Provider::from_dir_name(&state.provider).ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported provider in connection state: {}",
            state.provider
        )
    })?;
    let instance = Some(instance.to_string());
    match provider {
        #[cfg(feature = "proton")]
        Provider::Proton => {
            let command = crate::cli::ProtonCommand::Disconnect {
                instance,
                all: false,
            };
            crate::proton::handlers::dispatch(command, config).await
        }
        #[cfg(feature = "airvpn")]
        Provider::AirVpn => {
            let command = crate::cli::AirVpnCommand::Disconnect {
                instance,
                all: false,
            };
            crate::airvpn::handlers::dispatch(command, config).await
        }
        #[cfg(feature = "mullvad")]
        Provider::Mullvad => {
            let command = crate::cli::MullvadCommand::Disconnect {
                instance,
                all: false,
            };
            crate::mullvad::handlers::dispatch(command, config).await
        }
        #[cfg(feature = "ivpn")]
        Provider::Ivpn => {
            let command = crate::cli::IvpnCommand::Disconnect {
                instance,
                all: false,
            };
            crate::ivpn::handlers::dispatch(command, config).await
        }
        #[cfg(feature = "wgconf")]
        Provider::Wgconf => {
            let command = crate::cli::WgconfCommand::Disconnect {
                instance,
                all: false,
            };
            crate::wgconf::handlers::dispatch(command, config).await
        }
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (instance, config);
            Err(not_compiled(provider))
        }
    }
}

/// Disconnect every saved instance, continuing past failures.
pub async fn disconnect_all(config: &AppConfig) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for state in ConnectionState::load_all()? {
        if let Err(error) = disconnect(&state.instance_name, config).await {
            errors.push(format!("{}: {error:#}", state.instance_name));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{env_lock, unique_test_dir};
    use crate::config::CredentialStore;

    #[test]
    fn connect_spec_maps_modes_to_cli_options() {
        let spec = ConnectSpec {
            mode: ConnectMode::LocalProxy,
            backend: Some("userspace".into()),
            mtu: Some(1380),
            socks_port: Some(1090),
            http_port: Some(8120),
            allow_lan: true,
            ..ConnectSpec::default()
        };
        let opts = spec.options();
        assert!(opts.local_proxy && !opts.proxy);
        assert_eq!(opts.backend.as_deref(), Some("userspace"));
        assert_eq!(
            (opts.mtu, opts.socks_port, opts.http_port),
            (Some(1380), Some(1090), Some(8120))
        );
        assert!(opts.allow_lan && !opts.if_missing);

        let netns = ConnectSpec {
            mode: ConnectMode::NamespaceProxy,
            ..ConnectSpec::default()
        }
        .options();
        assert!(netns.proxy && !netns.local_proxy);
        let direct = ConnectSpec::default().options();
        assert!(!direct.proxy && !direct.local_proxy);
    }

    #[test]
    fn accounts_reads_saved_sessions_without_network() {
        let _guard = env_lock().lock().expect("test env lock poisoned");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let dir = unique_test_dir("api-accounts");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut config = AppConfig::default();
        config.general.credential_store = CredentialStore::File;
        let saved = [
            (Provider::AirVpn, serde_json::json!({ "username": "alice" })),
            (
                Provider::Mullvad,
                serde_json::json!({ "account_number": "1234", "account_expiry": "2027-01-01" }),
            ),
        ];
        for (provider, session) in &saved {
            if providers().contains(provider) {
                crate::config::save_session(*provider, session, &config).expect("save session");
            }
        }

        let accounts = accounts(&config);
        assert_eq!(
            accounts.iter().map(|a| a.provider).collect::<Vec<_>>(),
            providers()
        );
        for account in &accounts {
            match account.provider {
                Provider::AirVpn => assert_eq!(account.account.as_deref(), Some("alice")),
                Provider::Mullvad => {
                    assert_eq!(account.account.as_deref(), Some("1234"));
                    assert_eq!(account.detail, "expires 2027-01-01");
                }
                Provider::Wgconf => assert_eq!(account.detail, "0 saved profile(s)"),
                Provider::Proton | Provider::Ivpn => assert!(account.account.is_none()),
            }
        }

        if let Some(value) = previous {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

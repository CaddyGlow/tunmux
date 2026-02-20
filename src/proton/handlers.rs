use crate::api;
use crate::cli::ProtonCommand;
use crate::config::{self, AppConfig, Provider};
use crate::crypto;
use crate::error;
use crate::models;
use crate::netns;
use crate::proxy;
use crate::wireguard;

const PROVIDER: Provider = Provider::Proton;
const INTERFACE_NAME: &str = "proton0";
const MANIFEST_FILE: &str = "manifest.json";

#[derive(serde::Deserialize, serde::Serialize)]
struct ProtonManifest {
    logical_servers: Vec<models::server::LogicalServer>,
}

pub async fn dispatch(command: ProtonCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        ProtonCommand::Login { username } => cmd_login(&username, config).await,
        ProtonCommand::Logout => cmd_logout(config).await,
        ProtonCommand::Info => cmd_info(config),
        ProtonCommand::Servers { country, free } => cmd_servers(country, free, config).await,
        ProtonCommand::Connect {
            server,
            country,
            p2p,
            backend,
            proxy,
            socks_port,
            http_port,
            proxy_access_log,
        } => {
            cmd_connect(
                server,
                country,
                p2p,
                backend,
                proxy,
                socks_port,
                http_port,
                proxy_access_log,
                config,
            )
            .await
        }
        ProtonCommand::Disconnect { instance, all } => cmd_disconnect(instance, all),
    }
}

async fn cmd_login(username: &str, config: &AppConfig) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;

    let mut client = api::http::ProtonClient::new()?;

    // SRP authentication
    let auth = api::auth::login(&mut client, username, &password).await?;

    // Handle 2FA if required
    if auth.two_factor.totp_required() {
        let code = rpassword::prompt_password("2FA code: ")?;
        api::auth::submit_2fa(&client, code.trim()).await?;
    }

    // Fetch VPN account info
    let vpn_info = api::vpn_info::fetch_vpn_info(&client).await?;

    // Generate Ed25519 keypair and derive X25519
    let keys = crypto::keys::VpnKeys::generate()?;

    // Fetch VPN certificate
    let cert = api::certificate::fetch_certificate(&client, &keys.ed25519_pk_pem()).await?;

    // Build and save session
    let session = models::session::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        vpn_username: vpn_info.vpn.name,
        vpn_password: vpn_info.vpn.password,
        plan_name: vpn_info.vpn.plan_name,
        plan_title: vpn_info.vpn.plan_title,
        max_tier: vpn_info.vpn.max_tier,
        max_connections: vpn_info.vpn.max_connect,
        ed25519_private_key: keys.ed25519_sk_base64(),
        ed25519_public_key_pem: keys.ed25519_pk_pem(),
        wg_private_key: keys.wg_private_key(),
        wg_public_key: keys.wg_public_key(),
        fingerprint: keys.fingerprint(),
        certificate_pem: cert.certificate,
    };

    config::save_session(PROVIDER, &session, config)?;
    println!("Logged in as {} ({})", username, session.plan_title);
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    // Disconnect if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        println!("Disconnecting active VPN connection...");
        disconnect_instance_direct()?;
    }

    config::delete_session(PROVIDER, config)?;

    // Also remove cached server list
    let manifest_path = config::config_dir(PROVIDER).join(MANIFEST_FILE);
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path)?;
    }

    println!("Logged out");
    Ok(())
}

fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    println!("Username:    {}", session.vpn_username);
    println!(
        "Plan:        {} ({})",
        session.plan_title, session.plan_name
    );
    println!("Tier:        {}", session.max_tier);
    println!("Connections: {}", session.max_connections);
    println!("Fingerprint: {}", &session.fingerprint[..16]);
    Ok(())
}

async fn cmd_servers(
    country: Option<String>,
    free: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let mut servers = load_servers_cached_or_fetch(&session).await?;

    // Filter enabled servers
    servers.retain(|s| s.is_enabled());

    // Filter by country
    if let Some(ref cc) = country {
        let cc_upper = cc.to_uppercase();
        servers.retain(|s| s.exit_country == cc_upper);
    }

    // Filter free-tier only
    if free {
        servers.retain(|s| s.tier == 0);
    }

    // Sort by score (lower = better)
    servers.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if servers.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    // Print header
    println!(
        "{:<16} {:>2}  {:>5}  {:>5}  {:>4}  Features",
        "Name", "CC", "Load", "Score", "Tier"
    );
    let separator = "-".repeat(60);
    println!("{separator}");

    for server in &servers {
        println!("{}", server);
    }

    println!("\n{} servers listed", servers.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
    p2p: bool,
    backend_arg: Option<String>,
    use_proxy: bool,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log_arg: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let backend_str = backend_arg.as_deref().unwrap_or(&config.general.backend);

    #[cfg(not(target_os = "linux"))]
    if use_proxy {
        anyhow::bail!("--proxy is available only on Linux");
    }

    if use_proxy {
        // Proxy mode requires kernel backend
        if matches!(backend_str, "wg-quick" | "userspace") {
            anyhow::bail!(
                "--proxy requires kernel backend (incompatible with --backend {})",
                backend_str
            );
        }
    }

    let backend = if use_proxy {
        wireguard::backend::WgBackend::Kernel
    } else {
        wireguard::backend::WgBackend::from_str_arg(backend_str)?
    };

    // Apply config defaults -- CLI flags override config
    let effective_country = country.or_else(|| config.proton.default_country.clone());
    let proxy_access_log = proxy_access_log_arg || config.general.proxy_access_log;

    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let mut servers = load_servers_cached_or_fetch(&session).await?;

    // Filter enabled servers with WireGuard support
    servers.retain(|s| s.is_enabled() && s.best_physical().is_some());

    // Filter by user tier
    servers.retain(|s| s.tier <= session.max_tier);

    // Select server
    let server = if let Some(ref name) = server_name {
        servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| error::AppError::NoServerFound)?
    } else {
        // Apply filters
        if let Some(ref cc) = effective_country {
            let cc_upper = cc.to_uppercase();
            servers.retain(|s| s.exit_country == cc_upper);
        }
        if p2p {
            servers.retain(|s| s.has_feature(models::server::ServerFeature::P2P));
        }
        // Sort by score and pick best
        servers.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        servers.first().ok_or(error::AppError::NoServerFound)?
    };

    let physical = server
        .best_physical()
        .ok_or(error::AppError::NoServerFound)?;

    // Restore keys from session
    let keys = crypto::keys::VpnKeys::from_base64(&session.ed25519_private_key)?;

    let server_pubkey = physical
        .x25519_public_key
        .as_deref()
        .ok_or_else(|| error::AppError::NoServerFound)?;

    let wg_private_key = keys.wg_private_key();
    let params = wireguard::config::WgConfigParams {
        private_key: &wg_private_key,
        addresses: &["10.2.0.2/32"],
        dns_servers: &["10.2.0.1"],
        server_public_key: server_pubkey,
        server_ip: &physical.entry_ip,
        server_port: 51820,
        preshared_key: None,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    if use_proxy {
        connect_proxy(
            server,
            &params,
            socks_port_arg,
            http_port_arg,
            proxy_access_log,
        )?;
    } else {
        connect_direct(server, &params, backend, config)?;
    }

    Ok(())
}

fn connect_proxy(
    server: &models::server::LogicalServer,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(&server.name);

    // Check for duplicate instance
    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            server.name
        );
    }

    let interface_name = format!("wg-{}", instance);
    let namespace_name = format!("tunmux_{}", instance);

    // Determine ports
    let proxy_config = if let (Some(sp), Some(hp)) = (socks_port_arg, http_port_arg) {
        proxy::ProxyConfig {
            socks_port: sp,
            http_port: hp,
            access_log: proxy_access_log,
        }
    } else {
        let mut auto = proxy::next_available_ports()?;
        if let Some(sp) = socks_port_arg {
            auto.socks_port = sp;
        }
        if let Some(hp) = http_port_arg {
            auto.http_port = hp;
        }
        auto.access_log = proxy_access_log;
        auto
    };

    println!("Connecting to {} ({})...", server.name, params.server_ip);

    // Create namespace
    netns::create(&namespace_name)?;

    // Bring up WireGuard in namespace
    if let Err(e) = wireguard::kernel::up_in_netns(params, &interface_name, &namespace_name) {
        netns::delete(&namespace_name)?;
        return Err(e.into());
    }

    // Spawn proxy daemon
    let pid = match proxy::spawn_daemon(&instance, &namespace_name, &proxy_config) {
        Ok(pid) => pid,
        Err(e) => {
            // Clean up on failure
            netns::delete(&namespace_name)?;
            return Err(e);
        }
    };

    // Save connection state
    let state = wireguard::connection::ConnectionState {
        instance_name: instance.clone(),
        provider: PROVIDER.dir_name().to_string(),
        interface_name,
        backend: wireguard::backend::WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: server.name.clone(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: Some(namespace_name),
        proxy_pid: Some(pid),
        socks_port: Some(proxy_config.socks_port),
        http_port: Some(proxy_config.http_port),
    };
    state.save()?;

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, server.name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_direct(
    server: &models::server::LogicalServer,
    params: &wireguard::config::WgConfigParams<'_>,
    backend: wireguard::backend::WgBackend,
    _config: &AppConfig,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    // Check if a direct connection already exists
    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        anyhow::bail!("Already connected. Run `tunmux proton disconnect` first.");
    }

    println!("Connecting to {} ({})...", server.name, params.server_ip);

    match backend {
        wireguard::backend::WgBackend::WgQuick => {
            let wg_config = wireguard::config::generate_config(params);
            wireguard::wg_quick::up(&wg_config, INTERFACE_NAME, PROVIDER, false)?;

            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: INTERFACE_NAME.to_string(),
                backend,
                server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
                server_display_name: server.name.clone(),
                original_gateway_ip: None,
                original_gateway_iface: None,
                original_resolv_conf: None,
                namespace_name: None,
                proxy_pid: None,
                socks_port: None,
                http_port: None,
            };
            state.save()?;
        }
        wireguard::backend::WgBackend::Userspace => {
            let wg_config = wireguard::config::generate_config(params);
            wireguard::userspace::up(&wg_config, INTERFACE_NAME)?;

            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: INTERFACE_NAME.to_string(),
                backend,
                server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
                server_display_name: server.name.clone(),
                original_gateway_ip: None,
                original_gateway_iface: None,
                original_resolv_conf: None,
                namespace_name: None,
                proxy_pid: None,
                socks_port: None,
                http_port: None,
            };
            state.save()?;
        }
        wireguard::backend::WgBackend::Kernel => {
            wireguard::kernel::up(params, INTERFACE_NAME, PROVIDER.dir_name(), &server.name)?;
        }
    }

    println!(
        "Connected to {} ({}) [backend: {}]",
        server.name, server.exit_country, backend
    );
    Ok(())
}

fn cmd_disconnect(instance: Option<String>, all: bool) -> anyhow::Result<()> {
    let provider_name = PROVIDER.dir_name();

    if all {
        let connections = wireguard::connection::ConnectionState::load_all()?;
        let mine: Vec<_> = connections
            .into_iter()
            .filter(|c| c.provider == provider_name)
            .collect();
        if mine.is_empty() {
            println!("No active proton connections.");
            return Ok(());
        }
        for conn in mine {
            disconnect_one(&conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        return Ok(());
    }

    if let Some(ref name) = instance {
        let conn = wireguard::connection::ConnectionState::load(name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", name))?;
        if conn.provider != provider_name {
            anyhow::bail!(
                "instance {:?} belongs to provider {:?}, not proton",
                name,
                conn.provider
            );
        }
        disconnect_one(&conn)?;
        println!("Disconnected {}", name);
        return Ok(());
    }

    // No instance specified -- find sole connection for this provider
    let connections = wireguard::connection::ConnectionState::load_all()?;
    let mine: Vec<_> = connections
        .into_iter()
        .filter(|c| c.provider == provider_name)
        .collect();

    match mine.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &mine[0];
            disconnect_one(conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &mine {
                let ports = match (conn.socks_port, conn.http_port) {
                    (Some(s), Some(h)) => format!("SOCKS5 :{}, HTTP :{}", s, h),
                    _ => "-".to_string(),
                };
                println!(
                    "  {}  {}  {}",
                    conn.instance_name, conn.server_display_name, ports
                );
            }
            println!("\nUsage: tunmux proton disconnect <instance>");
            println!("       tunmux proton disconnect --all");
        }
    }

    Ok(())
}

fn disconnect_one(state: &wireguard::connection::ConnectionState) -> anyhow::Result<()> {
    // Stop proxy daemon if running
    if let Some(pid) = state.proxy_pid {
        proxy::stop_daemon(pid)?;
    }

    // Clean up proxy pid/log files
    let pid_path = proxy::pid_file(&state.instance_name);
    let log_path = proxy::log_file(&state.instance_name);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&log_path);

    // Delete namespace if set
    if let Some(ref ns) = state.namespace_name {
        netns::delete(ns)?;
        let _ = netns::remove_namespace_dir(ns);
    }

    // Tear down WireGuard
    if state.namespace_name.is_some() {
        // Proxy mode: namespace deletion already removed the interface
        // Just remove state file
        wireguard::connection::ConnectionState::remove(&state.instance_name)?;
    } else {
        // Direct mode: use the appropriate backend teardown
        match state.backend {
            wireguard::backend::WgBackend::Kernel => {
                wireguard::kernel::down(state)?;
            }
            wireguard::backend::WgBackend::WgQuick => {
                wireguard::wg_quick::down(&state.interface_name, PROVIDER)?;
                wireguard::connection::ConnectionState::remove(&state.instance_name)?;
            }
            wireguard::backend::WgBackend::Userspace => {
                wireguard::userspace::down(&state.interface_name)?;
                wireguard::connection::ConnectionState::remove(&state.instance_name)?;
            }
        }
    }

    Ok(())
}

/// Legacy helper for logout -- disconnects any direct connection.
fn disconnect_instance_direct() -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;
    if let Some(state) = wireguard::connection::ConnectionState::load(DIRECT_INSTANCE)? {
        disconnect_one(&state)?;
    }
    Ok(())
}

async fn load_servers_cached_or_fetch(
    session: &models::session::Session,
) -> anyhow::Result<Vec<models::server::LogicalServer>> {
    if let Ok(logical_servers) = load_manifest() {
        return Ok(logical_servers);
    }

    let client = api::http::ProtonClient::authenticated(&session.uid, &session.access_token)?;
    let resp = api::servers::fetch_server_list(&client).await?;
    save_manifest(&resp.logical_servers)?;
    Ok(resp.logical_servers)
}

fn save_manifest(logical_servers: &[models::server::LogicalServer]) -> anyhow::Result<()> {
    let manifest = ProtonManifest {
        logical_servers: logical_servers.to_vec(),
    };
    let json = serde_json::to_string_pretty(&manifest)?;
    config::save_provider_file(PROVIDER, MANIFEST_FILE, json.as_bytes())?;
    Ok(())
}

fn load_manifest() -> anyhow::Result<Vec<models::server::LogicalServer>> {
    let data = config::load_provider_file(PROVIDER, MANIFEST_FILE)?.ok_or_else(|| {
        error::AppError::Other("no cached manifest -- run `tunmux proton servers` first".into())
    })?;
    let manifest: ProtonManifest = serde_json::from_slice(&data)?;
    Ok(manifest.logical_servers)
}

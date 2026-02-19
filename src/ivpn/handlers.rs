use anyhow::Context;
use reqwest::Client;
use serde::de::DeserializeOwned;

use crate::cli::IvpnCommand;
use crate::config::{self, AppConfig, Provider};
use crate::crypto;
use crate::error;
use crate::netns;
use crate::proxy;
use crate::wireguard;

const PROVIDER: Provider = Provider::Ivpn;
const INTERFACE_NAME: &str = "ivpn0";
const MANIFEST_FILE: &str = "manifest.json";
const API_BASE: &str = "https://api.ivpn.net";
const CODE_SUCCESS: i64 = 200;
const CODE_2FA_REQUIRED: i64 = 70011;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnSession {
    account_id: String,
    session_token: String,
    device_name: String,
    vpn_username: String,
    vpn_password: String,
    wg_private_key: String,
    wg_public_key: String,
    wg_local_ip: String,
    account_active: bool,
    account_active_until: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnManifest {
    wireguard: Vec<IvpnWireGuardServer>,
    config: IvpnConfigInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnWireGuardServer {
    gateway: String,
    country_code: String,
    country: String,
    city: String,
    hosts: Vec<IvpnWireGuardHost>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnWireGuardHost {
    hostname: String,
    dns_name: String,
    host: String,
    public_key: String,
    local_ip: String,
    #[serde(default)]
    load: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnConfigInfo {
    ports: IvpnPortsInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnPortsInfo {
    wireguard: Vec<IvpnPortInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnPortInfo {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    range: Option<IvpnPortRange>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IvpnPortRange {
    min: u16,
    max: u16,
}

#[derive(Debug, serde::Serialize)]
struct IvpnSessionNewRequest<'a> {
    username: &'a str,
    force: bool,
    wg_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmation: Option<&'a str>,
}

#[derive(Debug, serde::Serialize)]
struct IvpnSessionStatusRequest<'a> {
    session_token: &'a str,
}

#[derive(Debug, serde::Serialize)]
struct IvpnSessionDeleteRequest<'a> {
    session_token: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnSessionNewResponse {
    status: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    vpn_username: String,
    #[serde(default)]
    vpn_password: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    service_status: Option<IvpnServiceStatus>,
    #[serde(default)]
    wireguard: Option<IvpnWireGuardLogin>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct IvpnServiceStatus {
    #[serde(default)]
    is_active: bool,
    #[serde(default)]
    active_until: i64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct IvpnWireGuardLogin {
    #[serde(default)]
    status: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    ip_address: String,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnSessionStatusResponse {
    status: i64,
    #[serde(default, rename = "message")]
    _message: String,
    #[serde(default)]
    service_status: Option<IvpnServiceStatus>,
    #[serde(default)]
    device_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnBasicResponse {
    status: i64,
    #[serde(default)]
    message: String,
}

pub async fn dispatch(command: IvpnCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        IvpnCommand::Login { account } => cmd_login(&account, config).await,
        IvpnCommand::Logout => cmd_logout(config).await,
        IvpnCommand::Info => cmd_info(config).await,
        IvpnCommand::Servers { country } => cmd_servers(country).await,
        IvpnCommand::Connect {
            server,
            country,
            backend,
            proxy,
            socks_port,
            http_port,
            proxy_access_log,
        } => {
            cmd_connect(
                server,
                country,
                backend,
                proxy,
                socks_port,
                http_port,
                proxy_access_log,
                config,
            )
            .await
        }
        IvpnCommand::Disconnect { instance, all } => cmd_disconnect(instance, all),
    }
}

async fn cmd_login(account_id: &str, config: &AppConfig) -> anyhow::Result<()> {
    let client = api_client()?;
    let keys = crypto::keys::VpnKeys::generate()?;
    let wg_public_key = keys.wg_public_key();
    let wg_private_key = keys.wg_private_key();

    let mut response = session_new(&client, account_id, &wg_public_key, None).await?;
    if response.status == CODE_2FA_REQUIRED {
        let code = rpassword::prompt_password("2FA code: ")?;
        response = session_new(&client, account_id, &wg_public_key, Some(code.trim())).await?;
    }

    ensure_api_success(response.status, &response.message, "IVPN login")?;
    let wg_info = response
        .wireguard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IVPN login response missing wireguard section"))?;
    ensure_api_success(wg_info.status, &wg_info.message, "IVPN WireGuard login")?;
    if wg_info.ip_address.is_empty() {
        anyhow::bail!("IVPN login did not return a WireGuard IP address");
    }

    let status = response.service_status.unwrap_or(IvpnServiceStatus {
        is_active: false,
        active_until: 0,
    });
    let session = IvpnSession {
        account_id: account_id.to_string(),
        session_token: response.token,
        device_name: response.device_name,
        vpn_username: response.vpn_username,
        vpn_password: response.vpn_password,
        wg_private_key,
        wg_public_key,
        wg_local_ip: wg_info.ip_address.clone(),
        account_active: status.is_active,
        account_active_until: if status.active_until > 0 {
            Some(status.active_until)
        } else {
            None
        },
    };
    config::save_session(PROVIDER, &session, config)?;

    if let Ok(manifest) = fetch_manifest(&client).await {
        let _ = save_manifest(&manifest);
    }

    println!(
        "Logged in to IVPN account {}{}",
        account_id,
        if session.device_name.is_empty() {
            String::new()
        } else {
            format!(" (device: {})", session.device_name)
        }
    );
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    let _ = cmd_disconnect(None, true);

    if let Ok(session) = config::load_session::<IvpnSession>(PROVIDER, config) {
        let client = api_client()?;
        if let Err(e) = session_delete(&client, &session.session_token).await {
            eprintln!("Warning: failed to delete IVPN session on backend: {e}");
        }
    }

    config::delete_session(PROVIDER, config)?;
    let manifest_path = config::config_dir(PROVIDER).join(MANIFEST_FILE);
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path)?;
    }

    println!("Logged out");
    Ok(())
}

async fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let mut session: IvpnSession = config::load_session(PROVIDER, config)?;

    let client = api_client()?;
    if let Ok(status) = session_status(&client, &session.session_token).await {
        if status.status == CODE_SUCCESS {
            if let Some(service) = status.service_status {
                session.account_active = service.is_active;
                session.account_active_until = if service.active_until > 0 {
                    Some(service.active_until)
                } else {
                    None
                };
            }
            if !status.device_name.is_empty() {
                session.device_name = status.device_name;
            }
            config::save_session(PROVIDER, &session, config)?;
        }
    }

    println!("Account:      {}", session.account_id);
    println!("Active:       {}", session.account_active);
    if let Some(unix_ts) = session.account_active_until {
        println!("Active until: {}", unix_ts);
    }
    println!(
        "Device:       {}",
        if session.device_name.is_empty() {
            "-".to_string()
        } else {
            session.device_name.clone()
        }
    );
    println!("WG local IP:  {}", session.wg_local_ip);
    println!("WG pubkey:    {}", short_key(&session.wg_public_key));
    Ok(())
}

async fn cmd_servers(country: Option<String>) -> anyhow::Result<()> {
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;

    let mut rows: Vec<(&IvpnWireGuardServer, &IvpnWireGuardHost)> = Vec::new();
    for server in &manifest.wireguard {
        for host in &server.hosts {
            rows.push((server, host));
        }
    }

    if let Some(cc) = country {
        let cc_upper = cc.to_uppercase();
        rows.retain(|(s, _)| s.country_code.eq_ignore_ascii_case(&cc_upper));
    }

    rows.sort_by(|a, b| {
        a.1.load
            .partial_cmp(&b.1.load)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if rows.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    println!(
        "{:<24} {:>2}  {:<18} {:>6}  Host",
        "Gateway", "CC", "City", "Load"
    );
    println!("{}", "-".repeat(90));
    for (server, host) in rows {
        println!(
            "{:<24} {:>2}  {:<18} {:>5.1}%  {}",
            server.gateway, server.country_code, server.city, host.load, host.hostname
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
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

    if use_proxy && matches!(backend_str, "wg-quick" | "userspace" | "user-space") {
        anyhow::bail!(
            "--proxy requires kernel backend (incompatible with --backend {})",
            backend_str
        );
    }

    let backend = if use_proxy {
        wireguard::backend::WgBackend::Kernel
    } else {
        wireguard::backend::WgBackend::from_str_arg(backend_str)?
    };

    let effective_country = country.or_else(|| config.ivpn.default_country.clone());
    let proxy_access_log = proxy_access_log_arg || config.general.proxy_access_log;

    let session: IvpnSession = config::load_session(PROVIDER, config)?;
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;
    let (server, host) = select_host(
        &manifest,
        server_name.as_deref(),
        effective_country.as_deref(),
    )?;

    let server_port = choose_ivpn_port(&manifest.config.ports.wireguard);
    let local_ip_no_mask = session
        .wg_local_ip
        .split('/')
        .next()
        .unwrap_or(&session.wg_local_ip)
        .to_string();
    let address = ensure_cidr(&local_ip_no_mask, "/32");
    let address_refs = [address.as_str()];

    let dns_ip = host
        .local_ip
        .split('/')
        .next()
        .unwrap_or("10.0.0.1")
        .to_string();
    let dns_refs = [dns_ip.as_str()];

    let params = wireguard::config::WgConfigParams {
        private_key: &session.wg_private_key,
        addresses: &address_refs,
        dns_servers: &dns_refs,
        server_public_key: &host.public_key,
        server_ip: &host.host,
        server_port,
        preshared_key: None,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    if use_proxy {
        connect_proxy(
            server,
            host,
            &params,
            socks_port_arg,
            http_port_arg,
            proxy_access_log,
        )?;
    } else {
        connect_direct(server, host, &params, backend)?;
    }

    Ok(())
}

fn connect_proxy(
    server: &IvpnWireGuardServer,
    host: &IvpnWireGuardHost,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(&host.hostname);

    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            host.hostname
        );
    }

    let interface_name = format!("wg-{}", instance);
    let namespace_name = format!("tunmux_{}", instance);

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

    println!("Connecting to {} ({})...", host.hostname, params.server_ip);

    netns::create(&namespace_name)?;

    if let Err(e) = wireguard::kernel::up_in_netns(params, &interface_name, &namespace_name) {
        netns::delete(&namespace_name)?;
        return Err(e.into());
    }

    let pid = match proxy::spawn_daemon(&instance, &namespace_name, &proxy_config) {
        Ok(pid) => pid,
        Err(e) => {
            netns::delete(&namespace_name)?;
            return Err(e);
        }
    };

    let state = wireguard::connection::ConnectionState {
        instance_name: instance.clone(),
        provider: PROVIDER.dir_name().to_string(),
        interface_name,
        backend: wireguard::backend::WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: host.hostname.clone(),
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
        "Connected {} ({} / {}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance,
        server.country_code,
        host.hostname,
        proxy_config.socks_port,
        proxy_config.http_port
    );
    Ok(())
}

fn connect_direct(
    server: &IvpnWireGuardServer,
    host: &IvpnWireGuardHost,
    params: &wireguard::config::WgConfigParams<'_>,
    backend: wireguard::backend::WgBackend,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        anyhow::bail!("Already connected. Run `tunmux ivpn disconnect` first.");
    }

    println!("Connecting to {} ({})...", host.hostname, params.server_ip);

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
                server_display_name: host.hostname.clone(),
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
            wireguard::wg_quick::up(&wg_config, INTERFACE_NAME, PROVIDER, true)?;

            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: INTERFACE_NAME.to_string(),
                backend,
                server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
                server_display_name: host.hostname.clone(),
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
            wireguard::kernel::up(params, INTERFACE_NAME, PROVIDER.dir_name(), &host.hostname)?;
        }
    }

    println!(
        "Connected to {} ({}, {}) [backend: {}]",
        host.hostname, server.country_code, server.city, backend
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
            println!("No active ivpn connections.");
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
                "instance {:?} belongs to provider {:?}, not ivpn",
                name,
                conn.provider
            );
        }
        disconnect_one(&conn)?;
        println!("Disconnected {}", name);
        return Ok(());
    }

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
            println!("\nUsage: tunmux ivpn disconnect <instance>");
            println!("       tunmux ivpn disconnect --all");
        }
    }

    Ok(())
}

fn disconnect_one(state: &wireguard::connection::ConnectionState) -> anyhow::Result<()> {
    if let Some(pid) = state.proxy_pid {
        proxy::stop_daemon(pid)?;
    }

    let pid_path = proxy::pid_file(&state.instance_name);
    let log_path = proxy::log_file(&state.instance_name);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&log_path);

    if let Some(ref ns) = state.namespace_name {
        netns::delete(ns)?;
        let _ = netns::remove_namespace_dir(ns);
    }

    if state.namespace_name.is_some() {
        wireguard::connection::ConnectionState::remove(&state.instance_name)?;
    } else {
        match state.backend {
            wireguard::backend::WgBackend::Kernel => {
                wireguard::kernel::down(state)?;
            }
            wireguard::backend::WgBackend::WgQuick | wireguard::backend::WgBackend::Userspace => {
                wireguard::wg_quick::down(&state.interface_name, PROVIDER)?;
                wireguard::connection::ConnectionState::remove(&state.instance_name)?;
            }
        }
    }

    Ok(())
}

async fn load_manifest_cached_or_fetch(client: &Client) -> anyhow::Result<IvpnManifest> {
    if let Ok(manifest) = load_manifest() {
        return Ok(manifest);
    }
    let manifest = fetch_manifest(client).await?;
    save_manifest(&manifest)?;
    Ok(manifest)
}

fn save_manifest(manifest: &IvpnManifest) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    config::save_provider_file(PROVIDER, MANIFEST_FILE, json.as_bytes())?;
    Ok(())
}

fn load_manifest() -> anyhow::Result<IvpnManifest> {
    let data = config::load_provider_file(PROVIDER, MANIFEST_FILE)?.ok_or_else(|| {
        error::AppError::Other("no cached manifest -- run `tunmux ivpn servers` first".into())
    })?;
    Ok(serde_json::from_slice(&data)?)
}

fn select_host<'a>(
    manifest: &'a IvpnManifest,
    server_name: Option<&str>,
    country: Option<&str>,
) -> anyhow::Result<(&'a IvpnWireGuardServer, &'a IvpnWireGuardHost)> {
    if let Some(name) = server_name {
        for server in &manifest.wireguard {
            if server.gateway.eq_ignore_ascii_case(name) {
                let best = server
                    .hosts
                    .iter()
                    .min_by(|a, b| {
                        a.load
                            .partial_cmp(&b.load)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .ok_or_else(|| error::AppError::NoServerFound)?;
                return Ok((server, best));
            }
            if let Some(host) = server.hosts.iter().find(|h| {
                h.hostname.eq_ignore_ascii_case(name) || h.dns_name.eq_ignore_ascii_case(name)
            }) {
                return Ok((server, host));
            }
        }
        return Err(error::AppError::NoServerFound.into());
    }

    let mut rows: Vec<(&IvpnWireGuardServer, &IvpnWireGuardHost)> = Vec::new();
    for server in &manifest.wireguard {
        if let Some(cc) = country {
            if !server.country_code.eq_ignore_ascii_case(cc) {
                continue;
            }
        }
        for host in &server.hosts {
            rows.push((server, host));
        }
    }

    rows.sort_by(|a, b| {
        a.1.load
            .partial_cmp(&b.1.load)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.first()
        .copied()
        .ok_or_else(|| error::AppError::NoServerFound.into())
}

fn choose_ivpn_port(ports: &[IvpnPortInfo]) -> u16 {
    for preferred in [2049u16, 51820u16, 443u16, 53u16] {
        if ports
            .iter()
            .any(|p| is_udp(p) && port_matches(p, preferred))
        {
            return preferred;
        }
    }

    if let Some(port) = ports
        .iter()
        .find(|p| is_udp(p) && p.port.unwrap_or(0) > 0)
        .and_then(|p| p.port)
    {
        return port;
    }

    if let Some(min) = ports
        .iter()
        .find(|p| is_udp(p) && p.range.is_some())
        .and_then(|p| p.range.as_ref().map(|r| r.min))
    {
        return min;
    }

    2049
}

fn is_udp(port: &IvpnPortInfo) -> bool {
    port.kind.eq_ignore_ascii_case("udp")
}

fn port_matches(port: &IvpnPortInfo, value: u16) -> bool {
    if let Some(p) = port.port {
        return p == value;
    }
    if let Some(range) = &port.range {
        return range.min <= value && value <= range.max;
    }
    false
}

fn ensure_cidr(addr: &str, default_mask: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else {
        format!("{}{}", addr, default_mask)
    }
}

fn short_key(key: &str) -> String {
    if key.len() <= 20 {
        key.to_string()
    } else {
        format!("{}...", &key[..20])
    }
}

fn ensure_api_success(code: i64, message: &str, action: &str) -> anyhow::Result<()> {
    if code == CODE_SUCCESS {
        return Ok(());
    }
    if message.is_empty() {
        anyhow::bail!("{action} failed: API status {}", code);
    }
    anyhow::bail!("{action} failed: [{}] {}", code, message);
}

fn api_client() -> anyhow::Result<Client> {
    Ok(Client::builder().user_agent("tunmux").build()?)
}

async fn session_new(
    client: &Client,
    account_id: &str,
    wg_public_key: &str,
    confirmation: Option<&str>,
) -> anyhow::Result<IvpnSessionNewResponse> {
    session_new_with_base(client, API_BASE, account_id, wg_public_key, confirmation).await
}

async fn session_new_with_base(
    client: &Client,
    api_base: &str,
    account_id: &str,
    wg_public_key: &str,
    confirmation: Option<&str>,
) -> anyhow::Result<IvpnSessionNewResponse> {
    let url = format!("{}/v4/session/new", api_base);
    let req = IvpnSessionNewRequest {
        username: account_id,
        force: false,
        wg_public_key,
        confirmation,
    };
    let resp = client.post(url).json(&req).send().await?;
    parse_api_json(resp, "IVPN session/new").await
}

async fn session_status(
    client: &Client,
    session_token: &str,
) -> anyhow::Result<IvpnSessionStatusResponse> {
    session_status_with_base(client, API_BASE, session_token).await
}

async fn session_status_with_base(
    client: &Client,
    api_base: &str,
    session_token: &str,
) -> anyhow::Result<IvpnSessionStatusResponse> {
    let url = format!("{}/v4/session/status", api_base);
    let req = IvpnSessionStatusRequest { session_token };
    let resp = client.post(url).json(&req).send().await?;
    parse_api_json(resp, "IVPN session/status").await
}

async fn session_delete(client: &Client, session_token: &str) -> anyhow::Result<()> {
    session_delete_with_base(client, API_BASE, session_token).await
}

async fn session_delete_with_base(
    client: &Client,
    api_base: &str,
    session_token: &str,
) -> anyhow::Result<()> {
    let url = format!("{}/v4/session/delete", api_base);
    let req = IvpnSessionDeleteRequest { session_token };
    let resp = client.post(url).json(&req).send().await?;
    let parsed: IvpnBasicResponse = parse_api_json(resp, "IVPN session/delete").await?;
    ensure_api_success(parsed.status, &parsed.message, "IVPN logout")
}

async fn fetch_manifest(client: &Client) -> anyhow::Result<IvpnManifest> {
    fetch_manifest_with_base(client, API_BASE).await
}

async fn fetch_manifest_with_base(client: &Client, api_base: &str) -> anyhow::Result<IvpnManifest> {
    let url = format!("{}/v5/servers.json", api_base);
    let resp = client.get(url).send().await?;
    parse_api_json(resp, "IVPN server list").await
}

async fn parse_api_json<T: DeserializeOwned>(
    resp: reqwest::Response,
    action: &str,
) -> anyhow::Result<T> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("{action} failed ({}): {}", status, extract_api_error(&body));
    }
    serde_json::from_str::<T>(&body).with_context(|| format!("failed to parse {} response", action))
}

fn extract_api_error(body: &str) -> String {
    if body.trim().is_empty() {
        return "empty response body".to_string();
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["message", "error", "code"] {
            if let Some(v) = value.get(key) {
                if let Some(s) = v.as_str() {
                    return s.to_string();
                }
                return v.to_string();
            }
        }
    }

    body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        must_contain: &'static [&'static str],
        status: u16,
        body: &'static str,
    }

    fn sample_manifest() -> IvpnManifest {
        IvpnManifest {
            wireguard: vec![
                IvpnWireGuardServer {
                    gateway: "fr1.gw.ivpn.net".to_string(),
                    country_code: "FR".to_string(),
                    country: "France".to_string(),
                    city: "Paris".to_string(),
                    hosts: vec![
                        IvpnWireGuardHost {
                            hostname: "fr1-wg1".to_string(),
                            dns_name: "fr1-wg1.ivpn.net".to_string(),
                            host: "198.51.100.10".to_string(),
                            public_key: "PK1".to_string(),
                            local_ip: "10.0.0.1".to_string(),
                            load: 45.0,
                        },
                        IvpnWireGuardHost {
                            hostname: "fr1-wg2".to_string(),
                            dns_name: "fr1-wg2.ivpn.net".to_string(),
                            host: "198.51.100.11".to_string(),
                            public_key: "PK2".to_string(),
                            local_ip: "10.0.0.1".to_string(),
                            load: 10.0,
                        },
                    ],
                },
                IvpnWireGuardServer {
                    gateway: "us1.gw.ivpn.net".to_string(),
                    country_code: "US".to_string(),
                    country: "United States".to_string(),
                    city: "New York".to_string(),
                    hosts: vec![IvpnWireGuardHost {
                        hostname: "us1-wg1".to_string(),
                        dns_name: "us1-wg1.ivpn.net".to_string(),
                        host: "203.0.113.20".to_string(),
                        public_key: "PK3".to_string(),
                        local_ip: "10.0.0.1".to_string(),
                        load: 15.0,
                    }],
                },
            ],
            config: IvpnConfigInfo {
                ports: IvpnPortsInfo {
                    wireguard: vec![IvpnPortInfo {
                        kind: "UDP".to_string(),
                        port: Some(2049),
                        range: None,
                    }],
                },
            },
        }
    }

    fn http_status_text(code: u16) -> &'static str {
        match code {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    fn header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn parse_content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if !name.eq_ignore_ascii_case("content-length") {
                    return None;
                }
                value.trim().parse::<usize>().ok()
            })
            .unwrap_or(0)
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> anyhow::Result<(String, String)> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(h_end) = header_end(&buf) {
                let headers = String::from_utf8_lossy(&buf[..h_end + 4]).into_owned();
                let len = parse_content_length(&headers);
                let total = h_end + 4 + len;
                if buf.len() >= total {
                    let body = String::from_utf8_lossy(&buf[h_end + 4..total]).into_owned();
                    let request_line = headers
                        .lines()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing request line"))?
                        .to_string();
                    return Ok((request_line, body));
                }
            }
        }
        Err(anyhow::anyhow!("incomplete HTTP request"))
    }

    fn spawn_mock_api_server(expected: Vec<ExpectedRequest>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);

        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).ok();
            for exp in expected {
                let (mut stream, _) = listener.accept().unwrap();
                let (request_line, body) = read_http_request(&mut stream).unwrap();
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                assert!(
                    parts.len() >= 2,
                    "invalid request line received: {request_line}"
                );
                assert_eq!(parts[0], exp.method, "method mismatch");
                assert_eq!(parts[1], exp.path, "path mismatch");
                for needle in exp.must_contain {
                    assert!(
                        body.contains(needle),
                        "request body does not contain {:?}. body={:?}",
                        needle,
                        body
                    );
                }

                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    exp.status,
                    http_status_text(exp.status),
                    exp.body.len(),
                    exp.body
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        ready_rx.recv().unwrap();
        (base, handle)
    }

    #[test]
    fn test_select_host_by_gateway_chooses_lowest_load() {
        let manifest = sample_manifest();
        let (server, host) = select_host(&manifest, Some("fr1.gw.ivpn.net"), None).unwrap();
        assert_eq!(server.country_code, "FR");
        assert_eq!(host.hostname, "fr1-wg2");
    }

    #[test]
    fn test_select_host_by_hostname() {
        let manifest = sample_manifest();
        let (server, host) = select_host(&manifest, Some("us1-wg1"), None).unwrap();
        assert_eq!(server.gateway, "us1.gw.ivpn.net");
        assert_eq!(host.dns_name, "us1-wg1.ivpn.net");
    }

    #[test]
    fn test_select_host_country_filter() {
        let manifest = sample_manifest();
        let (_, host) = select_host(&manifest, None, Some("FR")).unwrap();
        assert_eq!(host.hostname, "fr1-wg2");
    }

    #[test]
    fn test_select_host_missing_returns_error() {
        let manifest = sample_manifest();
        let err = select_host(&manifest, Some("does-not-exist"), None).unwrap_err();
        assert!(err.to_string().contains("No suitable server found"));
    }

    #[test]
    fn test_choose_ivpn_port_preferred_and_fallbacks() {
        let preferred = vec![IvpnPortInfo {
            kind: "udp".to_string(),
            port: Some(443),
            range: None,
        }];
        assert_eq!(choose_ivpn_port(&preferred), 443);

        let from_range = vec![IvpnPortInfo {
            kind: "udp".to_string(),
            port: None,
            range: Some(IvpnPortRange {
                min: 20000,
                max: 25000,
            }),
        }];
        assert_eq!(choose_ivpn_port(&from_range), 20000);

        let defaulted = vec![IvpnPortInfo {
            kind: "tcp".to_string(),
            port: Some(443),
            range: None,
        }];
        assert_eq!(choose_ivpn_port(&defaulted), 2049);
    }

    #[test]
    fn test_ensure_cidr_and_short_key() {
        assert_eq!(ensure_cidr("10.0.0.2", "/32"), "10.0.0.2/32");
        assert_eq!(ensure_cidr("10.0.0.2/32", "/24"), "10.0.0.2/32");
        assert_eq!(
            short_key("01234567890123456789abcd"),
            "01234567890123456789..."
        );
        assert_eq!(short_key("short"), "short");
    }

    #[test]
    fn test_extract_api_error_prefers_message() {
        assert_eq!(
            extract_api_error(r#"{"message":"problem"}"#),
            "problem".to_string()
        );
        assert_eq!(extract_api_error(""), "empty response body".to_string());
        assert_eq!(extract_api_error("plain text"), "plain text".to_string());
    }

    #[test]
    fn test_ensure_api_success_errors() {
        assert!(ensure_api_success(200, "", "action").is_ok());

        let err = ensure_api_success(702, "account inactive", "IVPN login").unwrap_err();
        assert_eq!(err.to_string(), "IVPN login failed: [702] account inactive");

        let err = ensure_api_success(500, "", "IVPN login").unwrap_err();
        assert_eq!(err.to_string(), "IVPN login failed: API status 500");
    }

    #[tokio::test]
    async fn test_session_new_with_confirmation_and_manifest_fetch() {
        let manifest_json = r#"{
            "wireguard":[
                {
                    "gateway":"fr1.gw.ivpn.net",
                    "country_code":"FR",
                    "country":"France",
                    "city":"Paris",
                    "hosts":[
                        {
                            "hostname":"fr1-wg1",
                            "dns_name":"fr1-wg1.ivpn.net",
                            "host":"198.51.100.10",
                            "public_key":"PUBKEY",
                            "local_ip":"10.0.0.1",
                            "load":12.5
                        }
                    ]
                }
            ],
            "config":{"ports":{"wireguard":[{"type":"UDP","port":2049}]}}
        }"#;

        let (base, handle) = spawn_mock_api_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/v4/session/new",
                must_contain: &[
                    r#""username":"i-AAAA-BBBB-CCCC""#,
                    r#""wg_public_key":"WG-PUB""#,
                    r#""confirmation":"123456""#,
                ],
                status: 200,
                body: r#"{
                    "status":200,
                    "token":"sess-1",
                    "vpn_username":"u",
                    "vpn_password":"p",
                    "device_name":"dev",
                    "service_status":{"is_active":true,"active_until":1735689600},
                    "wireguard":{"status":200,"message":"","ip_address":"10.0.0.2/32"}
                }"#,
            },
            ExpectedRequest {
                method: "GET",
                path: "/v5/servers.json",
                must_contain: &[],
                status: 200,
                body: manifest_json,
            },
        ]);

        let client = api_client().unwrap();
        let login =
            session_new_with_base(&client, &base, "i-AAAA-BBBB-CCCC", "WG-PUB", Some("123456"))
                .await
                .unwrap();
        assert_eq!(login.status, 200);
        assert_eq!(login.token, "sess-1");
        assert_eq!(login.wireguard.unwrap().ip_address, "10.0.0.2/32");

        let manifest = fetch_manifest_with_base(&client, &base).await.unwrap();
        assert_eq!(manifest.wireguard.len(), 1);
        assert_eq!(manifest.config.ports.wireguard.len(), 1);

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_session_status_and_delete_flow() {
        let (base, handle) = spawn_mock_api_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/v4/session/status",
                must_contain: &[r#""session_token":"sess-xyz""#],
                status: 200,
                body: r#"{
                    "status":200,
                    "service_status":{"is_active":true,"active_until":1735689600},
                    "device_name":"desktop-a"
                }"#,
            },
            ExpectedRequest {
                method: "POST",
                path: "/v4/session/delete",
                must_contain: &[r#""session_token":"sess-xyz""#],
                status: 200,
                body: r#"{"status":200,"message":"ok"}"#,
            },
        ]);

        let client = api_client().unwrap();
        let status = session_status_with_base(&client, &base, "sess-xyz")
            .await
            .unwrap();
        assert_eq!(status.status, 200);
        assert_eq!(status.device_name, "desktop-a");
        assert!(status.service_status.unwrap().is_active);

        session_delete_with_base(&client, &base, "sess-xyz")
            .await
            .unwrap();

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_parse_api_json_http_error_surfaces_message() {
        let (base, handle) = spawn_mock_api_server(vec![ExpectedRequest {
            method: "GET",
            path: "/v5/servers.json",
            must_contain: &[],
            status: 401,
            body: r#"{"message":"invalid token"}"#,
        }]);

        let client = api_client().unwrap();
        let err = fetch_manifest_with_base(&client, &base).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("IVPN server list failed (401 Unauthorized): invalid token"));

        handle.join().unwrap();
    }
}

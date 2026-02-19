use std::collections::HashMap;

use anyhow::Context;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;

use crate::cli::MullvadCommand;
use crate::config::{self, AppConfig, Provider};
use crate::crypto;
use crate::error;
use crate::netns;
use crate::proxy;
use crate::wireguard;

const PROVIDER: Provider = Provider::Mullvad;
const INTERFACE_NAME: &str = "mullvad0";
const MANIFEST_FILE: &str = "manifest.json";
const API_BASE: &str = "https://api.mullvad.net";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MullvadSession {
    account_number: String,
    account_id: String,
    account_expiry: String,
    device_id: String,
    device_name: String,
    device_public_key: String,
    wg_private_key: String,
    wg_public_key: String,
    ipv4_address: String,
    ipv6_address: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MullvadManifest {
    locations: HashMap<String, MullvadLocation>,
    wireguard: MullvadWireguard,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MullvadLocation {
    country: String,
    city: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MullvadWireguard {
    relays: Vec<MullvadRelay>,
    port_ranges: Vec<(u16, u16)>,
    ipv4_gateway: String,
    #[serde(default)]
    ipv6_gateway: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MullvadRelay {
    hostname: String,
    location: String,
    active: bool,
    provider: String,
    ipv4_addr_in: String,
    public_key: String,
    #[serde(default)]
    ipv6_addr_in: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct MullvadTokenRequest<'a> {
    account_number: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct MullvadTokenResponse {
    access_token: String,
}

#[derive(Debug, serde::Deserialize)]
struct MullvadAccountResponse {
    id: String,
    expiry: String,
}

#[derive(Debug, serde::Serialize)]
struct MullvadCreateDeviceRequest<'a> {
    pubkey: &'a str,
    hijack_dns: bool,
}

#[derive(Debug, serde::Deserialize)]
struct MullvadDeviceResponse {
    id: String,
    name: String,
    pubkey: String,
    ipv4_address: String,
    ipv6_address: String,
}

pub async fn dispatch(command: MullvadCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        MullvadCommand::Login { account } => cmd_login(&account, config).await,
        MullvadCommand::Logout => cmd_logout(config).await,
        MullvadCommand::Info => cmd_info(config).await,
        MullvadCommand::Servers { country } => cmd_servers(country).await,
        MullvadCommand::Connect {
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
        MullvadCommand::Disconnect { instance, all } => cmd_disconnect(instance, all),
    }
}

async fn cmd_login(account_number: &str, config: &AppConfig) -> anyhow::Result<()> {
    let client = api_client()?;
    let keys = crypto::keys::VpnKeys::generate()?;
    let wg_public_key = keys.wg_public_key();
    let wg_private_key = keys.wg_private_key();

    let access_token = fetch_access_token(&client, account_number).await?;
    let account = fetch_account(&client, &access_token).await?;
    let device = create_device(&client, &access_token, &wg_public_key).await?;

    let session = MullvadSession {
        account_number: account_number.to_string(),
        account_id: account.id,
        account_expiry: account.expiry,
        device_id: device.id,
        device_name: device.name,
        device_public_key: device.pubkey,
        wg_private_key,
        wg_public_key,
        ipv4_address: device.ipv4_address,
        ipv6_address: if device.ipv6_address.is_empty() {
            None
        } else {
            Some(device.ipv6_address)
        },
    };
    config::save_session(PROVIDER, &session, config)?;

    if let Ok(manifest) = fetch_manifest(&client).await {
        let _ = save_manifest(&manifest);
    }

    println!(
        "Logged in to Mullvad account {} (device: {})",
        account_number, session.device_name
    );
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    let _ = cmd_disconnect(None, true);

    if let Ok(session) = config::load_session::<MullvadSession>(PROVIDER, config) {
        let client = api_client()?;
        if let Err(e) = delete_device(&client, &session.account_number, &session.device_id).await {
            eprintln!("Warning: failed to remove Mullvad device from account: {e}");
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
    let mut session: MullvadSession = config::load_session(PROVIDER, config)?;

    let client = api_client()?;
    if let Ok(access_token) = fetch_access_token(&client, &session.account_number).await {
        if let Ok(account) = fetch_account(&client, &access_token).await {
            session.account_id = account.id;
            session.account_expiry = account.expiry;
            config::save_session(PROVIDER, &session, config)?;
        }
    }

    println!("Account:      {}", session.account_number);
    println!("Account ID:   {}", session.account_id);
    println!("Expiry:       {}", session.account_expiry);
    println!(
        "Device:       {} ({})",
        session.device_name, session.device_id
    );
    println!("WG pubkey:    {}", short_key(&session.wg_public_key));
    println!("Device pubkey: {}", short_key(&session.device_public_key));
    Ok(())
}

async fn cmd_servers(country: Option<String>) -> anyhow::Result<()> {
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;
    let mut relays: Vec<&MullvadRelay> = manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .collect();

    if let Some(cc) = country {
        let cc_upper = cc.to_uppercase();
        relays.retain(|r| country_code_from_location(&r.location) == cc_upper);
    }

    relays.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    if relays.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    println!(
        "{:<20} {:>2}  {:<20} {:<14} Ingress",
        "Hostname", "CC", "City", "Provider"
    );
    println!("{}", "-".repeat(84));

    for relay in relays {
        let cc = country_code_from_location(&relay.location);
        let city = manifest
            .locations
            .get(&relay.location)
            .map(|l| l.city.as_str())
            .unwrap_or("-");
        println!(
            "{:<20} {:>2}  {:<20} {:<14} {}",
            relay.hostname, cc, city, relay.provider, relay.ipv4_addr_in
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

    let effective_country = country.or_else(|| config.mullvad.default_country.clone());
    let proxy_access_log = proxy_access_log_arg || config.general.proxy_access_log;

    let session: MullvadSession = config::load_session(PROVIDER, config)?;
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;
    let relay = select_relay(
        &manifest,
        server_name.as_deref(),
        effective_country.as_deref(),
    )?;

    let server_port = choose_mullvad_port(&manifest.wireguard.port_ranges);
    let mut addresses = vec![ensure_cidr(&session.ipv4_address, "/32")];
    if let Some(ref ipv6) = session.ipv6_address {
        if !ipv6.is_empty() {
            addresses.push(ensure_cidr(ipv6, "/128"));
        }
    }

    let mut dns_servers = vec![manifest.wireguard.ipv4_gateway.clone()];
    if !manifest.wireguard.ipv6_gateway.is_empty() {
        dns_servers.push(manifest.wireguard.ipv6_gateway.clone());
    }

    let address_refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let dns_refs: Vec<&str> = dns_servers.iter().map(String::as_str).collect();

    let params = wireguard::config::WgConfigParams {
        private_key: &session.wg_private_key,
        addresses: &address_refs,
        dns_servers: &dns_refs,
        server_public_key: &relay.public_key,
        server_ip: &relay.ipv4_addr_in,
        server_port,
        preshared_key: None,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    if use_proxy {
        connect_proxy(
            relay,
            &params,
            socks_port_arg,
            http_port_arg,
            proxy_access_log,
        )?;
    } else {
        connect_direct(relay, &params, backend)?;
    }

    Ok(())
}

fn connect_proxy(
    relay: &MullvadRelay,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(&relay.hostname);

    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            relay.hostname
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

    println!("Connecting to {} ({})...", relay.hostname, params.server_ip);

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
        server_display_name: relay.hostname.clone(),
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
        instance, relay.hostname, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_direct(
    relay: &MullvadRelay,
    params: &wireguard::config::WgConfigParams<'_>,
    backend: wireguard::backend::WgBackend,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        anyhow::bail!("Already connected. Run `tunmux mullvad disconnect` first.");
    }

    println!("Connecting to {} ({})...", relay.hostname, params.server_ip);

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
                server_display_name: relay.hostname.clone(),
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
                server_display_name: relay.hostname.clone(),
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
            wireguard::kernel::up(params, INTERFACE_NAME, PROVIDER.dir_name(), &relay.hostname)?;
        }
    }

    println!("Connected to {} [backend: {}]", relay.hostname, backend);
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
            println!("No active mullvad connections.");
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
                "instance {:?} belongs to provider {:?}, not mullvad",
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
            println!("\nUsage: tunmux mullvad disconnect <instance>");
            println!("       tunmux mullvad disconnect --all");
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

async fn load_manifest_cached_or_fetch(client: &Client) -> anyhow::Result<MullvadManifest> {
    if let Ok(manifest) = load_manifest() {
        return Ok(manifest);
    }
    let manifest = fetch_manifest(client).await?;
    save_manifest(&manifest)?;
    Ok(manifest)
}

fn save_manifest(manifest: &MullvadManifest) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    config::save_provider_file(PROVIDER, MANIFEST_FILE, json.as_bytes())?;
    Ok(())
}

fn load_manifest() -> anyhow::Result<MullvadManifest> {
    let data = config::load_provider_file(PROVIDER, MANIFEST_FILE)?.ok_or_else(|| {
        error::AppError::Other("no cached manifest -- run `tunmux mullvad servers` first".into())
    })?;
    Ok(serde_json::from_slice(&data)?)
}

fn select_relay<'a>(
    manifest: &'a MullvadManifest,
    server_name: Option<&str>,
    country: Option<&str>,
) -> anyhow::Result<&'a MullvadRelay> {
    let mut relays: Vec<&MullvadRelay> = manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .collect();

    if let Some(name) = server_name {
        return relays
            .into_iter()
            .find(|r| r.hostname.eq_ignore_ascii_case(name))
            .ok_or_else(|| error::AppError::NoServerFound.into());
    }

    if let Some(cc) = country {
        let cc_upper = cc.to_uppercase();
        relays.retain(|r| country_code_from_location(&r.location) == cc_upper);
    }

    relays.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    relays
        .first()
        .copied()
        .ok_or_else(|| error::AppError::NoServerFound.into())
}

fn choose_mullvad_port(ranges: &[(u16, u16)]) -> u16 {
    if ranges
        .iter()
        .any(|(start, end)| *start <= 51820 && 51820 <= *end)
    {
        return 51820;
    }
    if ranges
        .iter()
        .any(|(start, end)| *start <= 2049 && 2049 <= *end)
    {
        return 2049;
    }
    ranges.first().map(|(start, _)| *start).unwrap_or(51820)
}

fn country_code_from_location(location: &str) -> String {
    location.split('-').next().unwrap_or("").to_uppercase()
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

fn api_client() -> anyhow::Result<Client> {
    Ok(Client::builder().user_agent("tunmux").build()?)
}

async fn fetch_access_token(client: &Client, account_number: &str) -> anyhow::Result<String> {
    fetch_access_token_with_base(client, API_BASE, account_number).await
}

async fn fetch_access_token_with_base(
    client: &Client,
    api_base: &str,
    account_number: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/auth/v1/token", api_base);
    let req = MullvadTokenRequest { account_number };
    let resp = client.post(url).json(&req).send().await?;
    let token: MullvadTokenResponse = parse_api_json(resp, "Mullvad token request").await?;
    Ok(token.access_token)
}

async fn fetch_account(
    client: &Client,
    access_token: &str,
) -> anyhow::Result<MullvadAccountResponse> {
    fetch_account_with_base(client, API_BASE, access_token).await
}

async fn fetch_account_with_base(
    client: &Client,
    api_base: &str,
    access_token: &str,
) -> anyhow::Result<MullvadAccountResponse> {
    let url = format!("{}/accounts/v1/accounts/me", api_base);
    let resp = client.get(url).bearer_auth(access_token).send().await?;
    parse_api_json(resp, "Mullvad account lookup").await
}

async fn create_device(
    client: &Client,
    access_token: &str,
    public_key: &str,
) -> anyhow::Result<MullvadDeviceResponse> {
    create_device_with_base(client, API_BASE, access_token, public_key).await
}

async fn create_device_with_base(
    client: &Client,
    api_base: &str,
    access_token: &str,
    public_key: &str,
) -> anyhow::Result<MullvadDeviceResponse> {
    let url = format!("{}/accounts/v1/devices", api_base);
    let req = MullvadCreateDeviceRequest {
        pubkey: public_key,
        hijack_dns: false,
    };
    let resp = client
        .post(url)
        .bearer_auth(access_token)
        .json(&req)
        .send()
        .await?;
    parse_api_json(resp, "Mullvad device creation").await
}

async fn delete_device(
    client: &Client,
    account_number: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    delete_device_with_base(client, API_BASE, account_number, device_id).await
}

async fn delete_device_with_base(
    client: &Client,
    api_base: &str,
    account_number: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    let access_token = fetch_access_token_with_base(client, api_base, account_number).await?;
    let url = format!("{}/accounts/v1/devices/{}", api_base, device_id);
    let resp = client.delete(url).bearer_auth(access_token).send().await?;
    if resp.status() == StatusCode::NO_CONTENT {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    anyhow::bail!(
        "Mullvad device deletion failed ({}): {}",
        status,
        extract_api_error(&body)
    );
}

async fn fetch_manifest(client: &Client) -> anyhow::Result<MullvadManifest> {
    fetch_manifest_with_base(client, API_BASE).await
}

async fn fetch_manifest_with_base(
    client: &Client,
    api_base: &str,
) -> anyhow::Result<MullvadManifest> {
    let url = format!("{}/app/v1/relays", api_base);
    let resp = client.get(url).send().await?;
    parse_api_json(resp, "Mullvad relay list").await
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
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        must_contain_body: &'static [&'static str],
        must_contain_headers: &'static [&'static str],
        status: u16,
        body: &'static str,
    }

    fn sample_manifest() -> MullvadManifest {
        let mut locations = HashMap::new();
        locations.insert(
            "se-got".to_string(),
            MullvadLocation {
                country: "Sweden".to_string(),
                city: "Gothenburg".to_string(),
            },
        );
        locations.insert(
            "us-nyc".to_string(),
            MullvadLocation {
                country: "United States".to_string(),
                city: "New York".to_string(),
            },
        );

        MullvadManifest {
            locations,
            wireguard: MullvadWireguard {
                relays: vec![
                    MullvadRelay {
                        hostname: "se1-wireguard".to_string(),
                        location: "se-got".to_string(),
                        active: true,
                        provider: "31173".to_string(),
                        ipv4_addr_in: "198.51.100.10".to_string(),
                        public_key: "PK1".to_string(),
                        ipv6_addr_in: None,
                    },
                    MullvadRelay {
                        hostname: "us1-wireguard".to_string(),
                        location: "us-nyc".to_string(),
                        active: true,
                        provider: "m247".to_string(),
                        ipv4_addr_in: "203.0.113.20".to_string(),
                        public_key: "PK2".to_string(),
                        ipv6_addr_in: None,
                    },
                    MullvadRelay {
                        hostname: "se2-wireguard".to_string(),
                        location: "se-got".to_string(),
                        active: false,
                        provider: "31173".to_string(),
                        ipv4_addr_in: "198.51.100.11".to_string(),
                        public_key: "PK3".to_string(),
                        ipv6_addr_in: None,
                    },
                ],
                port_ranges: vec![(53, 53), (2049, 2050), (51820, 51830)],
                ipv4_gateway: "10.64.0.1".to_string(),
                ipv6_gateway: "fc00::1".to_string(),
            },
        }
    }

    fn http_status_text(code: u16) -> &'static str {
        match code {
            200 => "OK",
            204 => "No Content",
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

    fn read_http_request(
        stream: &mut std::net::TcpStream,
    ) -> anyhow::Result<(String, String, String)> {
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
                    return Ok((request_line, headers, body));
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
                let (request_line, headers, body) = read_http_request(&mut stream).unwrap();
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                assert!(
                    parts.len() >= 2,
                    "invalid request line received: {request_line}"
                );
                assert_eq!(parts[0], exp.method, "method mismatch");
                assert_eq!(parts[1], exp.path, "path mismatch");

                for needle in exp.must_contain_body {
                    assert!(
                        body.contains(needle),
                        "request body does not contain {:?}. body={:?}",
                        needle,
                        body
                    );
                }

                let headers_lower = headers.to_ascii_lowercase();
                for needle in exp.must_contain_headers {
                    assert!(
                        headers_lower.contains(&needle.to_ascii_lowercase()),
                        "request headers do not contain {:?}. headers={:?}",
                        needle,
                        headers
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
    fn test_select_relay_by_name() {
        let manifest = sample_manifest();
        let relay = select_relay(&manifest, Some("us1-wireguard"), None).unwrap();
        assert_eq!(relay.location, "us-nyc");
    }

    #[test]
    fn test_select_relay_by_country_uses_active_only() {
        let manifest = sample_manifest();
        let relay = select_relay(&manifest, None, Some("SE")).unwrap();
        assert_eq!(relay.hostname, "se1-wireguard");
    }

    #[test]
    fn test_select_relay_missing_returns_error() {
        let manifest = sample_manifest();
        let err = select_relay(&manifest, Some("missing"), None).unwrap_err();
        assert!(err.to_string().contains("No suitable server found"));
    }

    #[test]
    fn test_choose_mullvad_port_priority_and_default() {
        assert_eq!(choose_mullvad_port(&[(1000, 2000), (51820, 51830)]), 51820);
        assert_eq!(choose_mullvad_port(&[(2000, 2050)]), 2049);
        assert_eq!(choose_mullvad_port(&[(3000, 4000)]), 3000);
        assert_eq!(choose_mullvad_port(&[]), 51820);
    }

    #[test]
    fn test_country_code_from_location() {
        assert_eq!(country_code_from_location("us-nyc"), "US");
        assert_eq!(country_code_from_location("se"), "SE");
        assert_eq!(country_code_from_location(""), "");
    }

    #[test]
    fn test_ensure_cidr_short_key_and_extract_api_error() {
        assert_eq!(ensure_cidr("10.64.0.2", "/32"), "10.64.0.2/32");
        assert_eq!(ensure_cidr("10.64.0.2/32", "/24"), "10.64.0.2/32");
        assert_eq!(
            short_key("01234567890123456789abcd"),
            "01234567890123456789..."
        );
        assert_eq!(short_key("short"), "short");
        assert_eq!(
            extract_api_error(r#"{"message":"problem"}"#),
            "problem".to_string()
        );
    }

    #[tokio::test]
    async fn test_mullvad_api_login_and_manifest_flow() {
        let manifest_json = r#"{
            "locations":{
                "se-got":{"country":"Sweden","city":"Gothenburg"}
            },
            "wireguard":{
                "relays":[
                    {
                        "hostname":"se1-wireguard",
                        "location":"se-got",
                        "active":true,
                        "provider":"31173",
                        "ipv4_addr_in":"198.51.100.10",
                        "public_key":"PK1"
                    }
                ],
                "port_ranges":[[51820,51830]],
                "ipv4_gateway":"10.64.0.1",
                "ipv6_gateway":""
            }
        }"#;

        let (base, handle) = spawn_mock_api_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/auth/v1/token",
                must_contain_body: &[r#""account_number":"1234123412341234""#],
                must_contain_headers: &[],
                status: 200,
                body: r#"{"access_token":"tok-1"}"#,
            },
            ExpectedRequest {
                method: "GET",
                path: "/accounts/v1/accounts/me",
                must_contain_body: &[],
                must_contain_headers: &["authorization: bearer tok-1"],
                status: 200,
                body: r#"{"id":"acc-1","expiry":"2027-01-01T00:00:00Z"}"#,
            },
            ExpectedRequest {
                method: "POST",
                path: "/accounts/v1/devices",
                must_contain_body: &[r#""pubkey":"WG-PUB""#, r#""hijack_dns":false"#],
                must_contain_headers: &["authorization: bearer tok-1"],
                status: 200,
                body: r#"{
                    "id":"dev-1",
                    "name":"laptop",
                    "pubkey":"WG-PUB",
                    "ipv4_address":"10.64.0.2",
                    "ipv6_address":""
                }"#,
            },
            ExpectedRequest {
                method: "GET",
                path: "/app/v1/relays",
                must_contain_body: &[],
                must_contain_headers: &[],
                status: 200,
                body: manifest_json,
            },
        ]);

        let client = api_client().unwrap();

        let token = fetch_access_token_with_base(&client, &base, "1234123412341234")
            .await
            .unwrap();
        assert_eq!(token, "tok-1");

        let account = fetch_account_with_base(&client, &base, &token)
            .await
            .unwrap();
        assert_eq!(account.id, "acc-1");
        assert_eq!(account.expiry, "2027-01-01T00:00:00Z");

        let device = create_device_with_base(&client, &base, &token, "WG-PUB")
            .await
            .unwrap();
        assert_eq!(device.id, "dev-1");
        assert_eq!(device.pubkey, "WG-PUB");

        let manifest = fetch_manifest_with_base(&client, &base).await.unwrap();
        assert_eq!(manifest.wireguard.relays.len(), 1);

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_delete_device_flow_and_http_204() {
        let (base, handle) = spawn_mock_api_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/auth/v1/token",
                must_contain_body: &[r#""account_number":"1234123412341234""#],
                must_contain_headers: &[],
                status: 200,
                body: r#"{"access_token":"tok-del"}"#,
            },
            ExpectedRequest {
                method: "DELETE",
                path: "/accounts/v1/devices/dev-42",
                must_contain_body: &[],
                must_contain_headers: &["authorization: bearer tok-del"],
                status: 204,
                body: "",
            },
        ]);

        let client = api_client().unwrap();
        delete_device_with_base(&client, &base, "1234123412341234", "dev-42")
            .await
            .unwrap();

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_delete_device_error_contains_api_message() {
        let (base, handle) = spawn_mock_api_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/auth/v1/token",
                must_contain_body: &[r#""account_number":"1234123412341234""#],
                must_contain_headers: &[],
                status: 200,
                body: r#"{"access_token":"tok-del"}"#,
            },
            ExpectedRequest {
                method: "DELETE",
                path: "/accounts/v1/devices/dev-42",
                must_contain_body: &[],
                must_contain_headers: &["authorization: bearer tok-del"],
                status: 400,
                body: r#"{"message":"cannot delete device"}"#,
            },
        ]);

        let client = api_client().unwrap();
        let err = delete_device_with_base(&client, &base, "1234123412341234", "dev-42")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Mullvad device deletion failed (400 Bad Request): cannot delete device")
        );

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_parse_api_json_http_error_surfaces_message() {
        let (base, handle) = spawn_mock_api_server(vec![ExpectedRequest {
            method: "GET",
            path: "/app/v1/relays",
            must_contain_body: &[],
            must_contain_headers: &[],
            status: 401,
            body: r#"{"message":"unauthorized"}"#,
        }]);

        let client = api_client().unwrap();
        let err = fetch_manifest_with_base(&client, &base).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Mullvad relay list failed (401 Unauthorized): unauthorized"));

        handle.join().unwrap();
    }
}

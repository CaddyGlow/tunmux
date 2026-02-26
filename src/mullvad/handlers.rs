use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;

use crate::cli::{MullvadCommand, MullvadPaymentCommand};
use crate::config::{self, AppConfig, Provider};
use crate::error;
use crate::local_proxy;
use crate::netns;
use crate::proxy;
use crate::shared::crypto;
use crate::shared::hooks;
use crate::shared::latency;
use crate::wireguard;

const PROVIDER: Provider = Provider::Mullvad;
const INTERFACE_NAME: &str = "mullvad0";
const MANIFEST_FILE: &str = "manifest.json";
const ACCOUNT_ID_FILE: &str = "account_id.json";
const API_BASE: &str = "https://api.mullvad.net";
const WEB_BASE: &str = "https://mullvad.net";

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

#[derive(Debug, serde::Deserialize)]
struct MullvadCreateAccountResponse {
    number: String,
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

#[derive(Debug, serde::Deserialize)]
struct MullvadWebActionResponse {
    #[serde(rename = "type")]
    response_type: String,
    status: u16,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
struct MullvadMoneroPayment {
    monthly_price: f64,
    monthly_price_eur: f64,
    address: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SavedMullvadAccountId {
    account_id: String,
}

pub async fn dispatch(command: MullvadCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        MullvadCommand::Login { account, force } => cmd_login(&account, force, config).await,
        MullvadCommand::CreateAccount { json, force } => {
            cmd_create_account(json, force, config).await
        }
        MullvadCommand::Payment { action } => match action {
            MullvadPaymentCommand::Monero { account, json } => {
                cmd_monero_payment(account, json, config).await
            }
        },
        MullvadCommand::Logout => cmd_logout(config).await,
        MullvadCommand::Info => cmd_info(config).await,
        MullvadCommand::Servers { country, tag, sort } => cmd_servers(country, tag, sort).await,
        MullvadCommand::Connect(args) => {
            cmd_connect(
                args.server,
                args.country,
                args.sort,
                args.backend,
                args.proxy,
                args.local_proxy,
                args.disable_ipv6,
                args.mtu,
                args.socks_port,
                args.http_port,
                args.proxy_access_log,
                config,
            )
            .await
        }
        MullvadCommand::Disconnect { instance, all } => cmd_disconnect(instance, all, config),
    }
}

async fn cmd_create_account(json: bool, force: bool, config: &AppConfig) -> anyhow::Result<()> {
    confirm_create_account_allowed(force)?;
    let client = api_client()?;
    let account_number = create_account(&client).await?;
    save_account_id(&account_number)?;

    let session = login_with_client(&client, &account_number, config)
        .await
        .with_context(|| {
            format!(
                "created Mullvad account {}, but failed to register device/login",
                account_number
            )
        })?;

    if json {
        let output = serde_json::json!({
            "account_number": session.account_number,
            "account_id": session.account_id,
            "account_expiry": session.account_expiry,
            "device": {
                "id": session.device_id,
                "name": session.device_name,
                "public_key": session.device_public_key,
            },
            "wireguard": {
                "public_key": session.wg_public_key,
                "ipv4_address": session.ipv4_address,
                "ipv6_address": session.ipv6_address,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Created Mullvad account {}", account_number);
        println!(
            "Logged in to Mullvad account {} (device: {})",
            account_number, session.device_name
        );
    }

    Ok(())
}

async fn cmd_monero_payment(
    account: Option<String>,
    json: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let account_number = resolve_account_id(account.as_deref(), config)?;

    let client = mullvad_web_client()?;
    mullvad_web_login(&client, &account_number).await?;
    let payment = fetch_monero_payment(&client).await?;

    if json {
        let output = serde_json::json!({
            "account_number": account_number,
            "monthly_price": payment.monthly_price,
            "monthly_price_eur": payment.monthly_price_eur,
            "address": payment.address,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Account:           {}", account_number);
        println!("Monero monthly:    {}", payment.monthly_price);
        println!("Monthly EUR price: {}", payment.monthly_price_eur);
        println!("Address:           {}", payment.address);
    }

    Ok(())
}

async fn cmd_login(account_number: &str, force: bool, config: &AppConfig) -> anyhow::Result<()> {
    confirm_login_allowed(account_number, force)?;
    let client = api_client()?;
    let session = login_with_client(&client, account_number, config).await?;

    println!(
        "Logged in to Mullvad account {} (device: {})",
        account_number, session.device_name
    );
    Ok(())
}

async fn login_with_client(
    client: &Client,
    account_number: &str,
    config: &AppConfig,
) -> anyhow::Result<MullvadSession> {
    let keys = crypto::keys::VpnKeys::generate()?;
    let wg_public_key = keys.wg_public_key();
    let wg_private_key = keys.wg_private_key();

    let access_token = fetch_access_token(client, account_number).await?;
    let account = fetch_account(client, &access_token).await?;
    let device = create_device(client, &access_token, &wg_public_key).await?;

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
    save_account_id(account_number)?;

    if let Ok(manifest) = fetch_manifest(client).await {
        let _ = save_manifest(&manifest);
    }

    Ok(session)
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    let _ = cmd_disconnect(None, true, config);

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

async fn cmd_servers(
    country: Option<String>,
    tags: Vec<String>,
    sort: String,
) -> anyhow::Result<()> {
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

    let normalized_tags = normalize_tags(&tags);
    if !normalized_tags.is_empty() {
        relays.retain(|relay| mullvad_relay_matches_tags(&manifest, relay, &normalized_tags));
    }

    let sort_by_latency = sort == "latency";

    if sort_by_latency {
        let probe_port = choose_mullvad_port(&manifest.wireguard.port_ranges);
        let targets: Vec<(String, u16)> = relays
            .iter()
            .map(|relay| (relay.ipv4_addr_in.clone(), probe_port))
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut rows: Vec<(&MullvadRelay, Option<Duration>)> =
            relays.into_iter().zip(latencies).collect();
        rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1).then_with(|| a.0.hostname.cmp(&b.0.hostname))
        });

        if rows.is_empty() {
            println!("No servers match the given filters.");
            return Ok(());
        }

        println!(
            "{:<20} {:>2}  {:<20} {:<14} {:>8}  Ingress",
            "Hostname", "CC", "City", "Provider", "Latency"
        );
        println!("{}", "-".repeat(94));

        for (relay, latency) in rows {
            let cc = country_code_from_location(&relay.location);
            let city = manifest
                .locations
                .get(&relay.location)
                .map(|l| l.city.as_str())
                .unwrap_or("-");
            println!(
                "{:<20} {:>2}  {:<20} {:<14} {:>8}  {}",
                relay.hostname,
                cc,
                city,
                relay.provider,
                format_latency(latency),
                relay.ipv4_addr_in
            );
        }

        return Ok(());
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

fn latency_order(a: &Option<Duration>, b: &Option<Duration>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn format_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(value) => format!("{}ms", value.as_millis()),
        None => "-".to_string(),
    }
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn mullvad_relay_matches_tags(
    manifest: &MullvadManifest,
    relay: &MullvadRelay,
    tags: &[String],
) -> bool {
    let cc = country_code_from_location(&relay.location).to_ascii_lowercase();
    let city = manifest
        .locations
        .get(&relay.location)
        .map(|location| location.city.to_ascii_lowercase())
        .unwrap_or_default();
    let country = manifest
        .locations
        .get(&relay.location)
        .map(|location| location.country.to_ascii_lowercase())
        .unwrap_or_default();
    let hostname = relay.hostname.to_ascii_lowercase();
    let provider = relay.provider.to_ascii_lowercase();
    let location = relay.location.to_ascii_lowercase();

    tags.iter().all(|tag| {
        if tag == "ipv6" {
            return relay
                .ipv6_addr_in
                .as_ref()
                .is_some_and(|address| !address.is_empty());
        }

        hostname.contains(tag)
            || provider.contains(tag)
            || location.contains(tag)
            || cc.contains(tag)
            || city.contains(tag)
            || country.contains(tag)
    })
}

#[allow(clippy::too_many_arguments)]
async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
    sort: String,
    backend_arg: Option<String>,
    use_proxy: bool,
    use_local_proxy: bool,
    disable_ipv6: bool,
    mtu_arg: Option<u16>,
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

    if use_proxy && matches!(backend_str, "wg-quick" | "userspace") {
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

    if disable_ipv6
        && (use_proxy || use_local_proxy || backend != wireguard::backend::WgBackend::Kernel)
    {
        anyhow::bail!(
            "--disable-ipv6 is supported only for direct kernel mode (no --proxy/--local-proxy)"
        );
    }

    let effective_country = country.or_else(|| config.mullvad.default_country.clone());
    let proxy_access_log = proxy_access_log_arg || config.general.proxy_access_log;

    let session: MullvadSession = config::load_session(PROVIDER, config)?;
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;
    let relay = if server_name.is_some() || sort != "latency" {
        select_relay(
            &manifest,
            server_name.as_deref(),
            effective_country.as_deref(),
        )?
    } else {
        let mut relays: Vec<&MullvadRelay> = manifest
            .wireguard
            .relays
            .iter()
            .filter(|r| r.active)
            .collect();
        if let Some(ref cc) = effective_country {
            let cc_upper = cc.to_uppercase();
            relays.retain(|r| country_code_from_location(&r.location) == cc_upper);
        }

        let probe_port = choose_mullvad_port(&manifest.wireguard.port_ranges);
        let targets: Vec<(String, u16)> = relays
            .iter()
            .map(|relay| (relay.ipv4_addr_in.clone(), probe_port))
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut rows: Vec<(&MullvadRelay, Option<Duration>)> =
            relays.into_iter().zip(latencies).collect();
        rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1).then_with(|| a.0.hostname.cmp(&b.0.hostname))
        });
        rows.first()
            .map(|(relay, _)| *relay)
            .ok_or(error::AppError::NoServerFound)?
    };

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
        mtu: mtu_arg,
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
            config,
        )?;
    } else if use_local_proxy {
        connect_local_proxy(
            relay,
            &params,
            socks_port_arg,
            http_port_arg,
            proxy_access_log,
            config,
        )?;
    } else {
        connect_direct(relay, &params, backend, disable_ipv6, config)?;
    }

    Ok(())
}

fn connect_proxy(
    relay: &MullvadRelay,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
    config: &AppConfig,
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

    let pid = match proxy::spawn_daemon(&instance, &interface_name, &namespace_name, &proxy_config)
    {
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
        dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
        peer_public_key: None,
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;
    hooks::run_ifup(config, PROVIDER, &state);

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, relay.hostname, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_local_proxy(
    relay: &MullvadRelay,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(&relay.hostname);

    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            relay.hostname
        );
    }

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

    let cfg = local_proxy::local_proxy_config_from_params(
        params,
        Some(25),
        proxy_config.socks_port,
        proxy_config.http_port,
    )?;
    let local_public_key = local_proxy::derive_public_key_b64(params.private_key).ok();

    println!("Connecting to {} ({})...", relay.hostname, params.server_ip);

    let pid = local_proxy::spawn_daemon(&instance, &cfg, proxy_access_log)?;

    let state = wireguard::connection::ConnectionState {
        instance_name: instance.clone(),
        provider: PROVIDER.dir_name().to_string(),
        interface_name: String::new(),
        backend: wireguard::backend::WgBackend::LocalProxy,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: relay.hostname.clone(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: None,
        proxy_pid: Some(pid),
        socks_port: Some(proxy_config.socks_port),
        http_port: Some(proxy_config.http_port),
        dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
        peer_public_key: Some(params.server_public_key.to_string()),
        local_public_key,
        virtual_ips: params.addresses.iter().map(|s| s.to_string()).collect(),
        keepalive_secs: cfg.keepalive,
    };
    state.save()?;
    hooks::run_ifup(config, PROVIDER, &state);

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
    disable_ipv6: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        anyhow::bail!("Already connected. Run `tunmux disconnect --provider mullvad` first.");
    }

    println!("Connecting to {} ({})...", relay.hostname, params.server_ip);

    match backend {
        wireguard::backend::WgBackend::WgQuick => {
            let wg_config = wireguard::config::generate_config(params);
            let effective_iface =
                wireguard::wg_quick::up(&wg_config, INTERFACE_NAME, PROVIDER, false)?;

            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: effective_iface,
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
                dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
                peer_public_key: None,
                local_public_key: None,
                virtual_ips: vec![],
                keepalive_secs: None,
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
                server_display_name: relay.hostname.clone(),
                original_gateway_ip: None,
                original_gateway_iface: None,
                original_resolv_conf: None,
                namespace_name: None,
                proxy_pid: None,
                socks_port: None,
                http_port: None,
                dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
                peer_public_key: None,
                local_public_key: None,
                virtual_ips: vec![],
                keepalive_secs: None,
            };
            state.save()?;
        }
        wireguard::backend::WgBackend::Kernel => {
            wireguard::kernel::up(
                params,
                INTERFACE_NAME,
                PROVIDER.dir_name(),
                &relay.hostname,
                disable_ipv6,
            )?;
        }
        wireguard::backend::WgBackend::LocalProxy => {
            anyhow::bail!("use --local-proxy flag to start userspace WireGuard proxy mode");
        }
    }

    if let Some(state) = wireguard::connection::ConnectionState::load(DIRECT_INSTANCE)? {
        hooks::run_ifup(config, PROVIDER, &state);
    }

    println!("Connected to {} [backend: {}]", relay.hostname, backend);
    Ok(())
}

fn cmd_disconnect(instance: Option<String>, all: bool, config: &AppConfig) -> anyhow::Result<()> {
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
            disconnect_one(&conn, config)?;
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
        disconnect_one(&conn, config)?;
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
            disconnect_one(conn, config)?;
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
            println!("\nUsage: tunmux disconnect <instance>");
            println!("       tunmux disconnect --provider mullvad --all");
        }
    }

    Ok(())
}

fn disconnect_one(
    state: &wireguard::connection::ConnectionState,
    config: &AppConfig,
) -> anyhow::Result<()> {
    if state.backend == wireguard::backend::WgBackend::LocalProxy {
        local_proxy::disconnect(state, &state.instance_name)?;
        hooks::run_ifdown(config, PROVIDER, state);
        return Ok(());
    }

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
            wireguard::backend::WgBackend::WgQuick => {
                wireguard::wg_quick::down(&state.interface_name, PROVIDER)?;
                wireguard::connection::ConnectionState::remove(&state.instance_name)?;
            }
            wireguard::backend::WgBackend::Userspace => {
                wireguard::userspace::down(&state.interface_name)?;
                wireguard::connection::ConnectionState::remove(&state.instance_name)?;
            }
            wireguard::backend::WgBackend::LocalProxy => unreachable!(),
        }
    }

    hooks::run_ifdown(config, PROVIDER, state);
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

fn mullvad_web_client() -> anyhow::Result<Client> {
    let cookie_store = Arc::new(reqwest_cookie_store::CookieStoreMutex::new(
        reqwest_cookie_store::CookieStore::default(),
    ));
    Ok(Client::builder()
        .user_agent("tunmux")
        .cookie_provider(cookie_store)
        .build()?)
}

async fn create_account(client: &Client) -> anyhow::Result<String> {
    create_account_with_base(client, API_BASE).await
}

async fn create_account_with_base(client: &Client, api_base: &str) -> anyhow::Result<String> {
    let url = format!("{}/accounts/v1/accounts", api_base);
    let resp = client.post(url).send().await?;
    let account: MullvadCreateAccountResponse =
        parse_api_json(resp, "Mullvad account creation").await?;
    Ok(account.number)
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

async fn mullvad_web_login(client: &Client, account_number: &str) -> anyhow::Result<()> {
    mullvad_web_login_with_base(client, WEB_BASE, account_number).await
}

async fn mullvad_web_login_with_base(
    client: &Client,
    web_base: &str,
    account_number: &str,
) -> anyhow::Result<()> {
    let url = format!("{}/en/account/login", web_base);
    let origin = web_base.trim_end_matches('/');
    let referer = format!("{}/en/account/login", origin);
    let resp = client
        .post(url)
        .header("x-sveltekit-action", "true")
        .header("origin", origin)
        .header("referer", referer)
        .form(&[("account_number", account_number)])
        .send()
        .await?;

    let action: MullvadWebActionResponse = parse_api_json(resp, "Mullvad web login").await?;
    let is_successful_login = action.response_type == "redirect"
        && action.status == 302
        && action
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("/en/account"));

    if !is_successful_login {
        anyhow::bail!(
            "Mullvad web login failed: unexpected action response (type={}, status={})",
            action.response_type,
            action.status
        );
    }

    Ok(())
}

async fn fetch_monero_payment(client: &Client) -> anyhow::Result<MullvadMoneroPayment> {
    fetch_monero_payment_with_base(client, WEB_BASE).await
}

async fn fetch_monero_payment_with_base(
    client: &Client,
    web_base: &str,
) -> anyhow::Result<MullvadMoneroPayment> {
    let url = format!("{}/en/account/payment/monero", web_base);
    let origin = web_base.trim_end_matches('/');
    let referer = format!("{}/en/account/payment/monero", origin);
    let resp = client
        .post(url)
        .header("x-sveltekit-action", "true")
        .header("origin", origin)
        .header("referer", referer)
        .form(&[("understood", "on")])
        .send()
        .await?;

    let action: MullvadWebActionResponse =
        parse_api_json(resp, "Mullvad Monero payment request").await?;
    if action.response_type != "success" || action.status != 200 {
        anyhow::bail!(
            "Mullvad Monero payment request failed: unexpected action response (type={}, status={})",
            action.response_type,
            action.status
        );
    }

    let data = action
        .data
        .context("Mullvad Monero payment request returned no action data")?;
    parse_monero_payment_data(&data)
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

fn parse_monero_payment_data(data: &str) -> anyhow::Result<MullvadMoneroPayment> {
    let root: serde_json::Value = serde_json::from_str(data)
        .with_context(|| "failed to parse SvelteKit action data as JSON array")?;
    let values = root
        .as_array()
        .context("SvelteKit action data was not a JSON array")?;
    let mapping = values
        .first()
        .and_then(serde_json::Value::as_object)
        .context("SvelteKit action data did not include an index mapping object")?;

    let monthly_price =
        indexed_value_as_f64(values, mapping, "monthly_price").context("invalid monthly_price")?;
    let monthly_price_eur = indexed_value_as_f64(values, mapping, "monthly_price_eur")
        .context("invalid monthly_price_eur")?;
    let address = indexed_value_as_string(values, mapping, "address").context("invalid address")?;

    Ok(MullvadMoneroPayment {
        monthly_price,
        monthly_price_eur,
        address,
    })
}

fn indexed_value_as_f64(
    values: &[serde_json::Value],
    mapping: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<f64> {
    let value = indexed_value(values, mapping, key)?;
    if let Some(v) = value.as_f64() {
        return Ok(v);
    }
    if let Some(v) = value.as_i64() {
        return Ok(v as f64);
    }
    if let Some(v) = value.as_u64() {
        return Ok(v as f64);
    }
    if let Some(v) = value.as_str() {
        return v
            .parse::<f64>()
            .with_context(|| format!("value for {key} was not a number"));
    }
    anyhow::bail!("value for {key} was not a number")
}

fn indexed_value_as_string(
    values: &[serde_json::Value],
    mapping: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<String> {
    let value = indexed_value(values, mapping, key)?;
    value
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("value for {key} was not a string"))
}

fn indexed_value<'a>(
    values: &'a [serde_json::Value],
    mapping: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> anyhow::Result<&'a serde_json::Value> {
    let index = mapping
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .with_context(|| format!("missing index mapping for {key}"))? as usize;
    values
        .get(index)
        .with_context(|| format!("index mapping for {key} points out of bounds"))
}

fn save_account_id(account_id: &str) -> anyhow::Result<()> {
    let saved = SavedMullvadAccountId {
        account_id: account_id.to_string(),
    };
    let data = serde_json::to_vec_pretty(&saved)?;
    config::save_provider_file(PROVIDER, ACCOUNT_ID_FILE, &data)?;
    Ok(())
}

fn load_saved_account_id() -> anyhow::Result<Option<String>> {
    let data = match config::load_provider_file(PROVIDER, ACCOUNT_ID_FILE)? {
        Some(data) => data,
        None => return Ok(None),
    };

    let saved: SavedMullvadAccountId = serde_json::from_slice(&data)?;
    let id = saved.account_id.trim();
    if id.is_empty() {
        return Ok(None);
    }
    Ok(Some(id.to_string()))
}

fn resolve_account_id(explicit: Option<&str>, config: &AppConfig) -> anyhow::Result<String> {
    if let Some(id) = explicit.map(str::trim).filter(|id| !id.is_empty()) {
        save_account_id(id)?;
        return Ok(id.to_string());
    }

    if let Ok(session) = config::load_session::<MullvadSession>(PROVIDER, config) {
        let id = session.account_number.trim().to_string();
        if !id.is_empty() {
            save_account_id(&id)?;
            return Ok(id);
        }
    }

    if let Some(saved) = load_saved_account_id()? {
        return Ok(saved);
    }

    anyhow::bail!(
        "no Mullvad account ID available. Provide --account or run `tunmux mullvad create-account` / `tunmux mullvad login <account_number>` first."
    )
}

fn confirm_create_account_allowed(force: bool) -> anyhow::Result<()> {
    let existing = load_saved_account_id()?;
    confirm_account_overwrite(
        force,
        existing.as_deref(),
        None,
        "create a new Mullvad account",
    )
}

fn confirm_login_allowed(account_number: &str, force: bool) -> anyhow::Result<()> {
    let existing = load_saved_account_id()?;
    confirm_account_overwrite(
        force,
        existing.as_deref(),
        Some(account_number),
        "log in to Mullvad",
    )
}

fn confirm_account_overwrite(
    force: bool,
    existing_account_id: Option<&str>,
    requested_account_id: Option<&str>,
    action: &str,
) -> anyhow::Result<()> {
    if force {
        return Ok(());
    }

    let Some(existing_account_id) = existing_account_id else {
        return Ok(());
    };

    eprintln!("Warning: a saved Mullvad account ID already exists: {existing_account_id}");
    if let Some(requested_account_id) = requested_account_id {
        eprintln!("Requested account ID: {requested_account_id}");
    }
    eprintln!("You are about to {action}, which may replace the saved account ID.");
    eprint!("Continue? [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        return Ok(());
    }

    anyhow::bail!("Aborted by user")
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

    #[test]
    fn test_parse_monero_payment_data_sveltekit_indexed() {
        let encoded = r#"[{"monthly_price":1,"monthly_price_eur":2,"address":3},0.015705161763,4.5,"4FxacoBaGToSSWJAXmACVJjCtU27fzCrMAtTDs4jLNV8YUbN8NqYYv8btYJR97wMDNTAqP8fgYcvqG817jdDfd4UQT5Z6noxoH75NEVhff"]"#;
        let parsed = parse_monero_payment_data(encoded).unwrap();
        assert!((parsed.monthly_price - 0.015705161763).abs() < 1e-15);
        assert!((parsed.monthly_price_eur - 4.5).abs() < f64::EPSILON);
        assert_eq!(
            parsed.address,
            "4FxacoBaGToSSWJAXmACVJjCtU27fzCrMAtTDs4jLNV8YUbN8NqYYv8btYJR97wMDNTAqP8fgYcvqG817jdDfd4UQT5Z6noxoH75NEVhff"
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
    async fn test_monero_payment_web_flow_uses_login_cookie() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);

        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).ok();

            let (mut login_stream, _) = listener.accept().unwrap();
            let (request_line, headers, body) = read_http_request(&mut login_stream).unwrap();
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            assert!(parts.len() >= 2, "invalid request line: {request_line}");
            assert_eq!(parts[0], "POST");
            assert_eq!(parts[1], "/en/account/login");
            assert!(body.contains("account_number=1919656516838123"));
            let login_headers_lower = headers.to_ascii_lowercase();
            assert!(login_headers_lower.contains("x-sveltekit-action: true"));
            assert!(login_headers_lower.contains("content-type: application/x-www-form-urlencoded"));

            let login_body = r#"{"type":"redirect","status":302,"location":"/en/account"}"#;
            let login_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: accessToken=mva_test_cookie; Path=/; HttpOnly; SameSite=Lax\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                login_body.len(),
                login_body
            );
            login_stream.write_all(login_response.as_bytes()).unwrap();
            login_stream.flush().unwrap();

            let (mut payment_stream, _) = listener.accept().unwrap();
            let (request_line, headers, body) = read_http_request(&mut payment_stream).unwrap();
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            assert!(parts.len() >= 2, "invalid request line: {request_line}");
            assert_eq!(parts[0], "POST");
            assert_eq!(parts[1], "/en/account/payment/monero");
            assert!(body.contains("understood=on"));

            let payment_headers_lower = headers.to_ascii_lowercase();
            assert!(payment_headers_lower.contains("x-sveltekit-action: true"));
            assert!(payment_headers_lower.contains("cookie: accesstoken=mva_test_cookie"));

            let payment_body = r#"{"type":"success","status":200,"data":"[{\"monthly_price\":1,\"monthly_price_eur\":2,\"address\":3},0.015705161763,4.5,\"4FxacoBaGToSSWJAXmACVJjCtU27fzCrMAtTDs4jLNV8YUbN8NqYYv8btYJR97wMDNTAqP8fgYcvqG817jdDfd4UQT5Z6noxoH75NEVhff\"]"}"#;
            let payment_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payment_body.len(),
                payment_body
            );
            payment_stream
                .write_all(payment_response.as_bytes())
                .unwrap();
            payment_stream.flush().unwrap();
        });

        ready_rx.recv().unwrap();

        let client = mullvad_web_client().unwrap();
        mullvad_web_login_with_base(&client, &base, "1919656516838123")
            .await
            .unwrap();
        let payment = fetch_monero_payment_with_base(&client, &base)
            .await
            .unwrap();

        assert!((payment.monthly_price - 0.015705161763).abs() < 1e-15);
        assert!((payment.monthly_price_eur - 4.5).abs() < f64::EPSILON);
        assert_eq!(
            payment.address,
            "4FxacoBaGToSSWJAXmACVJjCtU27fzCrMAtTDs4jLNV8YUbN8NqYYv8btYJR97wMDNTAqP8fgYcvqG817jdDfd4UQT5Z6noxoH75NEVhff"
        );

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_create_account_flow() {
        let (base, handle) = spawn_mock_api_server(vec![ExpectedRequest {
            method: "POST",
            path: "/accounts/v1/accounts",
            must_contain_body: &[],
            must_contain_headers: &[],
            status: 201,
            body: r#"{"number":"1234123412341234"}"#,
        }]);

        let client = api_client().unwrap();
        let account = create_account_with_base(&client, &base).await.unwrap();
        assert_eq!(account, "1234123412341234");

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

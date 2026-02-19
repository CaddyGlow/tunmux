use crate::cli::{AirVpnCommand, ApiKeyAction, DeviceAction, PortAction};
use crate::config::{self, AppConfig, Provider};
use crate::error;
use crate::netns;
use crate::proxy;
use crate::wireguard;

use super::api::AirVpnClient;
use super::models::{AirManifest, AirSession};
use super::web::{AirVpnWeb, AirVpnWebApi};

const PROVIDER: Provider = Provider::AirVpn;
const INTERFACE_NAME: &str = "airvpn0";
const MANIFEST_FILE: &str = "manifest.json";

pub async fn dispatch(command: AirVpnCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        AirVpnCommand::Login { username } => cmd_login(&username, config).await,
        AirVpnCommand::Logout => cmd_logout(config).await,
        AirVpnCommand::Info => cmd_info(config),
        AirVpnCommand::Servers { country } => cmd_servers(country),
        AirVpnCommand::Connect {
            server,
            country,
            key,
            backend,
            proxy,
            socks_port,
            http_port,
        } => {
            cmd_connect(
                server, country, key, backend, proxy, socks_port, http_port, config,
            )
            .await
        }
        AirVpnCommand::Disconnect { instance, all } => cmd_disconnect(instance, all),
        AirVpnCommand::Sessions => cmd_sessions(config).await,
        AirVpnCommand::Ports { action } => cmd_ports(action, config).await,
        AirVpnCommand::Devices { action } => cmd_devices(action, config).await,
        AirVpnCommand::ApiKeys { action } => cmd_api_keys(action, config).await,
        AirVpnCommand::Generate {
            server,
            protocol,
            device,
            entry,
            exit,
            mtu,
            keepalive,
            output,
            format,
        } => {
            cmd_generate(
                &server, &protocol, device, &entry, &exit, mtu, keepalive, output, &format, config,
            )
            .await
        }
    }
}

async fn cmd_login(username: &str, config: &AppConfig) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;

    let client = AirVpnClient::new()?;

    // Authenticate
    let session = client.login(username, &password).await?;
    println!(
        "Authenticated as {} ({} WireGuard key(s))",
        username,
        session.keys.len()
    );

    // Fetch manifest (server list)
    let manifest = client.fetch_manifest(username, &password).await?;
    println!("Fetched {} servers", manifest.servers.len());

    // Save session and manifest
    config::save_session(PROVIDER, &session, config)?;
    save_manifest(&manifest)?;

    println!("Logged in as {}", username);
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    // Disconnect any direct connection if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        println!("Disconnecting active VPN connection...");
        disconnect_instance_direct()?;
    }

    config::delete_session(PROVIDER, config)?;

    // Also remove manifest
    let manifest_path = config::config_dir(PROVIDER).join(MANIFEST_FILE);
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path)?;
    }

    println!("Logged out");
    Ok(())
}

fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let session: AirSession = config::load_session(PROVIDER, config)?;
    println!("Username:   {}", session.username);
    println!("WG keys:    {}", session.keys.len());
    for key in &session.keys {
        println!(
            "  Key {:?}: IPv4={}, IPv6={}",
            key.name, key.wg_ipv4, key.wg_ipv6
        );
    }
    Ok(())
}

fn cmd_servers(country: Option<String>) -> anyhow::Result<()> {
    let manifest = load_manifest()?;
    let mut servers = manifest.servers;

    // Filter by country
    if let Some(ref cc) = country {
        let cc_upper = cc.to_uppercase();
        servers.retain(|s| s.country_code.eq_ignore_ascii_case(&cc_upper));
    }

    // Sort by name
    servers.sort_by(|a, b| a.name.cmp(&b.name));

    if servers.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    // Print header
    println!(
        "{:<20} {:>2}  {:>12}  {:>6}  {:>6}  Location",
        "Name", "CC", "Bandwidth", "Users", "Max"
    );
    let separator = "-".repeat(70);
    println!("{separator}");

    for s in &servers {
        let bw_mbps = s.bandwidth / 1_000_000;
        println!(
            "{:<20} {:>2}  {:>9} Mb  {:>4}/{:<4}  {}",
            s.name, s.country_code, bw_mbps, s.users, s.users_max, s.location,
        );
    }

    println!("\n{} servers listed", servers.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
    key_name: Option<String>,
    backend_arg: Option<String>,
    use_proxy: bool,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let backend_str = backend_arg.as_deref().unwrap_or(&config.general.backend);

    #[cfg(not(target_os = "linux"))]
    if use_proxy {
        anyhow::bail!("--proxy is available only on Linux");
    }

    if use_proxy && backend_str == "wg-quick" {
        anyhow::bail!("--proxy requires kernel backend (incompatible with --backend wg-quick)");
    }

    let backend = if use_proxy {
        wireguard::backend::WgBackend::Kernel
    } else {
        wireguard::backend::WgBackend::from_str_arg(backend_str)?
    };

    // Apply config defaults -- CLI flags override config
    let effective_country = country.or_else(|| config.airvpn.default_country.clone());
    let effective_key = key_name.or_else(|| config.airvpn.default_device.clone());

    let session: AirSession = config::load_session(PROVIDER, config)?;
    let manifest = load_manifest()?;

    // Select WireGuard key by name, or use the first one
    let wg_key = if let Some(ref name) = effective_key {
        session
            .keys
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                let available: Vec<&str> = session.keys.iter().map(|k| k.name.as_str()).collect();
                error::AppError::Other(format!(
                    "key {:?} not found. Available: {}",
                    name,
                    available.join(", ")
                ))
            })?
    } else {
        session
            .keys
            .first()
            .ok_or_else(|| error::AppError::Other("no WireGuard keys in session".into()))?
    };

    // Need at least one WireGuard mode
    let wg_mode = manifest
        .wg_modes
        .first()
        .ok_or_else(|| error::AppError::Other("no WireGuard modes in manifest".into()))?;

    // Select server
    let mut candidates = manifest.servers;

    let server = if let Some(ref name) = server_name {
        candidates
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| error::AppError::NoServerFound)?
            .clone()
    } else {
        // Apply filters
        if let Some(ref cc) = effective_country {
            let cc_upper = cc.to_uppercase();
            candidates.retain(|s| s.country_code.eq_ignore_ascii_case(&cc_upper));
        }

        // Sort by load (users/users_max ratio, lower is better)
        candidates.sort_by(|a, b| {
            let load_a = if a.users_max > 0 {
                a.users as f64 / a.users_max as f64
            } else {
                1.0
            };
            let load_b = if b.users_max > 0 {
                b.users as f64 / b.users_max as f64
            } else {
                1.0
            };
            load_a
                .partial_cmp(&load_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
            .first()
            .ok_or(error::AppError::NoServerFound)?
            .clone()
    };

    // Pick the entry IP based on the mode's entry_index
    let entry_idx = wg_mode.entry_index as usize;
    let server_ip = server
        .ips_entry
        .get(entry_idx)
        .or_else(|| server.ips_entry.first())
        .ok_or_else(|| error::AppError::NoServerFound)?;

    // Build WireGuard config params
    let ipv4_addr = &wg_key.wg_ipv4;
    let ipv6_addr = &wg_key.wg_ipv6;
    let dns_v4 = &wg_key.wg_dns_ipv4;
    let dns_v6 = &wg_key.wg_dns_ipv6;

    let mut addresses: Vec<&str> = Vec::new();
    if !ipv4_addr.is_empty() {
        addresses.push(ipv4_addr);
    }
    if !ipv6_addr.is_empty() {
        addresses.push(ipv6_addr);
    }

    let mut dns_servers: Vec<&str> = Vec::new();
    if !dns_v4.is_empty() {
        dns_servers.push(dns_v4);
    }
    if !dns_v6.is_empty() {
        dns_servers.push(dns_v6);
    }

    let preshared = if wg_key.wg_preshared.is_empty() {
        None
    } else {
        Some(wg_key.wg_preshared.as_str())
    };

    let params = wireguard::config::WgConfigParams {
        private_key: &wg_key.wg_private_key,
        addresses: &addresses,
        dns_servers: &dns_servers,
        server_public_key: &session.wg_public_key,
        server_ip,
        server_port: wg_mode.port,
        preshared_key: preshared,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    if use_proxy {
        connect_proxy(
            &server.name,
            &server.country_code,
            server_ip,
            wg_mode.port,
            &params,
            socks_port_arg,
            http_port_arg,
        )?;
    } else {
        connect_direct(
            &server.name,
            &server.country_code,
            server_ip,
            wg_mode.port,
            &params,
            backend,
        )?;
    }

    Ok(())
}

fn connect_proxy(
    server_name: &str,
    country_code: &str,
    server_ip: &str,
    _server_port: u16,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(server_name);

    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            server_name
        );
    }

    let interface_name = format!("wg-{}", instance);
    let namespace_name = format!("tunmux_{}", instance);

    let proxy_config = if let (Some(sp), Some(hp)) = (socks_port_arg, http_port_arg) {
        proxy::ProxyConfig {
            socks_port: sp,
            http_port: hp,
        }
    } else {
        let mut auto = proxy::next_available_ports()?;
        if let Some(sp) = socks_port_arg {
            auto.socks_port = sp;
        }
        if let Some(hp) = http_port_arg {
            auto.http_port = hp;
        }
        auto
    };

    println!("Connecting to {} ({})...", server_name, server_ip);

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
        server_display_name: server_name.to_string(),
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
        "Connected {} ({}) [{}] -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, server_name, country_code, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_direct(
    server_name: &str,
    country_code: &str,
    server_ip: &str,
    server_port: u16,
    params: &wireguard::config::WgConfigParams<'_>,
    backend: wireguard::backend::WgBackend,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        anyhow::bail!("Already connected. Run `tunmux airvpn disconnect` first.");
    }

    println!("Connecting to {} ({})...", server_name, server_ip);

    match backend {
        wireguard::backend::WgBackend::WgQuick => {
            let wg_config = wireguard::config::generate_config(params);
            wireguard::wg_quick::up(&wg_config, INTERFACE_NAME, PROVIDER)?;

            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: INTERFACE_NAME.to_string(),
                backend,
                server_endpoint: format!("{}:{}", server_ip, server_port),
                server_display_name: server_name.to_string(),
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
            wireguard::kernel::up(params, INTERFACE_NAME, PROVIDER.dir_name(), server_name)?;
        }
    }

    println!(
        "Connected to {} ({}) [backend: {}]",
        server_name, country_code, backend
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
            println!("No active airvpn connections.");
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
                "instance {:?} belongs to provider {:?}, not airvpn",
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
            println!("\nUsage: tunmux airvpn disconnect <instance>");
            println!("       tunmux airvpn disconnect --all");
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
        let netns_etc = format!("/etc/netns/{}", ns);
        if std::path::Path::new(&netns_etc).exists() {
            let _ = netns::remove_namespace_dir(ns);
        }
    }

    // Tear down WireGuard
    if state.namespace_name.is_some() {
        // Proxy mode: namespace deletion already removed the interface
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
        }
    }

    Ok(())
}

fn disconnect_instance_direct() -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;
    if let Some(state) = wireguard::connection::ConnectionState::load(DIRECT_INSTANCE)? {
        disconnect_one(&state)?;
    }
    Ok(())
}

async fn cmd_sessions(config: &AppConfig) -> anyhow::Result<()> {
    let session: AirSession = config::load_session(PROVIDER, config)?;
    let web = AirVpnWeb::login_or_restore(&session.username, &session.password).await?;

    let (sessions, message) = web.list_sessions().await?;
    web.save();

    if sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    for s in &sessions {
        let server = s.server_name();
        let location = s.server_location();
        let uptime = format_duration(s.connected_since);
        let tx = format_bytes(s.bytes_write);
        let rx = format_bytes(s.bytes_read);
        let tx_speed = format_speed(s.speed_write);
        let rx_speed = format_speed(s.speed_read);

        println!("{} on {} ({})", s.device_name, server, location);
        println!("  VPN:   {} / {}", s.vpn_ipv4, s.vpn_ipv6);
        println!("  Exit:  {} / {}", s.exit_ipv4, s.exit_ipv6);
        println!(
            "  Up {} -- TX {} ({}/s) / RX {} ({}/s)",
            uptime, tx, tx_speed, rx, rx_speed
        );
        println!(
            "  {} via {} -- DNS: {}",
            s.entry_layer, s.software_name, s.dns_filter
        );
        println!();
    }

    // Strip HTML tags from message
    let clean_msg = message.replace("<b>", "").replace("</b>", "");
    println!("{}", clean_msg);
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_speed(kbps: u64) -> String {
    if kbps >= 1024 {
        format!("{:.1} MiB", kbps as f64 / 1024.0)
    } else {
        format!("{} KiB", kbps)
    }
}

fn format_duration(connected_since: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let secs = (now - connected_since).max(0);
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

async fn cmd_ports(action: PortAction, config: &AppConfig) -> anyhow::Result<()> {
    let session: AirSession = config::load_session(PROVIDER, config)?;
    let web = AirVpnWeb::login_or_restore(&session.username, &session.password).await?;

    let result = match action {
        PortAction::List => cmd_ports_list(&web).await,
        PortAction::Add {
            port,
            protocol,
            local,
            ddns,
        } => cmd_ports_add(&web, port, &protocol, local, ddns).await,
        PortAction::Info { port } => cmd_ports_info(&web, port).await,
        PortAction::Check { port } => cmd_ports_check(&web, port).await,
        PortAction::Remove { port } => cmd_ports_remove(&web, port).await,
        PortAction::Set {
            port,
            protocol,
            local,
            ddns,
        } => cmd_ports_set(&web, port, protocol, local, ddns).await,
    };
    web.save();
    result
}

async fn cmd_ports_list(web: &AirVpnWeb) -> anyhow::Result<()> {
    let ports = web.list_ports().await?;

    if ports.is_empty() {
        println!("No forwarded ports.");
        return Ok(());
    }

    println!(
        "{:<8} {:<12} {:<8} {:<10} {:<10} DDNS",
        "Port", "Protocol", "Local", "Device", "Enabled"
    );
    println!("{}", "-".repeat(70));
    for fp in &ports {
        let local = if fp.local_port > 0 {
            fp.local_port.to_string()
        } else {
            "-".to_string()
        };
        let enabled = if fp.enabled { "yes" } else { "no" };
        let ddns = if fp.ddns.is_empty() {
            "-".to_string()
        } else {
            format!("{}.airdns.org", fp.ddns)
        };
        println!(
            "{:<8} {:<12} {:<8} {:<10} {:<10} {}",
            fp.port, fp.protocol, local, fp.device, enabled, ddns
        );
    }
    println!("\n{} port(s) forwarded", ports.len());
    Ok(())
}

async fn cmd_ports_add(
    web: &AirVpnWeb,
    port: u16,
    protocol: &str,
    local: Option<u16>,
    ddns: Option<String>,
) -> anyhow::Result<()> {
    let assigned = web.add_port(port).await?;
    if protocol != "both" {
        web.set_protocol(assigned, protocol).await?;
    }
    if let Some(lp) = local {
        web.set_local_port(assigned, lp).await?;
    }
    if let Some(ref name) = ddns {
        web.set_ddns(assigned, name).await?;
    }
    println!("Port {} ({}) forwarded", assigned, protocol);
    Ok(())
}

async fn cmd_ports_info(web: &AirVpnWeb, port: u16) -> anyhow::Result<()> {
    let sessions = web.port_sessions(port).await?;

    if sessions.is_empty() {
        println!("No active sessions for port {}.", port);
        return Ok(());
    }

    println!("Active sessions for port {}:\n", port);
    for s in &sessions {
        let local_port = match &s.local {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(v) => v.clone(),
            _ => "-".to_string(),
        };
        let ddns = if s.dns_name.is_empty() {
            "-".to_string()
        } else {
            format!("{}.airdns.org", s.dns_name)
        };
        println!(
            "  {} {} on {} ({}, {})",
            s.protocol.to_uppercase(),
            s.iplayer,
            s.server_name,
            s.server_location,
            s.server_country.to_uppercase(),
        );
        println!("    Server: {}  Client: {}", s.server_ip, s.client_ip);
        println!(
            "    Device: {}  Local: {}  DDNS: {}",
            s.device_name, local_port, ddns
        );
        println!();
    }

    println!("{} session(s)", sessions.len());
    Ok(())
}

async fn cmd_ports_check(web: &AirVpnWeb, port: u16) -> anyhow::Result<()> {
    let sessions = web.port_sessions(port).await?;

    if sessions.is_empty() {
        println!("No active sessions for port {}.", port);
        return Ok(());
    }

    // Deduplicate by (server_ip, protocol) -- sessions can have v4+v6 entries
    let mut tested: Vec<(String, String)> = Vec::new();
    for s in &sessions {
        let key = (s.server_ip.clone(), s.protocol.clone());
        if tested.contains(&key) {
            continue;
        }
        tested.push(key);

        let result = web
            .test_port(&s.server_ip, port, s.pool, &s.protocol)
            .await?;
        println!(
            "{} {} {} ({}): {}",
            s.server_name,
            s.protocol.to_uppercase(),
            s.iplayer,
            s.server_ip,
            result.message
        );
    }
    Ok(())
}

async fn cmd_ports_remove(web: &AirVpnWeb, port: u16) -> anyhow::Result<()> {
    web.remove_port(port).await?;
    println!("Port {} removed", port);
    Ok(())
}

async fn cmd_ports_set(
    web: &AirVpnWeb,
    port: u16,
    protocol: Option<String>,
    local: Option<u16>,
    ddns: Option<String>,
) -> anyhow::Result<()> {
    if protocol.is_none() && local.is_none() && ddns.is_none() {
        println!("Nothing to change. Use --protocol, --local, or --ddns.");
        return Ok(());
    }

    if let Some(ref proto) = protocol {
        web.set_protocol(port, proto).await?;
        println!("Port {} protocol set to {}", port, proto);
    }
    if let Some(lp) = local {
        web.set_local_port(port, lp).await?;
        println!("Port {} local port set to {}", port, lp);
    }
    if let Some(ref name) = ddns {
        web.set_ddns(port, name).await?;
        let display = name.trim_end_matches(".airdns.org").trim_end_matches('.');
        println!("Port {} DDNS set to {}.airdns.org", port, display);
    }
    Ok(())
}

async fn cmd_devices(action: DeviceAction, config: &AppConfig) -> anyhow::Result<()> {
    let session: AirSession = config::load_session(PROVIDER, config)?;
    let web = AirVpnWeb::login_or_restore(&session.username, &session.password).await?;

    let result = match action {
        DeviceAction::List => cmd_devices_list(&web).await,
        DeviceAction::Add { name } => cmd_devices_add(&web, name).await,
        DeviceAction::Rename { device, name } => cmd_devices_rename(&web, &device, &name).await,
        DeviceAction::Delete { device } => cmd_devices_delete(&web, &device).await,
    };
    web.save();
    result
}

async fn cmd_devices_list(web: &AirVpnWeb) -> anyhow::Result<()> {
    let devices = web.list_devices().await?;

    if devices.is_empty() {
        println!("No devices.");
        return Ok(());
    }

    println!("{:<16} {:<18} {:<44} Public Key", "Name", "IPv4", "IPv6");
    println!("{}", "-".repeat(110));
    for d in &devices {
        let key_short = if d.wg_public_key.len() > 20 {
            format!("{}...", &d.wg_public_key[..20])
        } else {
            d.wg_public_key.clone()
        };
        println!(
            "{:<16} {:<18} {:<44} {}",
            d.name, d.wg_ipv4, d.wg_ipv6, key_short
        );
    }
    println!("\n{} device(s)", devices.len());
    Ok(())
}

async fn cmd_devices_add(web: &AirVpnWeb, name: Option<String>) -> anyhow::Result<()> {
    let id = web.add_device().await?;

    if let Some(ref n) = name {
        web.rename_device(&id, n).await?;
        println!("Device {:?} created", n);
    } else {
        println!("Device created (name: \"New device\")");
    }
    Ok(())
}

async fn cmd_devices_rename(web: &AirVpnWeb, device: &str, new_name: &str) -> anyhow::Result<()> {
    let id = web.lookup_device_id(device).await?;
    web.rename_device(&id, new_name).await?;
    println!("Device {:?} renamed to {:?}", device, new_name);
    Ok(())
}

async fn cmd_devices_delete(web: &AirVpnWeb, device: &str) -> anyhow::Result<()> {
    let id = web.lookup_device_id(device).await?;
    web.delete_device(&id).await?;
    println!("Device {:?} deleted", device);
    Ok(())
}

async fn cmd_api_keys(action: ApiKeyAction, config: &AppConfig) -> anyhow::Result<()> {
    let session: AirSession = config::load_session(PROVIDER, config)?;
    let web = AirVpnWeb::login_or_restore(&session.username, &session.password).await?;

    let result = match action {
        ApiKeyAction::List => cmd_api_keys_list(&web).await,
        ApiKeyAction::Add { name } => cmd_api_keys_add(&web, name).await,
        ApiKeyAction::Rename { key, name } => cmd_api_keys_rename(&web, &key, &name).await,
        ApiKeyAction::Delete { key } => cmd_api_keys_delete(&web, &key).await,
    };
    web.save();
    result
}

async fn cmd_api_keys_list(web: &AirVpnWeb) -> anyhow::Result<()> {
    let keys = web.list_api_keys().await?;

    if keys.is_empty() {
        println!("No API keys.");
        return Ok(());
    }

    println!("{:<16} {:<14} Secret", "Name", "Created");
    println!("{}", "-".repeat(60));
    for k in &keys {
        let created = if k.creation_date > 0 {
            chrono_lite(k.creation_date)
        } else {
            "-".to_string()
        };
        println!("{:<16} {:<14} {}", k.name, created, k.secret_short);
    }
    println!("\n{} key(s)", keys.len());
    Ok(())
}

async fn cmd_api_keys_add(web: &AirVpnWeb, name: Option<String>) -> anyhow::Result<()> {
    let id = web.add_api_key().await?;

    if let Some(ref n) = name {
        web.rename_api_key(&id, n).await?;
    }

    // Fetch the key to show the full secret
    let keys = web.list_api_keys().await?;
    let key = keys.iter().find(|k| k.id == id);
    if let Some(k) = key {
        let label = if name.is_some() {
            k.name.as_str()
        } else {
            "default"
        };
        println!("API key {:?} created", label);
        println!("Secret: {}", k.secret);
    } else {
        println!("API key created");
    }
    Ok(())
}

async fn cmd_api_keys_rename(web: &AirVpnWeb, key: &str, new_name: &str) -> anyhow::Result<()> {
    let id = web.lookup_api_key_id(key).await?;
    web.rename_api_key(&id, new_name).await?;
    println!("API key {:?} renamed to {:?}", key, new_name);
    Ok(())
}

async fn cmd_api_keys_delete(web: &AirVpnWeb, key: &str) -> anyhow::Result<()> {
    let id = web.lookup_api_key_id(key).await?;
    web.delete_api_key(&id).await?;
    println!("API key {:?} deleted", key);
    Ok(())
}

/// Format a unix timestamp as YYYY-MM-DD (no chrono dependency).
fn chrono_lite(ts: i64) -> String {
    // Days from unix epoch
    let secs_per_day: i64 = 86400;
    let mut days = ts / secs_per_day;

    let mut year = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    for md in &month_days {
        if days < *md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;

    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[allow(clippy::too_many_arguments)]
async fn cmd_generate(
    servers: &[String],
    protocols: &[String],
    device: Option<String>,
    entry: &str,
    exit: &str,
    mtu: u16,
    keepalive: u16,
    output: Option<String>,
    format: &str,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let mut session: AirSession = config::load_session(PROVIDER, config)?;
    let manifest = load_manifest()?;

    // Build protocol values. Default: first WireGuard mode from the manifest.
    let proto_values: Vec<String> = if protocols.is_empty() {
        let wg_mode = manifest
            .wg_modes
            .first()
            .ok_or_else(|| error::AppError::Other("no WireGuard modes in manifest".into()))?;
        vec![format!(
            "wireguard_3_{}_{}",
            wg_mode.protocol.to_lowercase(),
            wg_mode.port
        )]
    } else {
        protocols.iter().map(|p| resolve_protocol(p)).collect()
    };
    let protocols_value = proto_values.join(",");

    // Join multiple servers with comma.
    let servers_value = servers.join(",");

    // Device name: use provided or first from session
    let device_name = device.unwrap_or_else(|| {
        session
            .keys
            .first()
            .map(|k| k.name.clone())
            .unwrap_or_default()
    });

    let mtu_str = mtu.to_string();
    let keepalive_str = keepalive.to_string();

    // Multiple files when >1 server or >1 protocol.
    let multi = servers.len() > 1 || proto_values.len() > 1;
    let download = if multi { format } else { "auto" };

    let form: Vec<(&str, &str)> = vec![
        ("protocols", &protocols_value),
        ("servers", &servers_value),
        ("download", download),
        ("system", "linux"),
        ("iplayer_entry", entry),
        ("iplayer_exit", exit),
        ("wireguard_mtu", &mtu_str),
        ("wireguard_persistent_keepalive", &keepalive_str),
        ("device", &device_name),
    ];

    let api = AirVpnWebApi::from_session(&mut session, config).await?;

    if multi {
        let default_name = format!("airvpn.{}", format);
        let out = output.unwrap_or(default_name);

        let (data, _content_type) = api.post_bytes("generator", &form).await?;
        std::fs::write(&out, &data)?;
        println!("Config written to {} ({}B)", out, data.len());
    } else {
        let config = api.post_text("generator", &form).await?;
        match output {
            Some(path) => {
                std::fs::write(&path, &config)?;
                println!("Config written to {}", path);
            }
            None => {
                print!("{}", config);
            }
        }
    }

    Ok(())
}

/// Resolve a user-friendly protocol name to the generator API format.
fn resolve_protocol(name: &str) -> String {
    let lower = name.to_lowercase();

    // Already in raw format
    if lower.starts_with("wireguard_") || lower.starts_with("openvpn_") {
        return lower;
    }

    // wg or wg-PORT
    if lower == "wg" || lower == "wireguard" {
        return "wireguard_3_udp_1637".to_string();
    }
    if let Some(port) = lower.strip_prefix("wg-") {
        return format!("wireguard_3_udp_{}", port);
    }

    // openvpn-TRANSPORT-PORT  (all OpenVPN protocols use entry_index 1)
    if let Some(rest) = lower.strip_prefix("openvpn-") {
        if rest.contains('-') {
            return format!("openvpn_1_{}", rest.replacen('-', "_", 1));
        }
    }

    // Fallback: pass through as-is
    name.to_string()
}

fn save_manifest(manifest: &AirManifest) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    config::save_provider_file(PROVIDER, MANIFEST_FILE, json.as_bytes())?;
    Ok(())
}

fn load_manifest() -> anyhow::Result<AirManifest> {
    let data = config::load_provider_file(PROVIDER, MANIFEST_FILE)?.ok_or_else(|| {
        error::AppError::Other("no cached manifest -- run `tunmux airvpn login` first".into())
    })?;
    let manifest: AirManifest = serde_json::from_slice(&data)?;
    Ok(manifest)
}

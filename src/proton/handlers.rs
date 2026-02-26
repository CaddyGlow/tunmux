use std::cmp::Ordering;
use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cli::{ProtonCommand, ProtonPortAction};
use crate::config::{self, AppConfig, Provider};
use crate::error;
use crate::local_proxy;
use crate::netns;
use crate::proxy;
use crate::shared::connection_ops;
use crate::shared::crypto;
use crate::shared::hooks;
use crate::shared::latency;
use crate::wireguard;
use x509_parser::prelude::FromDer;

use super::{api, models};

const PROVIDER: Provider = Provider::Proton;
const INTERFACE_NAME: &str = "proton0";
const MANIFEST_FILE: &str = "manifest.json";
const PORT_FORWARD_FILE: &str = "port_forwards.json";
const PORT_FORWARD_DAEMON_PID_FILE: &str = "port_forward_daemon.pid";
const PORT_FORWARD_DAEMON_LOG_FILE: &str = "port_forward_daemon.log";
const NAT_PMP_PORT: u16 = 5351;
const NAT_PMP_DEFAULT_GATEWAY: &str = "10.2.0.1";

#[derive(serde::Deserialize, serde::Serialize)]
struct ProtonManifest {
    logical_servers: Vec<models::server::LogicalServer>,
}

pub async fn dispatch(command: ProtonCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        ProtonCommand::Login { username } => cmd_login(&username, config).await,
        ProtonCommand::Logout => cmd_logout(config).await,
        ProtonCommand::Info => cmd_info(config),
        ProtonCommand::Renew => cmd_renew(config).await,
        ProtonCommand::Servers {
            country,
            free,
            tag,
            sort,
        } => cmd_servers(country, free, tag, sort, config).await,
        ProtonCommand::Connect(args) => {
            cmd_connect(
                args.server,
                args.country,
                args.p2p,
                args.port_forwarding,
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
        ProtonCommand::Ports { action } => cmd_ports(action, config).await,
        ProtonCommand::Disconnect { instance, all } => cmd_disconnect(instance, all, config),
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
    let cert = api::certificate::fetch_certificate(&client, &keys.ed25519_pk_pem(), false).await?;

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
        certificate_port_forwarding: false,
    };

    config::save_session(PROVIDER, &session, config)?;
    println!("Logged in as {} ({})", username, session.plan_title);
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    stop_proton_ports_daemon()?;
    clear_proton_ports_daemon_log_file()?;

    // Disconnect if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        println!("Disconnecting active VPN connection...");
        disconnect_instance_direct(config)?;
    }

    config::delete_session(PROVIDER, config)?;
    clear_proton_port_forward_state_file()?;

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

async fn cmd_renew(config: &AppConfig) -> anyhow::Result<()> {
    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    let keep_port_forwarding = session.certificate_port_forwarding;
    renew_proton_certificate(&mut session, config, keep_port_forwarding)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "could not renew Proton certificate from saved session (token may be expired): {}. run `tunmux proton login <username>`",
                err
            )
        })?;
    println!("Proton VPN certificate renewed.");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProtonNatPmpProtocol {
    Tcp,
    Udp,
}

impl ProtonNatPmpProtocol {
    fn opcode(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Tcp => 2,
        }
    }
}

impl std::fmt::Display for ProtonNatPmpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProtonPortForwardRecord {
    protocol: ProtonNatPmpProtocol,
    public_port: u16,
    local_port: u16,
    lifetime_secs: u32,
    expires_at_unix: u64,
    gateway: String,
    instance_name: String,
    interface_name: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ProtonPortForwardState {
    #[serde(default)]
    mappings: Vec<ProtonPortForwardRecord>,
}

#[derive(Debug)]
struct ProtonNatPmpMapResponse {
    public_port: u16,
    lifetime_secs: u32,
}

async fn cmd_ports(action: ProtonPortAction, config: &AppConfig) -> anyhow::Result<()> {
    match action {
        ProtonPortAction::List { current, json } => cmd_ports_list(current, json),
        ProtonPortAction::Request {
            protocol,
            public_port,
            local_port,
            lifetime,
            no_daemon,
        } => {
            cmd_ports_request(
                &protocol,
                public_port,
                local_port,
                lifetime,
                no_daemon,
                config,
            )
            .await
        }
        ProtonPortAction::Renew { lifetime } => cmd_ports_renew(lifetime, config).await,
        ProtonPortAction::Release => cmd_ports_release(config).await,
        ProtonPortAction::Daemon {
            protocol,
            public_port,
            local_port,
            lifetime,
            renew_every,
            no_initial_request,
        } => {
            cmd_ports_daemon(
                &protocol,
                public_port,
                local_port,
                lifetime,
                renew_every,
                no_initial_request,
                config,
            )
            .await
        }
    }
}

fn cmd_ports_list(current_only: bool, json_output: bool) -> anyhow::Result<()> {
    let mut state = load_proton_port_forward_state()?;

    let now = current_unix_timestamp()? as u64;
    if current_only {
        let conn = require_active_proton_direct_connection()?;
        state.mappings.retain(|mapping| {
            mapping.instance_name == conn.instance_name
                && mapping.interface_name == conn.interface_name
                && mapping.expires_at_unix > now
        });
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&state.mappings)?);
        return Ok(());
    }

    if state.mappings.is_empty() {
        if current_only {
            println!("No current Proton forwarded ports.");
        } else {
            println!("No saved Proton forwarded ports.");
        }
        return Ok(());
    }

    state.mappings.sort_by(|a, b| {
        a.instance_name
            .cmp(&b.instance_name)
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| a.public_port.cmp(&b.public_port))
    });

    println!(
        "{:<8} {:<8} {:<8} {:<10} {:<12} {:<10} Gateway",
        "Proto", "Public", "Local", "Lifetime", "ExpiresIn", "Instance"
    );
    println!("{}", "-".repeat(80));
    for mapping in &state.mappings {
        let expires_in = if mapping.expires_at_unix > now {
            format!("{}s", mapping.expires_at_unix - now)
        } else {
            "expired".to_string()
        };
        println!(
            "{:<8} {:<8} {:<8} {:<10} {:<12} {:<10} {}",
            mapping.protocol,
            mapping.public_port,
            mapping.local_port,
            mapping.lifetime_secs,
            expires_in,
            mapping.instance_name,
            mapping.gateway
        );
    }
    println!("\n{} mapping(s) saved", state.mappings.len());
    Ok(())
}

async fn cmd_ports_request(
    protocol: &str,
    public_port: u16,
    local_port: u16,
    lifetime: u32,
    no_daemon: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    cmd_ports_request_once(protocol, public_port, local_port, lifetime, config).await?;
    if no_daemon {
        return Ok(());
    }

    stop_proton_ports_daemon()?;
    let renew_every = default_proton_ports_renew_every(lifetime);
    let pid = spawn_proton_ports_daemon(protocol, public_port, local_port, lifetime, renew_every)?;
    println!(
        "Started Proton port-forward daemon (pid {}, renew every {}s)",
        pid, renew_every
    );
    Ok(())
}

async fn cmd_ports_request_once(
    protocol: &str,
    public_port: u16,
    local_port: u16,
    lifetime: u32,
    config: &AppConfig,
) -> anyhow::Result<()> {
    if lifetime == 0 {
        anyhow::bail!("lifetime must be greater than 0");
    }

    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    ensure_proton_port_forwarding_certificate_ready(&mut session, config).await?;

    let conn = require_active_proton_direct_connection()?;
    let gateway = proton_nat_pmp_gateway_for_state(&conn);
    let protocols = parse_proton_nat_pmp_protocols(protocol)?;
    let mut requested_public_port = public_port;
    let now = current_unix_timestamp()? as u64;

    let mut new_mappings = Vec::new();
    for (index, proto) in protocols.iter().enumerate() {
        let response = nat_pmp_map_request(
            &gateway,
            *proto,
            local_port,
            requested_public_port,
            lifetime,
        )
        .await?;
        if index == 0 && public_port == 0 && protocols.len() > 1 {
            requested_public_port = response.public_port;
        }

        let record = ProtonPortForwardRecord {
            protocol: *proto,
            public_port: response.public_port,
            local_port,
            lifetime_secs: response.lifetime_secs,
            expires_at_unix: now.saturating_add(response.lifetime_secs as u64),
            gateway: gateway.clone(),
            instance_name: conn.instance_name.clone(),
            interface_name: conn.interface_name.clone(),
        };
        new_mappings.push(record);
    }

    let mut state = load_proton_port_forward_state()?;
    state.mappings.retain(|mapping| {
        !(mapping.instance_name == conn.instance_name && protocols.contains(&mapping.protocol))
    });
    state.mappings.extend(new_mappings.iter().cloned());
    save_proton_port_forward_state(&state)?;

    for mapping in &new_mappings {
        println!(
            "Forwarded {} public {} (local {}, lifetime {}s)",
            mapping.protocol, mapping.public_port, mapping.local_port, mapping.lifetime_secs
        );
    }
    Ok(())
}

async fn cmd_ports_renew(lifetime: u32, config: &AppConfig) -> anyhow::Result<()> {
    if lifetime == 0 {
        anyhow::bail!("lifetime must be greater than 0");
    }

    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    ensure_proton_port_forwarding_certificate_ready(&mut session, config).await?;

    let conn = require_active_proton_direct_connection()?;
    let gateway = proton_nat_pmp_gateway_for_state(&conn);
    let now = current_unix_timestamp()? as u64;

    let mut state = load_proton_port_forward_state()?;
    let mut renewed = 0usize;
    for mapping in state.mappings.iter_mut().filter(|mapping| {
        mapping.instance_name == conn.instance_name && mapping.interface_name == conn.interface_name
    }) {
        let response = nat_pmp_map_request(
            &gateway,
            mapping.protocol,
            mapping.local_port,
            mapping.public_port,
            lifetime,
        )
        .await?;
        mapping.public_port = response.public_port;
        mapping.lifetime_secs = response.lifetime_secs;
        mapping.expires_at_unix = now.saturating_add(response.lifetime_secs as u64);
        mapping.gateway = gateway.clone();
        renewed = renewed.saturating_add(1);
        println!(
            "Renewed {} public {} (lifetime {}s)",
            mapping.protocol, mapping.public_port, mapping.lifetime_secs
        );
    }

    if renewed == 0 {
        anyhow::bail!("no saved Proton mappings for the active connection. Run `tunmux proton ports request` first");
    }

    save_proton_port_forward_state(&state)?;
    Ok(())
}

async fn cmd_ports_daemon(
    protocol: &str,
    public_port: u16,
    local_port: u16,
    lifetime: u32,
    renew_every: u64,
    no_initial_request: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    if lifetime == 0 {
        anyhow::bail!("lifetime must be greater than 0");
    }
    if renew_every == 0 {
        anyhow::bail!("renew interval must be greater than 0");
    }
    if renew_every >= u64::from(lifetime) {
        tracing::warn!(
            renew_every,
            lifetime,
            "proton_ports_daemon_interval_not_less_than_lifetime"
        );
    }

    write_proton_ports_daemon_pid_file(std::process::id())?;
    let result = async {
        if !no_initial_request {
            cmd_ports_request_once(protocol, public_port, local_port, lifetime, config).await?;
        }
        println!(
            "Keeping Proton mappings alive (renew every {}s, Ctrl-C to stop)",
            renew_every
        );

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("Stopping Proton port forwarding daemon.");
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_secs(renew_every)) => {
                    if let Err(err) = cmd_ports_renew(lifetime, config).await {
                        tracing::warn!(
                            error = %err,
                            "proton_ports_daemon_renew_failed_retrying_request"
                        );
                        eprintln!("Renew failed: {}. Requesting a fresh mapping...", err);
                        cmd_ports_request_once(protocol, public_port, local_port, lifetime, config).await?;
                    }
                }
            }
        }
    }
    .await;
    let _ = clear_proton_ports_daemon_pid_file();
    result
}

async fn cmd_ports_release(_config: &AppConfig) -> anyhow::Result<()> {
    stop_proton_ports_daemon()?;

    let conn = require_active_proton_direct_connection()?;
    let mut state = load_proton_port_forward_state()?;
    let target_indexes: Vec<usize> = state
        .mappings
        .iter()
        .enumerate()
        .filter(|(_, mapping)| {
            mapping.instance_name == conn.instance_name
                && mapping.interface_name == conn.interface_name
        })
        .map(|(idx, _)| idx)
        .collect();

    if target_indexes.is_empty() {
        println!("No saved Proton mappings for active connection.");
        return Ok(());
    }

    let mut released = Vec::new();
    for index in target_indexes {
        let mapping = state
            .mappings
            .get(index)
            .cloned()
            .expect("mapping index must exist");
        nat_pmp_map_request(
            &mapping.gateway,
            mapping.protocol,
            mapping.local_port,
            mapping.public_port,
            0,
        )
        .await?;
        println!(
            "Released {} public {} (local {})",
            mapping.protocol, mapping.public_port, mapping.local_port
        );
        released.push(mapping);
    }

    state.mappings.retain(|mapping| {
        !released.iter().any(|released_mapping| {
            mapping.instance_name == released_mapping.instance_name
                && mapping.interface_name == released_mapping.interface_name
                && mapping.protocol == released_mapping.protocol
                && mapping.local_port == released_mapping.local_port
                && mapping.public_port == released_mapping.public_port
        })
    });
    save_proton_port_forward_state(&state)?;
    Ok(())
}

fn default_proton_ports_renew_every(lifetime: u32) -> u64 {
    let lifetime_u64 = u64::from(lifetime);
    if lifetime_u64 <= 5 {
        return 1;
    }
    lifetime_u64.saturating_sub(15).max(1)
}

fn proton_ports_daemon_pid_path() -> std::path::PathBuf {
    config::config_dir(PROVIDER).join(PORT_FORWARD_DAEMON_PID_FILE)
}

fn proton_ports_daemon_log_path() -> std::path::PathBuf {
    config::config_dir(PROVIDER).join(PORT_FORWARD_DAEMON_LOG_FILE)
}

fn write_proton_ports_daemon_pid_file(pid: u32) -> anyhow::Result<()> {
    let path = proton_ports_daemon_pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", pid))?;
    Ok(())
}

fn clear_proton_ports_daemon_pid_file() -> anyhow::Result<()> {
    let path = proton_ports_daemon_pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn clear_proton_ports_daemon_log_file() -> anyhow::Result<()> {
    let path = proton_ports_daemon_log_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn read_proton_ports_daemon_pid() -> anyhow::Result<Option<u32>> {
    let path = proton_ports_daemon_pid_path();
    if !path.exists() {
        return Ok(None);
    }
    let pid = std::fs::read_to_string(path)?
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid Proton port daemon pid file: {}", e))?;
    Ok(Some(pid))
}

fn spawn_proton_ports_daemon(
    protocol: &str,
    public_port: u16,
    local_port: u16,
    lifetime: u32,
    renew_every: u64,
) -> anyhow::Result<u32> {
    let exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
    let log_path = proton_ports_daemon_log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log.try_clone()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.args([
        "proton",
        "ports",
        "daemon",
        "--protocol",
        protocol,
        "--public-port",
        &public_port.to_string(),
        "--local-port",
        &local_port.to_string(),
        "--lifetime",
        &lifetime.to_string(),
        "--renew-every",
        &renew_every.to_string(),
        "--no-initial-request",
    ])
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::from(log))
    .stderr(std::process::Stdio::from(log_err));

    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn Proton port daemon: {}", e))?;
    write_proton_ports_daemon_pid_file(child.id())?;
    Ok(child.id())
}

fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn stop_proton_ports_daemon() -> anyhow::Result<()> {
    let Some(pid) = read_proton_ports_daemon_pid()? else {
        return Ok(());
    };
    if !process_alive(pid) {
        clear_proton_ports_daemon_pid_file()?;
        return Ok(());
    }

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !process_alive(pid) {
                clear_proton_ports_daemon_pid_file()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !process_alive(pid) {
                clear_proton_ports_daemon_pid_file()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        anyhow::bail!("failed to stop Proton port daemon pid {}", pid);
    }
    #[cfg(not(unix))]
    {
        clear_proton_ports_daemon_pid_file()?;
        Ok(())
    }
}

fn parse_proton_nat_pmp_protocols(protocol: &str) -> anyhow::Result<Vec<ProtonNatPmpProtocol>> {
    match protocol {
        "both" => Ok(vec![ProtonNatPmpProtocol::Tcp, ProtonNatPmpProtocol::Udp]),
        "tcp" => Ok(vec![ProtonNatPmpProtocol::Tcp]),
        "udp" => Ok(vec![ProtonNatPmpProtocol::Udp]),
        other => anyhow::bail!(
            "unsupported protocol {:?}; expected one of: both, tcp, udp",
            other
        ),
    }
}

fn require_active_proton_direct_connection(
) -> anyhow::Result<wireguard::connection::ConnectionState> {
    use wireguard::connection::{ConnectionState, DIRECT_INSTANCE};

    if let Some(state) = ConnectionState::load(DIRECT_INSTANCE)?
        .filter(|state| state.provider == PROVIDER.dir_name() && state.namespace_name.is_none())
    {
        return Ok(state);
    }

    let candidates: Vec<ConnectionState> = ConnectionState::load_all()?
        .into_iter()
        .filter(|state| {
            state.provider == PROVIDER.dir_name()
                && state.namespace_name.is_none()
                && state.interface_name == INTERFACE_NAME
        })
        .collect();

    match candidates.len() {
        0 => anyhow::bail!(
            "no active direct Proton connection. Connect first with `tunmux proton connect ...`"
        ),
        1 => Ok(candidates.into_iter().next().expect("single element")),
        _ => {
            let names: Vec<String> = candidates
                .into_iter()
                .map(|state| state.instance_name)
                .collect();
            anyhow::bail!(
                "multiple direct Proton connections found ({}). Disconnect extras or use the direct instance",
                names.join(", ")
            )
        }
    }
}

fn proton_nat_pmp_gateway_for_state(state: &wireguard::connection::ConnectionState) -> String {
    state
        .dns_servers
        .iter()
        .find_map(|value| value.parse::<Ipv4Addr>().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| NAT_PMP_DEFAULT_GATEWAY.to_string())
}

async fn nat_pmp_map_request(
    gateway: &str,
    protocol: ProtonNatPmpProtocol,
    local_port: u16,
    public_port: u16,
    lifetime: u32,
) -> anyhow::Result<ProtonNatPmpMapResponse> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let target = format!("{}:{}", gateway, NAT_PMP_PORT);

    let mut request = [0_u8; 12];
    request[0] = 0;
    request[1] = protocol.opcode();
    request[4..6].copy_from_slice(&local_port.to_be_bytes());
    request[6..8].copy_from_slice(&public_port.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime.to_be_bytes());

    socket.send_to(&request, &target).await?;

    let mut response = [0_u8; 64];
    let (size, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut response))
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for NAT-PMP reply from {}", target))??;
    if size < 16 {
        anyhow::bail!("NAT-PMP reply too short: {} bytes", size);
    }

    if response[0] != 0 {
        anyhow::bail!("unexpected NAT-PMP version {}", response[0]);
    }
    let expected_opcode = protocol.opcode().saturating_add(128);
    if response[1] != expected_opcode {
        anyhow::bail!(
            "unexpected NAT-PMP opcode {} (expected {})",
            response[1],
            expected_opcode
        );
    }

    let result_code = u16::from_be_bytes([response[2], response[3]]);
    if result_code != 0 {
        anyhow::bail!(
            "NAT-PMP request failed with code {} ({})",
            result_code,
            nat_pmp_result_code_desc(result_code)
        );
    }

    let mapped_public_port = u16::from_be_bytes([response[10], response[11]]);
    let mapped_lifetime_secs =
        u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    Ok(ProtonNatPmpMapResponse {
        public_port: mapped_public_port,
        lifetime_secs: mapped_lifetime_secs,
    })
}

fn nat_pmp_result_code_desc(result_code: u16) -> &'static str {
    match result_code {
        0 => "success",
        1 => "unsupported NAT-PMP version",
        2 => "not authorized/refused",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "unknown error",
    }
}

fn load_proton_port_forward_state() -> anyhow::Result<ProtonPortForwardState> {
    let data = match config::load_provider_file(PROVIDER, PORT_FORWARD_FILE)? {
        Some(data) => data,
        None => return Ok(ProtonPortForwardState::default()),
    };
    let state: ProtonPortForwardState = serde_json::from_slice(&data)?;
    Ok(state)
}

fn save_proton_port_forward_state(state: &ProtonPortForwardState) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    config::save_provider_file(PROVIDER, PORT_FORWARD_FILE, json.as_bytes())?;
    Ok(())
}

fn clear_proton_port_forward_state_file() -> anyhow::Result<()> {
    let path = config::config_dir(PROVIDER).join(PORT_FORWARD_FILE);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

async fn cmd_servers(
    country: Option<String>,
    free: bool,
    tags: Vec<String>,
    sort: String,
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

    let requested_tags = parse_proton_feature_tags(&tags)?;
    apply_proton_feature_filters(&mut servers, &requested_tags);

    let sort_by_latency = sort == "latency";

    if sort_by_latency {
        let targets: Vec<(String, u16)> = servers
            .iter()
            .map(|server| {
                let host = server
                    .best_physical()
                    .map(|physical| physical.entry_ip.clone())
                    .unwrap_or_else(|| server.domain.clone());
                (host, 51820)
            })
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut rows: Vec<(models::server::LogicalServer, Option<Duration>)> =
            servers.into_iter().zip(latencies).collect();
        rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1)
                .then_with(|| a.0.score.partial_cmp(&b.0.score).unwrap_or(Ordering::Equal))
                .then_with(|| a.0.name.cmp(&b.0.name))
        });

        if rows.is_empty() {
            println!("No servers match the given filters.");
            return Ok(());
        }

        println!(
            "{:<16} {:>2}  {:>5}  {:>5}  {:>4}  {:>8}  Features",
            "Name", "CC", "Load", "Score", "Tier", "Latency"
        );
        println!("{}", "-".repeat(74));

        for (server, latency) in &rows {
            let features = server.feature_tags();
            println!(
                "{:<16} {:>2}  {:>3}%  {:>5.1}  {:>4}  {:>8}  {}",
                server.name,
                server.exit_country,
                server.load,
                server.score,
                server.tier_enum(),
                format_latency(*latency),
                if features.is_empty() { "-" } else { &features }
            );
        }

        println!("\n{} servers listed", rows.len());
        return Ok(());
    }

    match sort.as_str() {
        "score" => {
            servers.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));
        }
        "load" => {
            servers.sort_by(|a, b| a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)));
        }
        "name" => {
            servers.sort_by(|a, b| a.name.cmp(&b.name));
        }
        _ => unreachable!(),
    }

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

fn parse_proton_feature_tags(
    tags: &[String],
) -> anyhow::Result<Vec<models::server::ServerFeature>> {
    let mut parsed = Vec::new();
    for tag in tags {
        let normalized = tag.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        let feature = match normalized.as_str() {
            "secure-core" | "securecore" | "sc" => models::server::ServerFeature::SecureCore,
            "tor" => models::server::ServerFeature::Tor,
            "p2p" => models::server::ServerFeature::P2P,
            "stream" | "streaming" => models::server::ServerFeature::Streaming,
            "ipv6" => models::server::ServerFeature::Ipv6,
            _ => anyhow::bail!(
                "unknown Proton tag {:?}. Supported tags: secure-core, tor, p2p, streaming, ipv6",
                tag
            ),
        };
        if !parsed.contains(&feature) {
            parsed.push(feature);
        }
    }
    Ok(parsed)
}

fn apply_proton_feature_filters(
    servers: &mut Vec<models::server::LogicalServer>,
    requested_features: &[models::server::ServerFeature],
) {
    let request_mask = requested_features
        .iter()
        .fold(0_i32, |mask, feature| mask | (*feature as i32));
    let default_exclude_mask = (models::server::ServerFeature::SecureCore as i32)
        | (models::server::ServerFeature::Tor as i32);
    // Match Proton's default selection policy: avoid Secure Core and Tor unless requested.
    let exclude_mask = default_exclude_mask & !request_mask;

    servers.retain(|server| {
        (server.features & exclude_mask) == 0 && (server.features & request_mask) == request_mask
    });
}

fn latency_order(a: &Option<Duration>, b: &Option<Duration>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn format_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(value) => format!("{}ms", value.as_millis()),
        None => "-".to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
    p2p: bool,
    port_forwarding: bool,
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
    let backend = connection_ops::resolve_connect_backend(
        backend_arg.as_deref(),
        &config.general.backend,
        use_proxy,
        use_local_proxy,
    )?;
    connection_ops::validate_disable_ipv6_direct_kernel(
        disable_ipv6,
        use_proxy,
        use_local_proxy,
        backend,
    )?;

    // Apply config defaults -- CLI flags override config
    let effective_country = country.or_else(|| config.proton.default_country.clone());
    let proxy_access_log = proxy_access_log_arg || config.general.proxy_access_log;

    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    if port_forwarding {
        ensure_proton_port_forwarding_certificate_ready(&mut session, config).await?;
    } else {
        ensure_proton_certificate_ready(&mut session, config).await?;
    }
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
        let mut requested_features = Vec::new();
        if p2p || port_forwarding {
            requested_features.push(models::server::ServerFeature::P2P);
        }
        apply_proton_feature_filters(&mut servers, &requested_features);

        if sort == "latency" {
            let targets: Vec<(String, u16)> = servers
                .iter()
                .map(|server| {
                    let host = server
                        .best_physical()
                        .map(|physical| physical.entry_ip.clone())
                        .unwrap_or_else(|| server.domain.clone());
                    (host, 51820)
                })
                .collect();
            let latencies =
                latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;
            let mut rows: Vec<(&models::server::LogicalServer, Option<Duration>)> =
                servers.iter().zip(latencies).collect();
            rows.sort_by(|a, b| {
                latency_order(&a.1, &b.1)
                    .then_with(|| a.0.score.partial_cmp(&b.0.score).unwrap_or(Ordering::Equal))
                    .then_with(|| a.0.name.cmp(&b.0.name))
            });
            rows.first()
                .map(|(server, _)| *server)
                .ok_or(error::AppError::NoServerFound)?
        } else {
            match sort.as_str() {
                "score" => {
                    servers
                        .sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));
                }
                "load" => {
                    servers.sort_by(|a, b| a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)));
                }
                "name" => {
                    servers.sort_by(|a, b| a.name.cmp(&b.name));
                }
                _ => unreachable!(),
            }
            servers.first().ok_or(error::AppError::NoServerFound)?
        }
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
        mtu: mtu_arg,
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
            config,
        )?;
    } else if use_local_proxy {
        connect_local_proxy(
            &server.name,
            &params,
            socks_port_arg,
            http_port_arg,
            proxy_access_log,
            config,
        )?;
    } else {
        connect_direct(server, &params, backend, disable_ipv6, config)?;
    }

    Ok(())
}

async fn ensure_proton_certificate_ready(
    session: &mut models::session::Session,
    config: &AppConfig,
) -> anyhow::Result<()> {
    if session.certificate_pem.trim().is_empty() {
        tracing::warn!("proton_certificate_missing_attempting_auto_renew");
        return renew_proton_certificate(session, config, session.certificate_port_forwarding)
            .await
            .map_err(|err| anyhow::anyhow!("no stored Proton certificate and automatic renewal failed: {}. run `tunmux proton login <username>`", err));
    }

    let not_after_unix = match proton_certificate_not_after_unix(session) {
        Some(value) => value,
        None => {
            tracing::warn!("proton_certificate_parse_failed_attempting_auto_renew");
            return renew_proton_certificate(session, config, session.certificate_port_forwarding)
                .await
                .map_err(|err| anyhow::anyhow!("stored Proton certificate could not be parsed and automatic renewal failed: {}. run `tunmux proton login <username>`", err));
        }
    };

    let now_unix = current_unix_timestamp()?;
    if now_unix < not_after_unix {
        return Ok(());
    }

    let expiry = format_unix_utc(not_after_unix);
    tracing::warn!(
        expires_at = %expiry,
        "proton_certificate_expired_attempting_auto_renew"
    );
    renew_proton_certificate(session, config, session.certificate_port_forwarding).await.map_err(
        |err| {
        anyhow::anyhow!(
            "stored Proton certificate expired at {} UTC and automatic renewal failed: {}. run `tunmux proton login <username>`",
            expiry,
            err
        )
    })
}

async fn ensure_proton_port_forwarding_certificate_ready(
    session: &mut models::session::Session,
    config: &AppConfig,
) -> anyhow::Result<()> {
    if session.certificate_port_forwarding {
        return ensure_proton_certificate_ready(session, config).await;
    }

    tracing::info!("proton_port_forwarding_not_enabled_refreshing_certificate");
    renew_proton_certificate(session, config, true).await.map_err(|err| {
        anyhow::anyhow!(
            "failed to enable Proton port-forwarding certificate features: {}. run `tunmux proton login <username>`",
            err
        )
    })
}

async fn renew_proton_certificate(
    session: &mut models::session::Session,
    config: &AppConfig,
    enable_port_forwarding: bool,
) -> anyhow::Result<()> {
    let ed25519_public_key_pem = if session.ed25519_public_key_pem.trim().is_empty() {
        let keys = crypto::keys::VpnKeys::from_base64(&session.ed25519_private_key)?;
        let pem = keys.ed25519_pk_pem();
        session.ed25519_public_key_pem = pem.clone();
        pem
    } else {
        session.ed25519_public_key_pem.clone()
    };

    let client = api::http::ProtonClient::authenticated(&session.uid, &session.access_token)?;
    let cert = api::certificate::fetch_certificate(
        &client,
        &ed25519_public_key_pem,
        enable_port_forwarding,
    )
    .await?;
    session.certificate_pem = cert.certificate;
    session.certificate_port_forwarding = enable_port_forwarding;
    config::save_session(PROVIDER, session, config)?;
    tracing::info!(
        serial = %cert.serial_number,
        port_forwarding = enable_port_forwarding,
        "proton_certificate_renewed"
    );
    Ok(())
}

fn proton_certificate_not_after_unix(session: &models::session::Session) -> Option<i64> {
    let (_, pem) = match x509_parser::pem::parse_x509_pem(session.certificate_pem.as_bytes()) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "proton_certificate_pem_parse_failed"
            );
            return None;
        }
    };
    let (_, cert) = match x509_parser::certificate::X509Certificate::from_der(&pem.contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "proton_certificate_der_parse_failed"
            );
            return None;
        }
    };
    Some(cert.validity().not_after.timestamp())
}

fn current_unix_timestamp() -> anyhow::Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock before unix epoch: {}", e))?
        .as_secs() as i64)
}

fn format_unix_utc(unix_time: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_time)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| unix_time.to_string())
}

fn connect_proxy(
    server: &models::server::LogicalServer,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
    config: &AppConfig,
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
    let pid = match proxy::spawn_daemon(&instance, &interface_name, &namespace_name, &proxy_config)
    {
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
        instance, server.name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_local_proxy(
    server_name: &str,
    params: &wireguard::config::WgConfigParams<'_>,
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let instance = proxy::instance_name(server_name);

    if wireguard::connection::ConnectionState::exists(&instance) {
        anyhow::bail!(
            "instance {:?} already exists (server {} already connected). Disconnect first or pick a different server.",
            instance,
            server_name
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

    println!("Connecting to {} ({})...", server_name, params.server_ip);

    let pid = local_proxy::spawn_daemon(&instance, &cfg, proxy_access_log)?;

    let state = wireguard::connection::ConnectionState {
        instance_name: instance.clone(),
        provider: PROVIDER.dir_name().to_string(),
        interface_name: String::new(),
        backend: wireguard::backend::WgBackend::LocalProxy,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: server_name.to_string(),
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
        instance, server_name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

fn connect_direct(
    server: &models::server::LogicalServer,
    params: &wireguard::config::WgConfigParams<'_>,
    backend: wireguard::backend::WgBackend,
    disable_ipv6: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    // Check if a direct connection already exists
    if wireguard::connection::ConnectionState::exists(DIRECT_INSTANCE) {
        anyhow::bail!("Already connected via direct VPN. Disconnect first.");
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        anyhow::bail!("Already connected. Run `tunmux disconnect --provider proton` first.");
    }

    println!("Connecting to {} ({})...", server.name, params.server_ip);

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
                server_display_name: server.name.clone(),
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
                server_display_name: server.name.clone(),
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
                &server.name,
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

    println!(
        "Connected to {} ({}) [backend: {}]",
        server.name, server.exit_country, backend
    );
    Ok(())
}

fn cmd_disconnect(instance: Option<String>, all: bool, config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_provider_connections(PROVIDER.dir_name(), instance, all, |conn| {
        disconnect_one(conn, config)
    })
}

fn disconnect_one(
    state: &wireguard::connection::ConnectionState,
    config: &AppConfig,
) -> anyhow::Result<()> {
    // Local-proxy mode: user-owned daemon, simple signal-based teardown.
    if state.backend == wireguard::backend::WgBackend::LocalProxy {
        local_proxy::disconnect(state, &state.instance_name)?;
        hooks::run_ifdown(config, PROVIDER, state);
        return Ok(());
    }

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
            wireguard::backend::WgBackend::LocalProxy => unreachable!(),
        }
    }

    hooks::run_ifdown(config, PROVIDER, state);
    if state.namespace_name.is_none()
        && state.instance_name == wireguard::connection::DIRECT_INSTANCE
    {
        clear_proton_port_forward_state_file()?;
    }
    Ok(())
}

/// Legacy helper for logout -- disconnects any direct connection.
fn disconnect_instance_direct(config: &AppConfig) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;
    if let Some(state) = wireguard::connection::ConnectionState::load(DIRECT_INSTANCE)? {
        disconnect_one(&state, config)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server(name: &str, features: i32) -> models::server::LogicalServer {
        models::server::LogicalServer {
            id: format!("id-{}", name),
            name: name.to_string(),
            entry_country: "US".to_string(),
            exit_country: "US".to_string(),
            host_country: None,
            domain: format!("{}.example.com", name.to_ascii_lowercase()),
            tier: 2,
            features,
            region: None,
            city: None,
            score: 1.0,
            load: 10,
            status: 1,
            servers: vec![models::server::PhysicalServer {
                id: "ps-1".to_string(),
                entry_ip: "127.0.0.1".to_string(),
                exit_ip: "127.0.0.1".to_string(),
                domain: "example.com".to_string(),
                status: 1,
                x25519_public_key: Some("key".to_string()),
            }],
            location: None,
        }
    }

    #[test]
    fn test_parse_proton_feature_tags_supported_aliases() {
        let tags = vec![
            "secure-core".to_string(),
            "sc".to_string(),
            "stream".to_string(),
            "p2p".to_string(),
        ];

        let parsed = parse_proton_feature_tags(&tags).expect("parse tags");
        assert!(parsed.contains(&models::server::ServerFeature::SecureCore));
        assert!(parsed.contains(&models::server::ServerFeature::Streaming));
        assert!(parsed.contains(&models::server::ServerFeature::P2P));
        assert_eq!(
            parsed
                .iter()
                .filter(|&&f| f == models::server::ServerFeature::SecureCore)
                .count(),
            1
        );
    }

    #[test]
    fn test_parse_proton_feature_tags_rejects_unknown_tag() {
        let err = parse_proton_feature_tags(&["unknown".to_string()]).expect_err("unknown tag");
        assert!(err.to_string().contains("unknown Proton tag"));
    }

    #[test]
    fn test_parse_proton_nat_pmp_protocols() {
        assert_eq!(
            parse_proton_nat_pmp_protocols("tcp").expect("tcp"),
            vec![ProtonNatPmpProtocol::Tcp]
        );
        assert_eq!(
            parse_proton_nat_pmp_protocols("udp").expect("udp"),
            vec![ProtonNatPmpProtocol::Udp]
        );
        assert_eq!(
            parse_proton_nat_pmp_protocols("both").expect("both"),
            vec![ProtonNatPmpProtocol::Tcp, ProtonNatPmpProtocol::Udp]
        );
        assert!(parse_proton_nat_pmp_protocols("sctp").is_err());
    }

    #[test]
    fn test_nat_pmp_result_code_desc_known_values() {
        assert_eq!(nat_pmp_result_code_desc(0), "success");
        assert_eq!(nat_pmp_result_code_desc(2), "not authorized/refused");
        assert_eq!(nat_pmp_result_code_desc(5), "unsupported opcode");
    }

    #[test]
    fn test_apply_proton_feature_filters_excludes_secure_core_and_tor_by_default() {
        let mut servers = vec![
            make_server("US#1", 0),
            make_server("US#2", models::server::ServerFeature::SecureCore as i32),
            make_server("US#3", models::server::ServerFeature::Tor as i32),
        ];

        apply_proton_feature_filters(&mut servers, &[]);
        let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["US#1"]);
    }

    #[test]
    fn test_apply_proton_feature_filters_secure_core_request_still_excludes_tor() {
        let mut servers = vec![
            make_server("US#1", models::server::ServerFeature::SecureCore as i32),
            make_server(
                "US#2",
                (models::server::ServerFeature::SecureCore as i32)
                    | (models::server::ServerFeature::Tor as i32),
            ),
            make_server("US#3", 0),
        ];

        apply_proton_feature_filters(&mut servers, &[models::server::ServerFeature::SecureCore]);
        let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["US#1"]);
    }

    #[test]
    fn test_apply_proton_feature_filters_p2p_request_excludes_secure_core_and_tor() {
        let mut servers = vec![
            make_server("US#1", models::server::ServerFeature::P2P as i32),
            make_server(
                "US#2",
                (models::server::ServerFeature::P2P as i32)
                    | (models::server::ServerFeature::SecureCore as i32),
            ),
            make_server(
                "US#3",
                (models::server::ServerFeature::P2P as i32)
                    | (models::server::ServerFeature::Tor as i32),
            ),
        ];

        apply_proton_feature_filters(&mut servers, &[models::server::ServerFeature::P2P]);
        let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["US#1"]);
    }

    #[test]
    fn test_latency_order_prefers_measured_values() {
        let fast = Some(Duration::from_millis(20));
        let slow = Some(Duration::from_millis(50));
        let missing = None;

        assert_eq!(latency_order(&fast, &slow), Ordering::Less);
        assert_eq!(latency_order(&fast, &missing), Ordering::Less);
        assert_eq!(latency_order(&missing, &slow), Ordering::Greater);
    }
}

use std::cmp::Ordering;
use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{self, AppConfig, Provider};
use crate::error;
use crate::shared::connection_ops::{self, ConnectOptions};
use crate::shared::crypto;
use crate::shared::latency;
use crate::shared::latency::latency_order;
use crate::wireguard;
use x509_parser::prelude::FromDer;

use super::{api, models};

pub const PROVIDER: Provider = Provider::Proton;
const INTERFACE_NAME: &str = "proton0";
const MANIFEST_FILE: &str = "manifest.json";
const PORT_FORWARD_FILE: &str = "port_forwards.json";
const PORT_FORWARD_DAEMON_PID_FILE: &str = "port_forward_daemon.pid";
const PORT_FORWARD_DAEMON_LOG_FILE: &str = "port_forward_daemon.log";
const NAT_PMP_PORT: u16 = 5351;
const NAT_PMP_DEFAULT_GATEWAY: &str = "10.2.0.1";

#[derive(serde::Deserialize, serde::Serialize)]
pub struct ProtonManifest {
    pub logical_servers: Vec<models::server::LogicalServer>,
}

/// Parameters for `connect`, the non-clap counterpart of `tunmux connect proton`.
#[derive(Clone, Debug, Default)]
pub struct ConnectRequest {
    pub server: Option<String>,
    pub country: Option<String>,
    /// Restrict selection to P2P servers.
    pub p2p: bool,
    /// Request a NAT-PMP capable server and certificate.
    pub port_forwarding: bool,
    /// One of `score`, `load`, `name` or `latency`.
    pub sort: String,
    pub opts: ConnectOptions,
}

/// Log in and save the session. `two_factor` supplies the TOTP code when the
/// account requires one; returning `None` stops with `NeedsTwoFactor`.
pub async fn login(
    username: &str,
    password: &str,
    two_factor: &mut dyn FnMut() -> anyhow::Result<Option<String>>,
    config: &AppConfig,
) -> anyhow::Result<crate::api::LoginOutcome> {
    let mut client = api::http::ProtonClient::new()?;

    // SRP authentication
    let auth = api::auth::login(&mut client, username, password).await?;

    // Handle 2FA if required
    if auth.two_factor.totp_required() {
        let Some(code) = two_factor()? else {
            return Ok(crate::api::LoginOutcome::NeedsTwoFactor);
        };
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
    Ok(crate::api::LoginOutcome::LoggedIn {
        account: session.vpn_username,
        detail: session.plan_title,
    })
}

/// Servers this account can connect to, from the cached list.
pub async fn server_list(config: &AppConfig) -> anyhow::Result<Vec<crate::api::ServerInfo>> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let servers = load_servers_cached_or_fetch(&session).await?;
    Ok(servers
        .into_iter()
        .filter(|s| s.is_enabled() && s.best_physical().is_some() && s.tier <= session.max_tier)
        .map(|s| crate::api::ServerInfo {
            provider: PROVIDER,
            tags: s
                .feature_tags()
                .split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_lowercase)
                .collect(),
            name: s.name,
            country_code: s.exit_country,
            city: s.city.unwrap_or_default(),
            load: Some(s.load as f32),
            score: Some(s.score),
        })
        .collect())
}

pub async fn logout(config: &AppConfig) -> anyhow::Result<()> {
    stop_proton_ports_daemon()?;
    clear_proton_ports_daemon_log_file()?;

    // Disconnect if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        crate::progress!("Disconnecting active VPN connection...");
        disconnect_instance_direct(config)?;
    }

    config::delete_session(PROVIDER, config)?;
    clear_proton_port_forward_state_file()?;

    // Also remove cached server list
    let manifest_path = config::config_dir(PROVIDER).join(MANIFEST_FILE);
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path)?;
    }

    crate::progress!("Logged out");
    Ok(())
}

pub async fn renew_certificate(config: &AppConfig) -> anyhow::Result<()> {
    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    let keep_port_forwarding = session.certificate_port_forwarding;
    renew_proton_certificate(&mut session, config, keep_port_forwarding)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "could not renew Proton certificate from saved session (token may be expired): {}. run `tunmux proton login <username>`",
                err
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtonNatPmpProtocol {
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
pub struct ProtonPortForwardRecord {
    pub protocol: ProtonNatPmpProtocol,
    pub public_port: u16,
    pub local_port: u16,
    pub lifetime_secs: u32,
    pub expires_at_unix: u64,
    pub gateway: String,
    pub instance_name: String,
    pub interface_name: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProtonPortForwardState {
    #[serde(default)]
    pub mappings: Vec<ProtonPortForwardRecord>,
}

#[derive(Debug)]
pub struct ProtonNatPmpMapResponse {
    pub public_port: u16,
    pub lifetime_secs: u32,
}

/// Unexpired mappings, daemon liveness and certificate expiry, for the API.
pub fn port_forward_status(config: &AppConfig) -> anyhow::Result<crate::api::ProtonPorts> {
    let now = current_unix_timestamp()? as u64;
    let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
    let forwards = load_proton_port_forward_state()?
        .mappings
        .into_iter()
        .filter(|mapping| mapping.expires_at_unix > now)
        .map(|mapping| crate::api::ProtonForward {
            instance: mapping.instance_name,
            protocol: mapping.protocol.to_string(),
            public_port: mapping.public_port,
            expires_at: at(mapping.expires_at_unix),
        })
        .collect();
    let daemon_running = read_proton_ports_daemon_pid()?.is_some_and(process_alive);
    let certificate_expires = config::load_session::<models::session::Session>(PROVIDER, config)
        .ok()
        .and_then(|session| proton_certificate_not_after_unix(&session))
        .and_then(|secs| u64::try_from(secs).ok())
        .map(at);
    Ok(crate::api::ProtonPorts {
        forwards,
        daemon_running,
        certificate_expires,
    })
}

/// `ports request` with the CLI defaults: both protocols, an assigned port,
/// a 60 s lease renewed by the daemon.
pub async fn request_port(config: &AppConfig) -> anyhow::Result<()> {
    request_ports("both", 0, 1, 60, false, config).await
}

pub async fn request_ports(
    protocol: &str,
    public_port: u16,
    local_port: u16,
    lifetime: u32,
    no_daemon: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    request_ports_once(protocol, public_port, local_port, lifetime, config).await?;
    if no_daemon {
        return Ok(());
    }

    stop_proton_ports_daemon()?;
    let renew_every = default_proton_ports_renew_every(lifetime);
    let pid = spawn_proton_ports_daemon(protocol, public_port, local_port, lifetime, renew_every)?;
    crate::progress!(
        "Started Proton port-forward daemon (pid {}, renew every {}s)",
        pid,
        renew_every
    );
    Ok(())
}

async fn request_ports_once(
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
        crate::progress!(
            "Forwarded {} public {} (local {}, lifetime {}s)",
            mapping.protocol,
            mapping.public_port,
            mapping.local_port,
            mapping.lifetime_secs
        );
    }
    Ok(())
}

pub async fn renew_ports(lifetime: u32, config: &AppConfig) -> anyhow::Result<()> {
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
        crate::progress!(
            "Renewed {} public {} (lifetime {}s)",
            mapping.protocol,
            mapping.public_port,
            mapping.lifetime_secs
        );
    }

    if renewed == 0 {
        anyhow::bail!("no saved Proton mappings for the active connection. Run `tunmux proton ports request` first");
    }

    save_proton_port_forward_state(&state)?;
    Ok(())
}

pub async fn run_ports_daemon(
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
            request_ports_once(protocol, public_port, local_port, lifetime, config).await?;
        }
        crate::progress!(
            "Keeping Proton mappings alive (renew every {}s, Ctrl-C to stop)",
            renew_every
        );

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    crate::progress!("Stopping Proton port forwarding daemon.");
                    return Ok(());
                }
                _ = tokio::time::sleep(Duration::from_secs(renew_every)) => {
                    if let Err(err) = renew_ports(lifetime, config).await {
                        tracing::warn!(
                            error = %err,
                            "proton_ports_daemon_renew_failed_retrying_request"
                        );
                        crate::progress!("Renew failed: {}. Requesting a fresh mapping...", err);
                        request_ports_once(protocol, public_port, local_port, lifetime, config).await?;
                    }
                }
            }
        }
    }
    .await;
    let _ = clear_proton_ports_daemon_pid_file();
    result
}

pub async fn release_ports(_config: &AppConfig) -> anyhow::Result<()> {
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
        crate::progress!("No saved Proton mappings for active connection.");
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
        crate::progress!(
            "Released {} public {} (local {})",
            mapping.protocol,
            mapping.public_port,
            mapping.local_port
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
    let exe = crate::shared::executable::cli_executable()
        .unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
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

pub fn require_active_proton_direct_connection(
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

pub fn load_proton_port_forward_state() -> anyhow::Result<ProtonPortForwardState> {
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

pub fn parse_proton_feature_tags(
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

pub fn apply_proton_feature_filters(
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

pub async fn connect(args: ConnectRequest, config: &AppConfig) -> anyhow::Result<()> {
    let backend = connection_ops::resolve_opts(&args.opts, &config.general.backend)?;

    // Apply config defaults -- CLI flags override config
    let effective_country = args
        .country
        .or_else(|| config.default_country_for(PROVIDER).map(str::to_owned));

    let mut session: models::session::Session = config::load_session(PROVIDER, config)?;
    if args.port_forwarding {
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
    let server = if let Some(ref name) = args.server {
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
        if args.p2p || args.port_forwarding {
            requested_features.push(models::server::ServerFeature::P2P);
        }
        apply_proton_feature_filters(&mut servers, &requested_features);

        if args.sort == "latency" {
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
            servers
                .iter()
                .zip(latencies)
                .min_by(|a, b| {
                    latency_order(&a.1, &b.1)
                        .then_with(|| a.0.score.partial_cmp(&b.0.score).unwrap_or(Ordering::Equal))
                        .then_with(|| a.0.name.cmp(&b.0.name))
                })
                .map(|(selected, _)| selected)
                .ok_or(error::AppError::NoServerFound)?
        } else {
            servers
                .iter()
                .min_by(|a, b| match args.sort.as_str() {
                    "score" => a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal),
                    "load" => a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)),
                    "name" => a.name.cmp(&b.name),
                    _ => unreachable!(),
                })
                .ok_or(error::AppError::NoServerFound)?
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
        mtu: args.opts.mtu,
        server_public_key: server_pubkey,
        server_ip: &physical.entry_ip,
        server_port: 51820,
        preshared_key: None,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    let display_name = format!("{} ({})", server.name, server.exit_country);
    connection_ops::connect_routed(
        &connection_ops::ResolvedServer {
            instance_seed: &server.name,
            display_name: &display_name,
        },
        &params,
        &args.opts,
        backend,
        PROVIDER,
        INTERFACE_NAME,
        config,
    )
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

pub fn current_unix_timestamp() -> anyhow::Result<i64> {
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

pub fn disconnect(instance: Option<String>, all: bool, config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_provider_connections(PROVIDER.dir_name(), instance, all, |conn| {
        connection_ops::disconnect_one_provider_connection(conn, PROVIDER, config, false)?;
        if conn.namespace_name.is_none()
            && conn.instance_name == wireguard::connection::DIRECT_INSTANCE
        {
            clear_proton_port_forward_state_file()?;
        }
        Ok(())
    })
}

fn disconnect_instance_direct(config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_instance_direct(|state| {
        connection_ops::disconnect_one_provider_connection(state, PROVIDER, config, false)?;
        if state.namespace_name.is_none()
            && state.instance_name == wireguard::connection::DIRECT_INSTANCE
        {
            clear_proton_port_forward_state_file()?;
        }
        Ok(())
    })
}

pub async fn load_servers_cached_or_fetch(
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
    config::save_manifest(PROVIDER, MANIFEST_FILE, &manifest)?;
    Ok(())
}

fn load_manifest() -> anyhow::Result<Vec<models::server::LogicalServer>> {
    let manifest: ProtonManifest = config::load_manifest(PROVIDER, MANIFEST_FILE)?;
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

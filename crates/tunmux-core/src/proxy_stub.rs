use std::path::PathBuf;

use crate::config;

pub mod daemon {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        _netns_name: &str,
        _interface_name: &str,
        _socks_port: u16,
        _http_port: u16,
        _proxy_access_log: bool,
        _pid_file: &str,
        _log_file: &str,
        _startup_status_file: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("proxy mode is not compiled in (enable with --features proxy)")
    }
}

pub mod http {}
pub mod socks5 {}

#[derive(Debug, Clone, Copy)]
pub struct ProxyConfig {
    pub socks_port: u16,
    pub http_port: u16,
    pub access_log: bool,
}

/// Sanitize a server name into a valid instance name.
#[must_use]
pub fn instance_name(server_name: &str) -> String {
    let sanitized: String = server_name
        .to_lowercase()
        .replace('#', "-")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let trimmed = sanitized.trim_matches('-').to_string();
    if trimmed.len() > 12 {
        trimmed[..12].trim_end_matches('-').to_string()
    } else {
        trimmed
    }
}

/// Path helpers for privileged instance files (used by --proxy netns mode).
#[must_use]
pub fn pid_file(instance: &str) -> PathBuf {
    config::privileged_proxy_dir().join(format!("{}.pid", instance))
}

#[must_use]
pub fn log_file(instance: &str) -> PathBuf {
    config::privileged_proxy_dir().join(format!("{}.log", instance))
}

/// Path helpers for user-owned local-proxy instance files.
#[must_use]
pub fn local_pid_file(instance: &str) -> PathBuf {
    config::user_proxy_dir().join(format!("{}.pid", instance))
}

#[must_use]
pub fn local_log_file(instance: &str) -> PathBuf {
    config::user_proxy_dir().join(format!("{}.log", instance))
}

/// Spawn the proxy daemon through the privileged service.
pub fn spawn_daemon(
    _instance: &str,
    _interface_name: &str,
    _netns_name: &str,
    _proxy_config: &ProxyConfig,
) -> anyhow::Result<u32> {
    anyhow::bail!("proxy mode is not compiled in (enable with --features proxy)")
}

/// Find the next available port pair by scanning active connections.
pub fn next_available_ports() -> anyhow::Result<ProxyConfig> {
    use crate::wireguard::connection::ConnectionState;

    let connections = ConnectionState::load_all().unwrap_or_default();

    let used_socks: Vec<u16> = connections.iter().filter_map(|c| c.socks_port).collect();
    let used_http: Vec<u16> = connections.iter().filter_map(|c| c.http_port).collect();

    let socks_port = next_available_port(1080, &used_socks)?;
    let http_port = next_available_port(8118, &used_http)?;

    Ok(ProxyConfig {
        socks_port,
        http_port,
        access_log: false,
    })
}

fn next_available_port(start: u16, used: &[u16]) -> anyhow::Result<u16> {
    let mut port = start;
    loop {
        if !used.contains(&port) && loopback_tcp_bind_available(port) {
            return Ok(port);
        }
        port = port.checked_add(1).unwrap_or(1024);
        if port == start {
            anyhow::bail!("no available proxy port found from {}", start);
        }
    }
}

fn loopback_tcp_bind_available(port: u16) -> bool {
    // local-proxy binds on 127.0.0.1, so IPv4 loopback availability is the
    // gating condition for safe auto-port selection.
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Stop a proxy daemon via the privileged API.
pub fn stop_daemon(_pid: u32) -> anyhow::Result<()> {
    Ok(())
}

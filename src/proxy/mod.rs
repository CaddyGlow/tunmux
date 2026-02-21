#![cfg(all(feature = "proxy", target_os = "linux"))]

pub mod daemon;
pub mod http;
pub mod socks5;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config;
use crate::privileged_api::KillSignal;
use crate::privileged_client::PrivilegedClient;

pub struct ProxyConfig {
    pub socks_port: u16,
    pub http_port: u16,
    pub access_log: bool,
}

/// Sanitize a server name into a valid instance name.
///
/// Lowercase, replace `#` with `-`, strip non-alphanumeric/dash, truncate to 12 chars.
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
/// Returns the daemon PID.
pub fn spawn_daemon(
    instance: &str,
    netns_name: &str,
    proxy_config: &ProxyConfig,
) -> anyhow::Result<u32> {
    let client = PrivilegedClient::new();
    let pid_path = pid_file(instance);
    let log_path = log_file(instance);

    let pid = client.spawn_proxy_daemon(
        netns_name,
        proxy_config.socks_port,
        proxy_config.http_port,
        proxy_config.access_log,
        &pid_path.to_string_lossy(),
        &log_path.to_string_lossy(),
    )?;

    info!( pid = ?pid, namespace = ?netns_name, "spawned_proxy_daemon");
    Ok(pid)
}

/// Find the next available port pair by scanning active connections.
pub fn next_available_ports() -> anyhow::Result<ProxyConfig> {
    use crate::wireguard::connection::ConnectionState;

    let connections = ConnectionState::load_all()?;

    let mut used_socks: Vec<u16> = Vec::new();
    let mut used_http: Vec<u16> = Vec::new();

    for conn in &connections {
        if let Some(port) = conn.socks_port {
            used_socks.push(port);
        }
        if let Some(port) = conn.http_port {
            used_http.push(port);
        }
    }

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
pub fn stop_daemon(pid: u32) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    if !pid_is_alive(pid) {
        debug!( pid = ?pid, "proxy_daemon_already_exited");
        return Ok(());
    }

    debug!( pid = ?pid, signal = ?"SIGTERM", "proxy_daemon_signal_send");
    if let Err(e) = client.kill_pid(pid, KillSignal::Term) {
        warn!( pid = ?pid, signal = ?"SIGTERM", error = ?e.to_string(), "proxy_daemon_signal_request_failed");
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !pid_is_alive(pid) {
            debug!( pid = ?pid, signal = ?"SIGTERM", "proxy_daemon_exited_after_signal");
            return Ok(());
        }
    }

    debug!( pid = ?pid, signal = ?"SIGKILL", "proxy_daemon_signal_send");
    client
        .kill_pid(pid, KillSignal::Kill)
        .map_err(|e| anyhow::anyhow!("failed to SIGKILL proxy daemon {}: {}", pid, e))?;

    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !pid_is_alive(pid) {
            debug!( pid = ?pid, signal = ?"SIGKILL", "proxy_daemon_exited_after_signal");
            return Ok(());
        }
    }

    anyhow::bail!("proxy daemon {} is still alive after SIGKILL", pid)
}
fn pid_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_name_proton() {
        assert_eq!(instance_name("US#1"), "us-1");
        assert_eq!(instance_name("CH#53"), "ch-53");
        assert_eq!(instance_name("US-FREE#7"), "us-free-7");
    }

    #[test]
    fn test_instance_name_airvpn() {
        assert_eq!(instance_name("Castor"), "castor");
        assert_eq!(instance_name("Vega"), "vega");
    }

    #[test]
    fn test_instance_name_truncation() {
        assert_eq!(instance_name("VeryLongServerName#123"), "verylongserv");
    }

    #[test]
    fn test_instance_name_special_chars() {
        assert_eq!(instance_name("US@#1!"), "us-1");
    }

    #[test]
    fn test_loopback_tcp_bind_available_ephemeral() {
        assert!(loopback_tcp_bind_available(0));
    }

    #[test]
    fn test_loopback_tcp_bind_available_respects_ipv4_conflict() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!loopback_tcp_bind_available(port));
    }
}

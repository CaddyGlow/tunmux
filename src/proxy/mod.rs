pub mod daemon;
pub mod http;
pub mod socks5;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use tracing::info;

use crate::config;
use crate::privileged_api::KillSignal;
use crate::privileged_client::PrivilegedClient;

pub struct ProxyConfig {
    pub socks_port: u16,
    pub http_port: u16,
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

/// Path helpers for instance files.
#[must_use]
pub fn pid_file(instance: &str) -> PathBuf {
    config::privileged_proxy_dir().join(format!("{}.pid", instance))
}

#[must_use]
pub fn log_file(instance: &str) -> PathBuf {
    config::privileged_proxy_dir().join(format!("{}.log", instance))
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
        &pid_path.to_string_lossy(),
        &log_path.to_string_lossy(),
    )?;

    info!("Spawned proxy daemon {} for namespace {}", pid, netns_name);
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

    let mut socks_port = 1080u16;
    while used_socks.contains(&socks_port) {
        socks_port = socks_port.checked_add(1).unwrap_or(1080);
    }

    let mut http_port = 8118u16;
    while used_http.contains(&http_port) {
        http_port = http_port.checked_add(1).unwrap_or(8118);
    }

    Ok(ProxyConfig {
        socks_port,
        http_port,
    })
}

/// Stop a proxy daemon via the privileged API.
pub fn stop_daemon(pid: u32) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    if !pid_is_alive(pid) {
        return Ok(());
    }

    let _ = client.kill_pid(pid, KillSignal::Term);
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !pid_is_alive(pid) {
            return Ok(());
        }
    }

    let _ = client.kill_pid(pid, KillSignal::Kill);
    thread::sleep(Duration::from_millis(100));
    Ok(())
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
}

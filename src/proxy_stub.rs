use std::path::PathBuf;

use crate::config;

pub mod daemon {
    pub fn run(
        _netns_name: &str,
        _socks_port: u16,
        _http_port: u16,
        _pid_file: &str,
        _log_file: &str,
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
pub fn spawn_daemon(
    _instance: &str,
    _netns_name: &str,
    _proxy_config: &ProxyConfig,
) -> anyhow::Result<u32> {
    anyhow::bail!("proxy mode is not compiled in (enable with --features proxy)")
}

/// Find the next available port pair by scanning active connections.
pub fn next_available_ports() -> anyhow::Result<ProxyConfig> {
    Ok(ProxyConfig {
        socks_port: 1080,
        http_port: 8118,
    })
}

/// Stop a proxy daemon via the privileged API.
pub fn stop_daemon(_pid: u32) -> anyhow::Result<()> {
    Ok(())
}

pub mod daemon;
pub mod http;
pub mod socks5;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use tracing::info;

use crate::config;
use crate::wireguard::connection::ConnectionState;

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
    config::connections_dir().join(format!("{}.pid", instance))
}

#[must_use]
pub fn log_file(instance: &str) -> PathBuf {
    config::connections_dir().join(format!("{}.log", instance))
}

/// Spawn the proxy daemon by re-exec'ing the current binary with proxy-daemon subcommand.
/// Returns the daemon PID.
pub fn spawn_daemon(
    instance: &str,
    netns_name: &str,
    proxy_config: &ProxyConfig,
) -> anyhow::Result<u32> {
    let exe = std::env::current_exe()?;
    let pid_path = pid_file(instance);
    let log_path = log_file(instance);

    config::ensure_connections_dir()?;

    // Remove stale pid/log files
    let _ = fs::remove_file(&pid_path);
    let _ = fs::remove_file(&log_path);

    let socks_str = proxy_config.socks_port.to_string();
    let http_str = proxy_config.http_port.to_string();
    let pid_str = pid_path.to_string_lossy().to_string();
    let log_str = log_path.to_string_lossy().to_string();

    let exe_str = exe.to_string_lossy().to_string();

    info!(
        "Spawning proxy daemon: sudo {} proxy-daemon --netns {} --socks-port {} --http-port {}",
        exe_str,
        netns_name,
        socks_str,
        http_str
    );

    // The daemon process will daemonize itself (double-fork), so the child we spawn
    // here will exit quickly. We just need to wait for the PID file to appear.
    // Run via sudo because setns() requires CAP_SYS_ADMIN.
    let mut cmd = Command::new("sudo");
    cmd.args([
        &exe_str,
        "proxy-daemon",
        "--netns",
        netns_name,
        "--socks-port",
        &socks_str,
        "--http-port",
        &http_str,
        "--pid-file",
        &pid_str,
        "--log-file",
        &log_str,
    ]);
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn()?;

    // Wait for the sudo/daemon process to exit. On success the daemon double-forks
    // and the first-fork parent calls exit(0), so sudo exits quickly with code 0.
    // On failure (e.g., port bind error), it exits non-zero before daemonizing.
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if !detail.is_empty() {
            anyhow::bail!("proxy daemon failed: {}", detail);
        }
        // Check the log file for details
        if let Ok(log_contents) = fs::read_to_string(&log_path) {
            if !log_contents.is_empty() {
                anyhow::bail!("proxy daemon failed to start. Log:\n{}", log_contents);
            }
        }
        anyhow::bail!(
            "proxy daemon exited with {} before daemonizing",
            output.status
        );
    }

    // Daemon daemonized successfully. Poll for PID file (up to 5 seconds).
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(contents) = fs::read_to_string(&pid_path) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                if pid_is_alive(pid) {
                    info!("Proxy daemon started with PID {}", pid);
                    return Ok(pid);
                }
            }
        }
    }

    // Check the log file for errors
    if let Ok(log_contents) = fs::read_to_string(&log_path) {
        if !log_contents.is_empty() {
            anyhow::bail!("proxy daemon failed to start. Log:\n{}", log_contents);
        }
    }

    anyhow::bail!("proxy daemon failed to start (no PID file after 5s)")
}

/// Find the next available port pair by scanning active connections.
pub fn next_available_ports() -> anyhow::Result<ProxyConfig> {
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

/// Stop a proxy daemon by PID. Sends SIGTERM via sudo (daemon runs as root),
/// waits up to 2s, then SIGKILL if needed.
pub fn stop_daemon(pid: u32) -> anyhow::Result<()> {
    if !pid_is_alive(pid) {
        return Ok(());
    }

    let pid_str = pid.to_string();

    // SIGTERM (via sudo -- daemon runs as root)
    let _ = Command::new("sudo").args(["kill", &pid_str]).output();

    // Wait up to 2 seconds
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !pid_is_alive(pid) {
            return Ok(());
        }
    }

    // SIGKILL
    let _ = Command::new("sudo")
        .args(["kill", "-9", &pid_str])
        .output();
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

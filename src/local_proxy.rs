//! Shared helpers for the --local-proxy userspace WireGuard proxy mode.
//!
//! Used by all four provider handler modules to spawn and stop the
//! local-proxy-daemon subprocess.

use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine as _;
use tracing::debug;

use crate::config;
use crate::proxy;
use crate::wireguard::config::WgConfigParams;
use crate::wireguard::proxy_tunnel::LocalProxyConfig;

/// Build a `LocalProxyConfig` from `WgConfigParams`.
///
/// `keepalive` is None for most providers; pass Some(25) or similar when desired.
pub fn local_proxy_config_from_params(
    params: &WgConfigParams<'_>,
    keepalive: Option<u16>,
    socks_port: u16,
    http_port: u16,
) -> anyhow::Result<LocalProxyConfig> {
    let decode_key = |b64: &str, label: &str| -> anyhow::Result<[u8; 32]> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .with_context(|| format!("base64 decode {}", label))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must be 32 bytes", label))?;
        Ok(arr)
    };

    let private_key = decode_key(params.private_key, "private_key")?;
    let peer_public_key = decode_key(params.server_public_key, "server_public_key")?;
    let preshared_key = params
        .preshared_key
        .map(|s| decode_key(s, "preshared_key"))
        .transpose()?;

    let endpoint = parse_endpoint(params.server_ip, params.server_port)?;

    let virtual_ips = params.addresses.iter().map(|s| s.to_string()).collect();
    let dns_servers = params.dns_servers.iter().map(|s| s.to_string()).collect();

    Ok(LocalProxyConfig {
        private_key,
        peer_public_key,
        preshared_key,
        endpoint,
        virtual_ips,
        keepalive,
        socks_port,
        http_port,
        dns_servers,
    })
}

fn parse_endpoint(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let endpoint = format!("{}:{}", host, port);
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let (raw_host, raw_port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint {}", endpoint))?;
    let ip: IpAddr = raw_host
        .trim_matches(['[', ']'])
        .parse()
        .with_context(|| format!("invalid endpoint IP {}", raw_host))?;
    let port: u16 = raw_port
        .parse()
        .with_context(|| format!("invalid endpoint port {}", raw_port))?;
    Ok(SocketAddr::new(ip, port))
}

/// Spawn a `tunmux local-proxy-daemon` subprocess and return its PID.
///
/// The subprocess double-forks and writes its final PID to the pid file.
/// This function waits for the intermediate process to exit, then polls
/// the pid file for up to 5 seconds.
pub fn spawn_daemon(
    instance: &str,
    cfg: &LocalProxyConfig,
    proxy_access_log: bool,
) -> anyhow::Result<u32> {
    config::ensure_user_proxy_dir()?;
    let pid_path = proxy::local_pid_file(instance);
    let log_path = proxy::local_log_file(instance);
    let status_path = std::path::PathBuf::from(format!("{}.status", pid_path.to_string_lossy()));
    let pid_file = pid_path.to_string_lossy();
    let log_file = log_path.to_string_lossy();

    let json = serde_json::to_string(cfg)?;
    let config_b64 = base64::engine::general_purpose::STANDARD.encode(&json);

    let exe = self_executable()?;

    // Remove stale pid/log files so the poll loop below doesn't read old data.
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&status_path);

    let socks = cfg.socks_port.to_string();
    let http = cfg.http_port.to_string();

    let mut cmd = std::process::Command::new(&exe);
    cmd.args([
        "local-proxy-daemon",
        "--socks-port",
        &socks,
        "--http-port",
        &http,
        "--pid-file",
        &pid_file,
        "--log-file",
        &log_file,
        "--config-b64",
        &config_b64,
    ]);
    if proxy_access_log {
        cmd.arg("--proxy-access-log");
    }

    let mut child = cmd
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("failed to spawn local-proxy-daemon")?;

    // Wait for the intermediate process (it exits after the second fork).
    let stderr_handle = child.stderr.take();
    let status = child
        .wait()
        .context("failed to wait on local-proxy-daemon")?;
    if !status.success() {
        let detail = stderr_handle
            .and_then(|mut s| {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                Some(buf)
            })
            .unwrap_or_default();
        anyhow::bail!("local-proxy-daemon exited {}: {}", status, detail.trim());
    }

    // Poll the pid file until the grandchild writes its PID (up to 5 seconds).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                if std::path::Path::new(&format!("/proc/{}/exe", pid)).exists() {
                    if wait_for_startup_ready(&status_path, Duration::from_secs(12)) {
                        debug!(pid = ?pid, instance = ?instance, "local_proxy_daemon_ready");
                        return Ok(pid);
                    }

                    let _ = stop_daemon(pid);
                    let _ = std::fs::remove_file(&pid_path);
                    let detail = tail_file(&log_path, 12);
                    anyhow::bail!(
                        "local-proxy tunnel did not establish a WireGuard handshake within 12s for instance {}. Recent log:\n{}",
                        instance,
                        detail
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    anyhow::bail!("local-proxy-daemon did not write a valid pid within 5 seconds")
}

fn wait_for_startup_ready(status_path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(status_path) {
            if text.trim() == "ready" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn tail_file(path: &std::path::Path, lines: usize) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return "<log unavailable>".to_string();
    };
    let mut rows: Vec<&str> = content.lines().collect();
    if rows.len() > lines {
        rows = rows.split_off(rows.len() - lines);
    }
    rows.join("\n")
}

/// Stop a user-owned local-proxy-daemon by PID.
///
/// Sends SIGTERM, waits up to 2 seconds, then sends SIGKILL.
pub fn stop_daemon(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    if !proc_alive(pid) {
        debug!(pid = ?pid, "local_proxy_daemon_already_exited");
        return Ok(());
    }

    debug!(pid = ?pid, signal = ?"SIGTERM", "local_proxy_daemon_signal_send");
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if !proc_alive(pid) {
            debug!(pid = ?pid, "local_proxy_daemon_exited_after_sigterm");
            return Ok(());
        }
    }

    debug!(pid = ?pid, signal = ?"SIGKILL", "local_proxy_daemon_signal_send");
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if !proc_alive(pid) {
            debug!(pid = ?pid, "local_proxy_daemon_exited_after_sigkill");
            return Ok(());
        }
    }

    anyhow::bail!("local-proxy-daemon {} is still alive after SIGKILL", pid)
}

fn proc_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn self_executable() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(current) = std::env::current_exe() {
        if current.exists() {
            return Ok(current);
        }
    }
    Ok(std::path::PathBuf::from("/proc/self/exe"))
}

/// Derive the WireGuard public key (base64) from a base64-encoded private key.
pub fn derive_public_key_b64(private_key_b64: &str) -> anyhow::Result<String> {
    use boringtun::x25519::{PublicKey, StaticSecret};
    let decoded = base64::engine::general_purpose::STANDARD.decode(private_key_b64)?;
    let arr: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes"))?;
    let pub_key = PublicKey::from(&StaticSecret::from(arr));
    Ok(base64::engine::general_purpose::STANDARD.encode(pub_key.as_bytes()))
}

/// Disconnect a local-proxy connection: stop the daemon, remove files.
pub fn disconnect(
    state: &crate::wireguard::connection::ConnectionState,
    instance_name: &str,
) -> anyhow::Result<()> {
    if let Some(pid) = state.proxy_pid {
        stop_daemon(pid)?;
    }
    let pid_path = proxy::local_pid_file(instance_name);
    let log_path = proxy::local_log_file(instance_name);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&log_path);
    crate::wireguard::connection::ConnectionState::remove(instance_name)?;
    Ok(())
}

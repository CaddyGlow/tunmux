//! Shared helpers for the --local-proxy userspace WireGuard proxy mode.
//!
//! Used by provider handler modules to spawn and stop the
//! local-proxy-daemon subprocess.

use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine as _;
use nix::libc;
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
    let endpoint = crate::wireguard::config::format_endpoint(host, port);
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

    // The config holds WireGuard private keys. It travels over stdin so it never
    // appears in argv, which every local user can read from /proc/<pid>/cmdline.
    let json = serde_json::to_string(cfg)?;

    let exe = self_executable()?;

    // Remove stale pid/log files so the poll loop below doesn't read old data.
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&status_path);

    let socks = cfg.socks_port.to_string();
    let http = cfg.http_port.to_string();

    let mut cmd = std::process::Command::new(&exe);
    crate::logging::apply_to_command(&mut cmd);
    cmd.env(
        "TUNMUX_LOCAL_PROXY_SESSION",
        format!("{:032x}", rand::random::<u128>()),
    );
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
    ]);
    if proxy_access_log {
        cmd.arg("--proxy-access-log");
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("failed to spawn local-proxy-daemon")?;

    // Write the config and close stdin so the daemon sees EOF. A failed write means
    // the child already exited; its stderr below carries the reason.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, json.as_bytes());
    }

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
                if proc_alive(pid) {
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
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn self_executable() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(current) = crate::shared::executable::cli_executable() {
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
    crate::local_proxy_control::stop(state)?;
    let pid_path = proxy::local_pid_file(instance_name);
    let log_path = proxy::local_log_file(instance_name);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&log_path);
    crate::wireguard::connection::ConnectionState::remove(instance_name)?;
    Ok(())
}

/// Body of the hidden `local-proxy-daemon` subcommand: daemonize unless
/// `TUNMUX_LOCAL_PROXY_FOREGROUND` is set, then serve until stopped.
///
/// The `LocalProxyConfig` JSON is read from stdin, written there by `spawn_daemon`.
pub fn run_daemon(pid_file: &str, log_file: &str) -> anyhow::Result<()> {
    // Read and decode config before daemonizing so errors surface to the shell.
    let mut json = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut json)?;
    let mut cfg: crate::wireguard::proxy_tunnel::LocalProxyConfig = serde_json::from_slice(&json)?;
    let dns_override_source =
        if let Some((source, dns_servers)) = local_proxy_dns_override_from_env() {
            cfg.dns_servers = dns_servers;
            Some(source)
        } else {
            None
        };

    // Ensure the user proxy dir exists before daemonizing.
    config::ensure_user_proxy_dir()?;

    let foreground = std::env::var_os("TUNMUX_LOCAL_PROXY_FOREGROUND").is_some();
    if !foreground {
        // Daemonize (double-fork).
        crate::shared::daemonize::daemonize(crate::shared::daemonize::OutputPolicy::Discard)?;
    }

    let _logging_guard = if foreground {
        crate::logging::init_terminal(true)?
    } else {
        crate::logging::init_file(log_file, false)?
    };

    if let Some(source) = dns_override_source {
        tracing::info!(
            source = source,
            dns_servers = cfg.dns_servers.len(),
            "local_proxy_dns_servers_overridden_from_env"
        );
    }

    // Ensure panics are captured in logs instead of disappearing after daemonize.
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.as_str()
        } else {
            "non-string panic payload"
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(
            panic = %payload,
            location = %location,
            backtrace = %backtrace,
            "local_proxy_daemon_panic"
        );
    }));

    // Write PID file.
    let pid = std::process::id();
    std::fs::write(pid_file, pid.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(pid_file, std::fs::Permissions::from_mode(0o600))?;
    }
    let startup_status_file = format!("{}.status", pid_file);
    std::fs::write(&startup_status_file, "starting\n")?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&startup_status_file, std::fs::Permissions::from_mode(0o600))?;
    }

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 8);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    let mut control = crate::local_proxy_control::Control::start(std::path::Path::new(pid_file))?;
    let (result, acknowledgment) = rt.block_on(async {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = crate::wireguard::proxy_tunnel::run_local_proxy(cfg, Some(startup_status_file.as_str())) => Ok::<_, anyhow::Error>((result, None)),
            stream = control.stop.recv() => Ok((Ok(()), stream)),
            _ = terminate.recv() => Ok((Ok(()), None)),
            _ = tokio::signal::ctrl_c() => Ok((Ok(()), None)),
        }
    })?;
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    std::fs::remove_file(pid_file)?;
    let _ = std::fs::remove_file(startup_status_file);
    if let Some(stream) = acknowledgment {
        control.acknowledge(stream)?;
    }
    result
}

fn local_proxy_dns_override_from_env() -> Option<(&'static str, Vec<String>)> {
    for key in ["TUNMUX_LOCAL_PROXY_DNS_SERVERS", "TUNMUX_DNS_SERVERS"] {
        let Some(raw_value) = std::env::var_os(key) else {
            continue;
        };

        let dns_servers = parse_dns_servers_env_list(&raw_value.to_string_lossy());
        if !dns_servers.is_empty() {
            return Some((key, dns_servers));
        }
    }

    None
}

fn parse_dns_servers_env_list(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_dns_servers_env_list;

    #[test]
    fn parse_dns_servers_env_list_accepts_csv_and_whitespace() {
        let parsed = parse_dns_servers_env_list("1.1.1.1, 9.9.9.9\n2606:4700:4700::1111\t8.8.8.8");

        assert_eq!(
            parsed,
            vec!["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111", "8.8.8.8"]
        );
    }
}

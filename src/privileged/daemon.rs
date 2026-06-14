use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::info;

use crate::config;
use crate::error::{AppError, Result};

use super::managed_pids::pid_is_alive;

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_proxy_daemon(
    netns: &str,
    interface: &str,
    socks_port: u16,
    http_port: u16,
    proxy_access_log: bool,
    pid_file: &str,
    log_file: &str,
    startup_status_file: &str,
) -> Result<u32> {
    let exe = self_executable_for_spawn()?;
    info!(
        exe = ?exe.display().to_string(),
        netns = ?netns, "spawn_proxy_daemon");

    // Ensure the proxy directory exists (e.g. /var/lib/tunmux/proxy/) for pid/status,
    // and the root log dir (/var/log/tunmux/) for the now-separate log file.
    if let Some(parent) = std::path::Path::new(pid_file).parent() {
        config::ensure_privileged_directory(parent)?;
    }
    config::ensure_root_log_dir()?;

    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(log_file);
    let _ = std::fs::remove_file(startup_status_file);

    let socks = socks_port.to_string();
    let http = http_port.to_string();

    let mut command = Command::new(exe);
    use std::os::unix::process::CommandExt;
    command.arg0("tunmux");
    command.args([
        "proxy-daemon",
        "--netns",
        netns,
        "--interface",
        interface,
        "--socks-port",
        socks.as_str(),
        "--http-port",
        http.as_str(),
        "--pid-file",
        pid_file,
        "--log-file",
        log_file,
        "--startup-status-file",
        startup_status_file,
    ]);
    if proxy_access_log {
        command.arg("--proxy-access-log");
    }
    let mut child = command
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| AppError::Other(format!("failed to spawn proxy-daemon: {}", e)))?;

    // The proxy-daemon double-forks and the intermediate process exits quickly.
    // Wait for it so we don't leave a zombie and can capture early failures.
    let stderr = child.stderr.take();
    let status = child
        .wait()
        .map_err(|e| AppError::Other(format!("failed to wait on proxy-daemon: {}", e)))?;
    if !status.success() {
        let detail = stderr
            .and_then(|mut s| {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                Some(buf)
            })
            .unwrap_or_default();
        return Err(AppError::Proxy(format!(
            "proxy-daemon exited {}: {}",
            status,
            detail.trim()
        )));
    }

    let pid = wait_for_pid_file(pid_file, Duration::from_secs(5))?;
    if !wait_for_startup_ready(startup_status_file, Duration::from_secs(12)) {
        terminate_managed_process(pid);
        let detail = tail_file(log_file, 12);
        return Err(AppError::Proxy(format!(
            "proxy tunnel did not establish a WireGuard handshake within 12s (instance interface {}). Recent log:\n{}",
            interface, detail
        )));
    }

    Ok(pid)
}

pub(super) fn self_executable_for_spawn() -> Result<std::path::PathBuf> {
    if let Ok(current) = std::env::current_exe() {
        if current.exists() {
            return Ok(current);
        }
    }

    if let Ok(cmdline) = std::fs::read("/proc/self/cmdline") {
        if let Some(raw) = cmdline.split(|b| *b == 0).next() {
            if !raw.is_empty() {
                let candidate = std::path::PathBuf::from(String::from_utf8_lossy(raw).to_string());
                if candidate.is_absolute() && candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    Ok(std::path::PathBuf::from("/proc/self/exe"))
}

pub(super) fn wait_for_pid_file(pid_file: &str, timeout: Duration) -> Result<u32> {
    let start = Instant::now();
    while Instant::now().duration_since(start) < timeout {
        if let Ok(pid_text) = std::fs::read_to_string(pid_file) {
            if let Ok(pid) = pid_text.trim().parse::<u32>() {
                if pid_is_alive(pid) {
                    return Ok(pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // If the launcher returns before creating pid file, capture a useful error.
    Err(AppError::Other(
        "proxy daemon did not write a valid pid".into(),
    ))
}

pub(super) fn wait_for_startup_ready(startup_status_file: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while Instant::now().duration_since(start) < timeout {
        if let Ok(text) = std::fs::read_to_string(startup_status_file) {
            if text.trim() == "ready" {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

pub(super) fn terminate_managed_process(pid: u32) {
    let target = Pid::from_raw(pid as i32);
    let _ = kill(target, Signal::SIGTERM);
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(100));
        if !pid_is_alive(pid) {
            return;
        }
    }
    let _ = kill(target, Signal::SIGKILL);
}

pub(super) fn tail_file(path: &str, lines: usize) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return "<log unavailable>".to_string();
    };
    let mut rows: Vec<&str> = content.lines().collect();
    if rows.len() > lines {
        rows = rows.split_off(rows.len() - lines);
    }
    rows.join("\n")
}

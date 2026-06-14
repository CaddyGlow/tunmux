use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::debug;

use crate::error::{AppError, Result};

use super::daemon::self_executable_for_spawn;

pub(super) fn run(args: &[&str]) -> Result<()> {
    debug!(cmd = args.join(" "), "exec");
    let status = Command::new(args[0]).args(&args[1..]).status()?;
    if !status.success() {
        return Err(AppError::Other(format!(
            "command {} failed: {}",
            args[0], status
        )));
    }
    Ok(())
}

pub(super) fn run_output(args: &[&str]) -> Result<std::process::Output> {
    debug!(cmd = args.join(" "), "exec");
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|error| AppError::Other(format!("command {} failed to start: {}", args[0], error)))
}

pub(super) fn run_resolved_set_dns(interface: &str, dns_servers: &[String]) -> Result<()> {
    let mut dns_command = vec!["resolvectl", "dns", interface];
    dns_command.extend(dns_servers.iter().map(String::as_str));
    run(&dns_command)?;
    run(&["resolvectl", "domain", interface, "~."])?;
    run(&["resolvectl", "default-route", interface, "yes"])?;
    Ok(())
}

pub(super) fn run_resolved_revert_dns(interface: &str) -> Result<()> {
    run(&["resolvectl", "revert", interface])
}

pub(super) fn run_wg_quick_up(
    path: &std::path::Path,
    config_content: &[u8],
    prefer_userspace: bool,
) -> Result<()> {
    std::fs::write(path, config_content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    let mut command = Command::new("wg-quick");
    if prefer_userspace {
        command.env("WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD", "1");
        command.env("TUNMUX_GOTATUN_HELPER", "1");
        let helper_exe = self_executable_for_spawn()?;
        command.env("WG_QUICK_USERSPACE_IMPLEMENTATION", &helper_exe);
        debug!(
            helper = ?helper_exe.display().to_string(),
            "wg_quick_userspace_helper"
        );
    }

    debug!(cmd = format!("wg-quick up {}", path.display()), "exec");
    let status = command
        .args(["up", path.to_string_lossy().as_ref()])
        .status()
        .map_err(|e| AppError::Other(format!("wg-quick up failed: {}", e)))?;
    if !status.success() {
        let _ = std::fs::remove_file(path);
        return Err(AppError::WireGuard(format!(
            "wg-quick up exited {}",
            status
        )));
    }
    Ok(())
}

pub(super) fn run_wg_quick_down(path: &std::path::Path) -> Result<()> {
    debug!(cmd = format!("wg-quick down {}", path.display()), "exec");
    let status = Command::new("wg-quick")
        .args(["down", path.to_string_lossy().as_ref()])
        .status()
        .map_err(|e| AppError::Other(format!("wg-quick down failed: {}", e)))?;
    if !status.success() {
        return Err(AppError::WireGuard(format!(
            "wg-quick down exited {}",
            status
        )));
    }
    Ok(())
}

pub(super) fn run_wg_show(interface: &str) -> Result<String> {
    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));

    if socket_path.exists() {
        run_wg_show_uapi(interface, &socket_path)
    } else {
        // Kernel backend: no UAPI socket; wg is already a dependency of WireguardSet.
        run_wg_show_kernel(interface)
    }
}

fn run_wg_show_uapi(interface: &str, socket_path: &std::path::Path) -> Result<String> {
    use std::io::BufRead;

    debug!(socket = ?socket_path.display().to_string(), "uapi_get");
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| AppError::WireGuard(format!("UAPI connect: {e}")))?;
    std::io::Write::write_all(&mut stream, b"get=1\n\n")
        .map_err(|e| AppError::WireGuard(format!("UAPI write: {e}")))?;

    // The UAPI protocol terminates responses with errno=N\n\n (double newline)
    // but keeps the socket open. Read line-by-line and stop after the empty
    // line that follows the errno= line, rather than waiting for EOF.
    let mut raw = String::new();
    let reader = std::io::BufReader::new(&mut stream);
    let mut saw_errno = false;
    for line in reader.lines() {
        let line = line.map_err(|e| AppError::WireGuard(format!("UAPI read: {e}")))?;
        if line.starts_with("errno=") {
            saw_errno = true;
            raw.push_str(&line);
            raw.push('\n');
        } else if line.is_empty() && saw_errno {
            break;
        } else {
            raw.push_str(&line);
            raw.push('\n');
        }
    }

    format_wg_show(&raw, interface)
}

#[cfg(target_os = "linux")]
fn run_wg_show_kernel(interface: &str) -> Result<String> {
    let uapi_text = crate::wireguard::netlink::wg_get_uapi(interface)?;
    format_wg_show(&uapi_text, interface)
}

#[cfg(not(target_os = "linux"))]
fn run_wg_show_kernel(_interface: &str) -> Result<String> {
    Err(AppError::WireGuard(
        "kernel wireguard backend is only supported on linux".to_string(),
    ))
}

pub(super) fn format_wg_show(raw: &str, interface: &str) -> Result<String> {
    use base64::Engine;
    use gotatun::x25519::{PublicKey, StaticSecret};

    struct PeerState {
        public_key_b64: String,
        has_preshared_key: bool,
        endpoint: Option<String>,
        allowed_ips: Vec<String>,
        last_handshake_sec: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        keepalive: u32,
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut listen_port: u32 = 0;
    let mut iface_pub_b64 = String::new();
    let mut peers: Vec<PeerState> = Vec::new();
    let mut current_peer: Option<PeerState> = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key {
            "private_key" => {
                if let Ok(bytes) = wg_hex_to_32(value) {
                    let secret = StaticSecret::from(bytes);
                    let public = PublicKey::from(&secret);
                    iface_pub_b64 =
                        base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
                }
            }
            "listen_port" => listen_port = value.parse().unwrap_or(0),
            "public_key" => {
                if let Some(peer) = current_peer.take() {
                    peers.push(peer);
                }
                if let Ok(bytes) = wg_hex_to_32(value) {
                    current_peer = Some(PeerState {
                        public_key_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                        has_preshared_key: false,
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        last_handshake_sec: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        keepalive: 0,
                    });
                }
            }
            _ => {
                if let Some(ref mut peer) = current_peer {
                    match key {
                        "preshared_key" => {
                            peer.has_preshared_key =
                                value.as_bytes().iter().any(|byte| *byte != b'0')
                        }
                        "endpoint" => peer.endpoint = Some(value.to_string()),
                        "allowed_ip" => peer.allowed_ips.push(value.to_string()),
                        "last_handshake_time_sec" => {
                            peer.last_handshake_sec = value.parse().unwrap_or(0)
                        }
                        "rx_bytes" => peer.rx_bytes = value.parse().unwrap_or(0),
                        "tx_bytes" => peer.tx_bytes = value.parse().unwrap_or(0),
                        "persistent_keepalive_interval" => {
                            peer.keepalive = value.parse().unwrap_or(0)
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(peer) = current_peer.take() {
        peers.push(peer);
    }

    let mut out = String::new();
    out.push_str(&format!("interface: {interface}\n"));
    if !iface_pub_b64.is_empty() {
        out.push_str(&format!("  public key: {iface_pub_b64}\n"));
    }
    out.push_str("  private key: (hidden)\n");
    if listen_port != 0 {
        out.push_str(&format!("  listening port: {listen_port}\n"));
    }

    for peer in &peers {
        out.push('\n');
        out.push_str(&format!("peer: {}\n", peer.public_key_b64));
        if let Some(ref ep) = peer.endpoint {
            out.push_str(&format!("  endpoint: {ep}\n"));
        }
        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("  allowed ips: {}\n", peer.allowed_ips.join(", ")));
        }
        if peer.has_preshared_key {
            out.push_str("  preshared key: (hidden)\n");
        }
        if peer.last_handshake_sec > 0 {
            let ago = now_secs.saturating_sub(peer.last_handshake_sec);
            out.push_str(&format!("  latest handshake: {}\n", wg_format_ago(ago)));
        } else {
            out.push_str("  latest handshake: (none)\n");
        }
        out.push_str(&format!(
            "  transfer: {} received, {} sent\n",
            wg_format_bytes(peer.rx_bytes),
            wg_format_bytes(peer.tx_bytes)
        ));
        if peer.keepalive > 0 {
            out.push_str(&format!(
                "  persistent keepalive: every {} seconds\n",
                peer.keepalive
            ));
        }
    }

    Ok(out)
}

pub(super) fn wg_hex_to_32(s: &str) -> std::result::Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

pub(super) fn wg_format_ago(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs} second{}", if secs == 1 { "" } else { "s" });
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins} minute{}", if mins == 1 { "" } else { "s" });
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours} hour{}", if hours == 1 { "" } else { "s" });
    }
    let days = hours / 24;
    format!("{days} day{}", if days == 1 { "" } else { "s" })
}

pub(super) fn wg_format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn run_gotatun_up(
    interface: &str,
    config_content: &str,
    mtu_override: Option<u16>,
    debug_enabled: bool,
) -> Result<()> {
    use base64::Engine;

    let exe = self_executable_for_spawn()?;
    let config_b64 = base64::engine::general_purpose::STANDARD.encode(config_content);
    for path in [
        gotatun_pid_path(interface),
        gotatun_name_path(interface),
        gotatun_cleanup_status_path(interface),
        // Start a fresh session log so the streamed connect output is just this session's.
        gotatun_log_path(interface),
    ] {
        let _ = std::fs::remove_file(path);
    }

    debug!(
        cmd = format!("{} {} [TUNMUX_GOTATUN_HELPER=1]", exe.display(), interface),
        "exec"
    );
    let mut command = Command::new(exe);
    command
        .env("TUNMUX_GOTATUN_HELPER", "1")
        .env("TUNMUX_GOTATUN_CONFIG_B64", config_b64)
        .arg(interface);
    if let Some(mtu) = mtu_override {
        command.env("TUNMUX_GOTATUN_MTU_OVERRIDE", mtu.to_string());
    }
    if debug_enabled {
        command.env("TUNMUX_DEBUG", "1");
    }
    #[cfg(target_os = "macos")]
    {
        command.env("TUNMUX_GOTATUN_DIAG", "1");
    }
    let status = command
        .status()
        .map_err(|e| AppError::Other(format!("gotatun up failed to start: {}", e)))?;

    if !status.success() {
        return Err(AppError::WireGuard(format!("gotatun up exited {}", status)));
    }
    let pid_path = gotatun_pid_path(interface);
    let pid = read_gotatun_pid(&pid_path)?.ok_or_else(|| {
        AppError::WireGuard(format!(
            "gotatun helper started without writing {}",
            pid_path.display()
        ))
    })?;
    if !pid_is_alive(pid) {
        return Err(AppError::WireGuard(format!(
            "gotatun helper process {} exited during startup",
            pid
        )));
    }
    ensure_gotatun_process_identity(pid)?;
    Ok(())
}

pub(super) fn run_gotatun_down(interface: &str) -> Result<()> {
    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));
    let pid_path = gotatun_pid_path(interface);
    let name_path = gotatun_name_path(interface);
    let cleanup_status_path = gotatun_cleanup_status_path(interface);
    let actual_interface = std::fs::read_to_string(&name_path)
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());

    let tracked_pid = read_gotatun_pid(&pid_path)?;
    if let Some(pid) = tracked_pid.filter(|pid| pid_is_alive(*pid)) {
        ensure_gotatun_process_identity(pid)?;
    }

    let started = Instant::now();
    debug!(
        interface,
        pid = ?tracked_pid,
        socket = %socket_path.display(),
        actual_interface = ?actual_interface,
        "gotatun_shutdown_begin"
    );

    if tracked_pid.is_none()
        && actual_interface.is_none()
        && !socket_path.exists()
        && !cleanup_status_path.exists()
    {
        debug!(interface, "gotatun_shutdown_already_absent");
        return Ok(());
    }

    if socket_path.exists() {
        // The helper treats removal of its UAPI socket as a cooperative shutdown request.
        std::fs::remove_file(&socket_path).map_err(|e| {
            AppError::Other(format!(
                "failed to remove gotatun control socket {}: {}",
                socket_path.display(),
                e
            ))
        })?;
        debug!(interface, "gotatun_shutdown_socket_removed");
    }

    let cleanup_status = wait_for_cleanup_status(&cleanup_status_path, Duration::from_secs(15));
    let cleanup_status = match cleanup_status {
        Some(status) => status,
        None => {
            if let Some(pid) = tracked_pid.filter(|pid| pid_is_alive(*pid)) {
                debug!(pid, interface, "gotatun_shutdown_sigterm_fallback");
                match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(error) => {
                        return Err(AppError::Other(format!(
                            "failed to signal gotatun helper {}: {}",
                            pid, error
                        )));
                    }
                }
            }
            wait_for_cleanup_status(&cleanup_status_path, Duration::from_secs(5)).ok_or_else(
                || {
                    AppError::WireGuard(format!(
                        "gotatun helper did not confirm cleanup within {} seconds; pid={:?}, interface={:?}",
                        started.elapsed().as_secs(),
                        tracked_pid,
                        actual_interface
                    ))
                },
            )?
        }
    };

    match cleanup_status.as_str() {
        "ok" => {}
        cleanup_status => {
            return Err(AppError::WireGuard(format!(
                "gotatun helper cleanup failed: {}",
                cleanup_status
            )));
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(actual_interface) = actual_interface.as_deref() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while macos_interface_exists(actual_interface) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if macos_interface_exists(actual_interface) {
            return Err(AppError::WireGuard(format!(
                "userspace tunnel interface {} still exists after confirmed network cleanup",
                actual_interface
            )));
        }
    }

    debug!(
        interface,
        pid = ?tracked_pid,
        elapsed_ms = started.elapsed().as_millis(),
        "gotatun_shutdown_complete"
    );

    for path in [pid_path, name_path, cleanup_status_path] {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn wait_for_cleanup_status(path: &std::path::Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read_to_string(path) {
            Ok(status) if !status.trim().is_empty() => return Some(status.trim().to_string()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                debug!(
                    path = %path.display(),
                    error = %error,
                    "gotatun_cleanup_status_read_failed"
                );
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn macos_interface_exists(interface: &str) -> bool {
    Command::new("ifconfig")
        .arg(interface)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn read_gotatun_pid(path: &std::path::Path) -> Result<Option<u32>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let pid = raw.trim().parse::<u32>().map_err(|error| {
        AppError::Other(format!(
            "invalid gotatun pid in {}: {}",
            path.display(),
            error
        ))
    })?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(AppError::Other(format!(
            "invalid gotatun pid {} in {}",
            pid,
            path.display()
        )));
    }
    Ok(Some(pid))
}

fn pid_is_alive(pid: u32) -> bool {
    let result = unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
}

fn ensure_gotatun_process_identity(pid: u32) -> Result<()> {
    let expected = std::env::current_exe()
        .map_err(|error| AppError::Other(format!("cannot resolve current executable: {error}")))?;
    let actual = process_executable(pid).ok_or_else(|| {
        AppError::Other(format!(
            "cannot resolve executable for gotatun helper pid {}",
            pid
        ))
    })?;

    let expected = std::fs::canonicalize(&expected).unwrap_or(expected);
    let actual = std::fs::canonicalize(&actual).unwrap_or(actual);
    if actual != expected {
        return Err(AppError::Other(format!(
            "refusing to signal pid {} because executable {} does not match {}",
            pid,
            actual.display(),
            expected.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_executable(pid: u32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn process_executable(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = vec![0u8; nix::libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        nix::libc::proc_pidpath(
            pid as nix::libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer[..length as usize],
    )))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_executable(_pid: u32) -> Option<std::path::PathBuf> {
    None
}

fn gotatun_pid_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "pid")
}

fn gotatun_name_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "name")
}

fn gotatun_cleanup_status_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "cleanup")
}

/// Log file the gotatun helper writes to. The service tails this to stream the
/// helper's setup/teardown output back to the calling CLI. Shares the single
/// source of truth in `config` with `userspace_helper` so the paths always match.
///
/// macOS: `~/Library/Logs/tunmux-<interface>.log`; Linux: `/var/log/tunmux/<interface>.log`.
pub(super) fn gotatun_log_path(interface: &str) -> std::path::PathBuf {
    crate::config::gotatun_helper_log_path(interface)
}

fn gotatun_runtime_path(interface: &str, suffix: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.tunmux.{suffix}"))
}

#[cfg(target_os = "linux")]
pub(super) fn wg_set(
    interface: &str,
    private_key: &str,
    peer_public_key: &str,
    endpoint: &str,
    allowed_ips: &str,
) -> Result<()> {
    crate::wireguard::netlink::wg_set_device(
        interface,
        private_key,
        peer_public_key,
        endpoint,
        allowed_ips,
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn wg_set(
    _interface: &str,
    _private_key: &str,
    _peer_public_key: &str,
    _endpoint: &str,
    _allowed_ips: &str,
) -> Result<()> {
    Err(AppError::WireGuard(
        "kernel wireguard backend is only supported on linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn set_preshared_key(interface: &str, peer_public_key: &str, psk: &str) -> Result<()> {
    crate::wireguard::netlink::wg_set_psk(interface, peer_public_key, psk)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn set_preshared_key(
    _interface: &str,
    _peer_public_key: &str,
    _psk: &str,
) -> Result<()> {
    Err(AppError::WireGuard(
        "kernel wireguard backend is only supported on linux".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_gotatun_process_identity, gotatun_runtime_path, read_gotatun_pid,
        wait_for_cleanup_status,
    };

    fn temp_path(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tunmux-gotatun-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn gotatun_runtime_paths_are_scoped_to_interface() {
        assert_eq!(
            gotatun_runtime_path("wgconf0", "cleanup"),
            std::path::PathBuf::from("/var/run/wireguard/wgconf0.tunmux.cleanup")
        );
    }

    #[test]
    fn read_gotatun_pid_handles_missing_valid_and_invalid_files() {
        let path = temp_path("pid");
        assert_eq!(read_gotatun_pid(&path).expect("missing pid"), None);

        std::fs::write(&path, format!("{}\n", std::process::id())).expect("write valid pid");
        assert_eq!(
            read_gotatun_pid(&path).expect("valid pid"),
            Some(std::process::id())
        );

        std::fs::write(&path, "0\n").expect("write invalid pid");
        assert!(read_gotatun_pid(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_process_matches_gotatun_executable_identity_check() {
        ensure_gotatun_process_identity(std::process::id()).expect("current executable identity");
    }

    #[test]
    fn cleanup_status_waits_for_helper_confirmation() {
        let path = temp_path("cleanup-status");
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::write(writer_path, "ok\n").expect("write cleanup status");
        });

        let status = wait_for_cleanup_status(&path, std::time::Duration::from_secs(1));
        writer.join().expect("cleanup status writer");
        let _ = std::fs::remove_file(path);
        assert_eq!(status.as_deref(), Some("ok"));
    }
}

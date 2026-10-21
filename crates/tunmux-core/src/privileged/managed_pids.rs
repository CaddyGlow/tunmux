use std::os::unix::fs::PermissionsExt;

use nix::libc;

use crate::config;
use crate::error::{AppError, Result};

pub(super) fn managed_pid_registry_dir() -> std::path::PathBuf {
    if let Some(override_dir) = std::env::var_os("TUNMUX_MANAGED_PIDS_DIR") {
        let path = std::path::PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    config::privileged_socket_dir().join("managed-pids")
}

pub(super) fn managed_pid_entry_path(pid: u32) -> std::path::PathBuf {
    managed_pid_registry_dir().join(format!("{}.start", pid))
}

pub(super) fn ensure_managed_pid_registry_dir() -> Result<()> {
    let dir = managed_pid_registry_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn register_managed_pid(pid: u32) -> Result<()> {
    let start_ticks = process_start_ticks(pid)
        .ok_or_else(|| AppError::Other(format!("failed reading /proc/{}/stat", pid)))?;
    ensure_managed_pid_registry_dir()?;
    let path = managed_pid_entry_path(pid);
    std::fs::write(&path, format!("{}\n", start_ticks))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(super) fn unregister_managed_pid(pid: u32) -> Result<()> {
    let path = managed_pid_entry_path(pid);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) fn managed_pid_is_current(pid: u32) -> Result<bool> {
    let path = managed_pid_entry_path(pid);
    if !path.exists() {
        return Ok(false);
    }

    let expected = match std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
    {
        Some(start) => start,
        None => {
            let _ = unregister_managed_pid(pid);
            return Ok(false);
        }
    };

    match process_start_ticks(pid) {
        Some(current) if current == expected => Ok(true),
        None if expected == 0 && pid_is_alive(pid) => Ok(true),
        _ => {
            let _ = unregister_managed_pid(pid);
            Ok(false)
        }
    }
}

pub(super) fn cleanup_stale_managed_pid_registry_entries() -> Result<()> {
    ensure_managed_pid_registry_dir()?;
    let dir = managed_pid_registry_dir();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        let Some(pid) = parse_managed_pid_entry_name(&name) else {
            let _ = std::fs::remove_file(entry.path());
            continue;
        };

        let _ = managed_pid_is_current(pid)?;
    }
    Ok(())
}

fn parse_managed_pid_entry_name(name: &str) -> Option<u32> {
    name.strip_suffix(".start")?.parse::<u32>().ok()
}

pub(super) fn lease_token_is_live(token: &str) -> bool {
    let mut parts = token.split(':');
    let pid = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
        Some(pid) => pid,
        None => return false,
    };
    let start_ticks = match parts.next().and_then(|s| s.parse::<u64>().ok()) {
        Some(start) => start,
        None => return false,
    };
    match process_start_ticks(pid) {
        Some(current) => current == start_ticks,
        None => start_ticks == 0 && pid_is_alive(pid),
    }
}

pub(super) fn pid_is_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
pub(super) fn process_start_ticks(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(path).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn process_start_ticks(_pid: u32) -> Option<u64> {
    None
}

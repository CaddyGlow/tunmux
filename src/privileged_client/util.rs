use std::fs;
use std::path::PathBuf;

use nix::unistd::Uid;
#[cfg(not(target_os = "android"))]
use nix::unistd::{Gid, Group};

use crate::privileged_api::PrivilegedRequest;

pub(crate) const FALLBACK_AUTH_GROUP: &str = "tunmux";

pub(crate) fn shell_quote(value: &str) -> String {
    if !value.contains([' ', '\t', '\'', '"', '\\']) {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

pub(crate) fn request_kind(request: &PrivilegedRequest) -> &'static str {
    match request {
        PrivilegedRequest::NamespaceCreate { .. } => "NamespaceCreate",
        PrivilegedRequest::NamespaceDelete { .. } => "NamespaceDelete",
        PrivilegedRequest::NamespaceExists { .. } => "NamespaceExists",
        PrivilegedRequest::InterfaceCreateWireguard { .. } => "InterfaceCreateWireguard",
        PrivilegedRequest::InterfaceDelete { .. } => "InterfaceDelete",
        PrivilegedRequest::InterfaceMoveToNetns { .. } => "InterfaceMoveToNetns",
        PrivilegedRequest::NetnsExec { .. } => "NetnsExec",
        PrivilegedRequest::HostIpAddrAdd { .. } => "HostIpAddrAdd",
        PrivilegedRequest::HostIpLinkSetUp { .. } => "HostIpLinkSetUp",
        PrivilegedRequest::HostIpLinkSetMtu { .. } => "HostIpLinkSetMtu",
        PrivilegedRequest::HostIpRouteAdd { .. } => "HostIpRouteAdd",
        PrivilegedRequest::HostIpRouteDel { .. } => "HostIpRouteDel",
        PrivilegedRequest::HostResolvedSetDns { .. } => "HostResolvedSetDns",
        PrivilegedRequest::HostResolvedRevertDns { .. } => "HostResolvedRevertDns",
        PrivilegedRequest::WireguardSet { .. } => "WireguardSet",
        PrivilegedRequest::WireguardSetPsk { .. } => "WireguardSetPsk",
        PrivilegedRequest::WgQuickRun { .. } => "WgQuickRun",
        PrivilegedRequest::GotaTunRun { .. } => "GotaTunRun",
        PrivilegedRequest::EnsureDir { .. } => "EnsureDir",
        PrivilegedRequest::WriteFile { .. } => "WriteFile",
        PrivilegedRequest::RemoveDirAll { .. } => "RemoveDirAll",
        PrivilegedRequest::KillPid { .. } => "KillPid",
        PrivilegedRequest::SpawnProxyDaemon { .. } => "SpawnProxyDaemon",
        PrivilegedRequest::LeaseAcquire { .. } => "LeaseAcquire",
        PrivilegedRequest::LeaseRelease { .. } => "LeaseRelease",
        PrivilegedRequest::ShutdownIfIdle => "ShutdownIfIdle",
        PrivilegedRequest::WgShow { .. } => "WgShow",
    }
}

pub(crate) fn resolve_client_authorized_group(configured_group: &str) -> String {
    let configured = configured_group.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    current_user_primary_group_name().unwrap_or_else(|| FALLBACK_AUTH_GROUP.to_string())
}

#[cfg(not(target_os = "android"))]
pub(crate) fn current_user_primary_group_name() -> Option<String> {
    Group::from_gid(Gid::current())
        .ok()
        .flatten()
        .and_then(|group| {
            let name = group.name.trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
}

#[cfg(target_os = "android")]
pub(crate) fn current_user_primary_group_name() -> Option<String> {
    None
}

pub(crate) fn startup_lock_dir() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("tunmux");
    }
    let uid = Uid::current().as_raw();
    PathBuf::from(format!("/tmp/tunmux-{}", uid))
}

pub(crate) fn build_lease_token() -> String {
    let pid = std::process::id();
    let start_ticks = process_start_ticks(pid).unwrap_or(0);
    format!("{}:{}", pid, start_ticks)
}

pub(crate) fn configured_privileged_stdio_log_path() -> Option<PathBuf> {
    let value = std::env::var_os("TUNMUX_PRIVILEGED_STDIO_LOG")?;
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(path)
}

pub(crate) fn process_start_ticks(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = fs::read_to_string(path).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

mod commands;
mod daemon;
mod dispatch;
mod managed_pids;

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
#[cfg(not(target_os = "android"))]
use nix::unistd::Group;
use nix::unistd::{chown, Gid};
use tracing::{debug, info, warn};

use crate::config;
use crate::privileged_api::{PrivilegedRequest, PrivilegedResponse};

use dispatch::dispatch;
use managed_pids::{cleanup_stale_managed_pid_registry_entries, ensure_managed_pid_registry_dir};

const AUTH_GROUP_NAME: &str = "tunmux";

struct ControlState {
    leases: HashSet<String>,
    allow_shutdown: bool,
    shutdown_requested: bool,
}

impl ControlState {
    fn new(allow_shutdown: bool) -> Self {
        Self {
            leases: HashSet::new(),
            allow_shutdown,
            shutdown_requested: false,
        }
    }

    fn prune_stale_leases(&mut self) {
        self.leases
            .retain(|token| managed_pids::lease_token_is_live(token));
    }

    fn should_exit_now(&mut self) -> bool {
        if !self.allow_shutdown || !self.shutdown_requested {
            return false;
        }
        self.prune_stale_leases();
        self.leases.is_empty()
    }
}

pub fn serve(
    cli_authorized_group: Option<String>,
    cli_idle_timeout_ms: Option<u64>,
    cli_autostarted: bool,
) -> anyhow::Result<()> {
    let authorized_group = resolve_authorized_group(cli_authorized_group);
    let idle_timeout = cli_idle_timeout_ms.map(|ms| Duration::from_millis(ms.max(100)));
    debug!(
        autostarted = ?cli_autostarted,
        idle_timeout_ms = ?idle_timeout.map(|d| d.as_millis()).unwrap_or(0) as u64, "privileged_service_start");
    config::ensure_privileged_socket_dir()?;
    config::ensure_privileged_runtime_dir()?;
    ensure_managed_pid_registry_dir()?;
    cleanup_stale_managed_pid_registry_entries()?;

    // Resolve group GID for chown of socket dir and file.
    let group_gid = authorized_group
        .as_deref()
        .and_then(read_group_gid)
        .or_else(|| read_group_gid(AUTH_GROUP_NAME));

    // Chown socket directory so group members can traverse it (mode 0750).
    if let Some(gid) = group_gid {
        let socket_dir = config::privileged_socket_dir();
        chown(&socket_dir, None, Some(Gid::from_raw(gid)))?;
        info!(
            path = ?socket_dir.display().to_string(),
            gid = ?gid, "socket_dir_chowned");
    }

    let listener = match systemd_activated_listener()? {
        Some(listener) => {
            info!("privileged_service_systemd_socket_activation");
            listener
        }
        None => {
            let socket_path = config::privileged_socket_path();
            if socket_path.exists() {
                let _ = std::fs::remove_file(&socket_path);
            }

            let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
            let perms = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(&socket_path, perms)?;

            // Chown socket file so group members can connect (mode 0660).
            if let Some(gid) = group_gid {
                chown(&socket_path, None, Some(Gid::from_raw(gid)))?;
                info!(
                    path = ?socket_path.display().to_string(),
                    gid = ?gid, "socket_file_chowned");
            }

            info!(
                socket = ?socket_path.display().to_string(), "privileged_service_listening");
            listener
        }
    };

    if idle_timeout.is_some() {
        listener.set_nonblocking(true)?;
        info!(
            idle_timeout_ms = ?idle_timeout.map(|d| d.as_millis()).unwrap_or_default() as u64, "privileged_service_idle_timeout_enabled");
    }

    let mut control_state = ControlState::new(cli_autostarted);
    let mut last_activity = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut stream = stream;
                loop {
                    match handle_client(
                        &mut stream,
                        &mut control_state,
                        authorized_group.as_deref(),
                    ) {
                        ClientReadResult::ConnectionClosed => break,
                        ClientReadResult::Response(response) => {
                            let mut buffer = serde_json::to_vec(&response)?;
                            buffer.push(b'\n');
                            if let Err(e) = stream.write_all(&buffer) {
                                warn!( error = ?e.to_string(), "privileged_response_write_failed");
                                break;
                            }
                            last_activity = Instant::now();
                            if control_state.should_exit_now() {
                                debug!(
                                    "privileged_service_stop_condition_explicit_shutdown_no_leases"
                                );
                                info!("privileged_service_exiting_explicit_shutdown");
                                return Ok(());
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(timeout) = idle_timeout {
                    if last_activity.elapsed() >= timeout {
                        debug!("privileged_service_stop_condition_idle_timeout_elapsed");
                        info!(
                            idle_timeout_ms = ?timeout.as_millis() as u64, "privileged_service_exiting_idle_timeout");
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                return Err(e.into());
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn serve_stdio(cli_idle_timeout_ms: Option<u64>, cli_autostarted: bool) -> anyhow::Result<()> {
    debug!(
        autostarted = ?cli_autostarted,
        idle_timeout_ms = ?cli_idle_timeout_ms.unwrap_or(0), "privileged_stdio_service_start");
    config::ensure_privileged_runtime_dir()?;
    ensure_managed_pid_registry_dir()?;
    cleanup_stale_managed_pid_registry_entries()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut control_state = ControlState::new(cli_autostarted);

    loop {
        let mut payload = String::new();
        let bytes = reader.read_line(&mut payload)?;
        if bytes == 0 {
            debug!("privileged_stdio_service_exiting_stdin_eof");
            return Ok(());
        }

        let response = process_request_payload(&payload, &mut control_state, None);
        let mut buffer = serde_json::to_vec(&response)?;
        buffer.push(b'\n');
        writer.write_all(&buffer)?;
        writer.flush()?;

        if control_state.should_exit_now() {
            debug!("privileged_stdio_service_stop_condition_explicit_shutdown_no_leases");
            info!("privileged_stdio_service_exiting_explicit_shutdown");
            return Ok(());
        }
    }
}

fn systemd_activated_listener() -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    let Some(listen_pid) = std::env::var("LISTEN_PID").ok() else {
        return Ok(None);
    };
    let listen_pid: u32 = match listen_pid.parse() {
        Ok(pid) => pid,
        Err(_) => return Ok(None),
    };
    if listen_pid != std::process::id() {
        return Ok(None);
    }

    let listen_fds: usize = match std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        Some(fds) if fds > 0 => fds,
        _ => return Ok(None),
    };
    let _ = listen_fds;

    // First inherited descriptor starts at fd 3 as defined by socket activation protocol.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };

    // Prevent reused descriptors by descendants from accidentally consuming this fd.
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");

    Ok(Some(listener))
}

enum ClientReadResult {
    ConnectionClosed,
    Response(PrivilegedResponse),
}

fn handle_client(
    stream: &mut UnixStream,
    control_state: &mut ControlState,
    authorized_group: Option<&str>,
) -> ClientReadResult {
    let mut reader = BufReader::new(&mut *stream);
    let mut payload = String::new();
    match reader.read_line(&mut payload) {
        Ok(0) => return ClientReadResult::ConnectionClosed,
        Ok(_) => {}
        Err(e) => {
            return ClientReadResult::Response(PrivilegedResponse::Error {
                code: "Protocol".into(),
                message: format!("failed to read request: {}", e),
            });
        }
    }

    let peer = {
        #[cfg(target_os = "linux")]
        {
            match getsockopt(&*stream, PeerCredentials) {
                Ok(peer) => {
                    let peer_uid = peer.uid();
                    let peer_gid = peer.gid();
                    if !is_authorized(peer_uid, peer_gid, authorized_group) {
                        let message =
                            format!("peer uid={} gid={} not authorized", peer_uid, peer_gid);
                        warn!(
                            uid = ?peer_uid,
                            gid = ?peer_gid, "peer_not_authorized");
                        return ClientReadResult::Response(PrivilegedResponse::Error {
                            code: "Auth".into(),
                            message,
                        });
                    }
                    (peer_uid, peer_gid)
                }
                Err(e) => {
                    return ClientReadResult::Response(PrivilegedResponse::Error {
                        code: "Auth".into(),
                        message: format!("SO_PEERCRED failed: {}", e),
                    });
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = authorized_group;
            (0u32, 0u32)
        }
    };

    ClientReadResult::Response(process_request_payload(
        &payload,
        control_state,
        Some((peer.0, peer.1)),
    ))
}

fn process_request_payload(
    payload: &str,
    control_state: &mut ControlState,
    peer: Option<(u32, u32)>,
) -> PrivilegedResponse {
    if payload.trim().is_empty() {
        return PrivilegedResponse::Error {
            code: "Protocol".into(),
            message: "empty privileged request".into(),
        };
    }

    let request: PrivilegedRequest = match serde_json::from_str::<PrivilegedRequest>(payload) {
        Ok(req) => req,
        Err(e) => {
            return PrivilegedResponse::Error {
                code: "Protocol".into(),
                message: format!("invalid request format: {}", e),
            };
        }
    };
    let request_kind = describe_request(&request);
    if let Some((uid, gid)) = peer {
        info!(
            transport = ?"socket",
            uid = ?uid,
            gid = ?gid,
            request = ?request_kind, "privileged_request_received");
    } else {
        info!(
            transport = ?"stdio",
            request = ?request_kind, "privileged_request_received");
    }

    if let Err(e) = request.validate() {
        return PrivilegedResponse::Error {
            code: "Validation".into(),
            message: e,
        };
    }
    if let Err(e) = cleanup_stale_managed_pid_registry_entries() {
        return PrivilegedResponse::Error {
            code: "IO".into(),
            message: format!("managed pid cleanup failed: {}", e),
        };
    }

    dispatch(request, control_state)
}

fn describe_request(request: &PrivilegedRequest) -> &'static str {
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

fn resolve_authorized_group(cli_group: Option<String>) -> Option<String> {
    if let Some(group) = cli_group {
        let trimmed = group.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Ok(group) = std::env::var("TUNMUX_PRIVILEGED_GROUP") {
        let trimmed = group.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    Some(AUTH_GROUP_NAME.to_string())
}

#[cfg(target_os = "linux")]
fn is_authorized(peer_uid: u32, peer_gid: u32, authorized_group: Option<&str>) -> bool {
    if peer_uid == 0 {
        return true;
    }

    if let Ok(uids) = std::env::var("TUNMUX_PRIVILEGED_UIDS") {
        let allowed = uids
            .split(',')
            .filter_map(|value| value.parse::<u32>().ok())
            .any(|uid| uid == peer_uid);
        if allowed {
            return true;
        }
    }

    let allowed_gid = std::env::var("TUNMUX_PRIVILEGED_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .or_else(|| authorized_group.and_then(read_group_gid))
        .or_else(|| read_group_gid(AUTH_GROUP_NAME));
    if let Some(gid) = allowed_gid {
        if gid == peer_gid {
            return true;
        }
    }

    false
}

#[cfg(not(target_os = "android"))]
fn read_group_gid(group_name: &str) -> Option<u32> {
    Group::from_name(group_name)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

#[cfg(target_os = "android")]
fn read_group_gid(_group_name: &str) -> Option<u32> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::privileged_api::KillSignal;
    use managed_pids::{
        managed_pid_entry_path, managed_pid_registry_dir, process_start_ticks, register_managed_pid,
    };
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn shutdown_if_idle_rejected_when_control_disabled() {
        let mut state = ControlState::new(false);
        let response = dispatch(PrivilegedRequest::ShutdownIfIdle, &mut state);
        match response {
            PrivilegedResponse::Error { code, .. } => assert_eq!(code, "Control"),
            other => panic!("expected control error, got {:?}", other),
        }
    }

    #[test]
    fn lease_refcount_blocks_then_allows_shutdown() {
        let mut state = ControlState::new(true);
        let token = live_token();

        let acquired = dispatch(
            PrivilegedRequest::LeaseAcquire {
                token: token.clone(),
            },
            &mut state,
        );
        assert!(matches!(acquired, PrivilegedResponse::Unit));

        let shutdown_while_leased = dispatch(PrivilegedRequest::ShutdownIfIdle, &mut state);
        assert!(matches!(
            shutdown_while_leased,
            PrivilegedResponse::Bool(false)
        ));
        assert!(!state.should_exit_now());

        let released = dispatch(PrivilegedRequest::LeaseRelease { token }, &mut state);
        assert!(matches!(released, PrivilegedResponse::Unit));
        assert!(state.should_exit_now());
    }

    #[test]
    fn lease_token_liveness_checks_pid_start_ticks() {
        let token = live_token();
        assert!(managed_pids::lease_token_is_live(&token));
        assert!(!managed_pids::lease_token_is_live("999999:1"));
        assert!(!managed_pids::lease_token_is_live("invalid-token"));
    }

    #[test]
    fn managed_pid_registry_round_trip_and_stale_cleanup() {
        with_managed_pid_registry_dir(|| {
            let pid = std::process::id();
            register_managed_pid(pid).expect("register managed pid");
            assert!(managed_pids::managed_pid_is_current(pid).expect("check managed pid"));

            let stale = managed_pid_entry_path(999_999);
            std::fs::write(&stale, "1\n").expect("write stale entry");
            managed_pids::cleanup_stale_managed_pid_registry_entries()
                .expect("cleanup stale entries");
            assert!(!stale.exists());
        });
    }

    #[test]
    fn managed_pid_cleanup_removes_invalid_entry_names() {
        with_managed_pid_registry_dir(|| {
            managed_pids::ensure_managed_pid_registry_dir()
                .expect("ensure managed pid registry dir");
            let invalid = managed_pid_registry_dir().join("bad-entry");
            std::fs::write(&invalid, "junk").expect("write invalid entry");
            managed_pids::cleanup_stale_managed_pid_registry_entries()
                .expect("cleanup invalid entries");
            assert!(!invalid.exists());
        });
    }

    #[test]
    fn kill_pid_rejects_stale_registry_entry_and_cleans_file() {
        with_managed_pid_registry_dir(|| {
            let pid = std::process::id();
            let stale_path = managed_pid_entry_path(pid);
            std::fs::write(&stale_path, "1\n").expect("write stale managed entry");

            let mut state = ControlState::new(false);
            let response = dispatch(
                PrivilegedRequest::KillPid {
                    pid,
                    signal: KillSignal::Term,
                },
                &mut state,
            );

            match response {
                PrivilegedResponse::Error { code, message } => {
                    assert_eq!(code, "Authorization");
                    assert!(message.contains("not managed by privileged service"));
                }
                other => panic!("expected authorization error, got {:?}", other),
            }
            assert!(!stale_path.exists());
        });
    }

    #[test]
    fn route_add_conflict_detects_file_exists_case_insensitive() {
        assert!(dispatch::route_add_conflicts_with_existing_route(
            "RTNETLINK answers: File exists"
        ));
        assert!(dispatch::route_add_conflicts_with_existing_route(
            "rtnetlink answers: file exists"
        ));
        assert!(!dispatch::route_add_conflicts_with_existing_route(
            "network unreachable"
        ));
    }

    fn live_token() -> String {
        let pid = std::process::id();
        let start = process_start_ticks(pid).expect("must read current process start ticks");
        format!("{}:{}", pid, start)
    }

    fn with_managed_pid_registry_dir<F>(f: F)
    where
        F: FnOnce(),
    {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock env mutex");

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tunmux-managed-pids-test-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&dir).expect("create test registry dir");

        let old = std::env::var_os("TUNMUX_MANAGED_PIDS_DIR");
        std::env::set_var("TUNMUX_MANAGED_PIDS_DIR", &dir);
        f();
        if let Some(value) = old {
            std::env::set_var("TUNMUX_MANAGED_PIDS_DIR", value);
        } else {
            std::env::remove_var("TUNMUX_MANAGED_PIDS_DIR");
        }

        let _ = std::fs::remove_dir_all(dir);
    }
}

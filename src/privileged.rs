use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::libc;
use nix::sys::signal::{kill, Signal};
#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
#[cfg(not(target_os = "android"))]
use nix::unistd::Group;
use nix::unistd::{chown, Gid, Pid};
use tracing::{debug, info, warn};

use crate::config;
use crate::error::{AppError, Result};
use crate::privileged_api::{
    GotaTunAction, KillSignal, PrivilegedRequest, PrivilegedResponse, WgQuickAction,
};

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
        self.leases.retain(|token| lease_token_is_live(token));
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

fn dispatch(request: PrivilegedRequest, control_state: &mut ControlState) -> PrivilegedResponse {
    match request {
        PrivilegedRequest::NamespaceCreate { name } => {
            execute_unit(run(&["ip", "netns", "add", name.as_str()]))
        }

        PrivilegedRequest::NamespaceDelete { name } => {
            execute_unit(run(&["ip", "netns", "del", name.as_str()]))
        }

        PrivilegedRequest::NamespaceExists { name } => {
            let path = std::path::Path::new("/run/netns").join(name);
            PrivilegedResponse::Bool(path.exists())
        }

        PrivilegedRequest::InterfaceCreateWireguard { name } => execute_unit(run(&[
            "ip",
            "link",
            "add",
            "dev",
            name.as_str(),
            "type",
            "wireguard",
        ])),

        PrivilegedRequest::InterfaceDelete { name } => {
            execute_unit(run(&["ip", "link", "del", "dev", name.as_str()]))
        }

        PrivilegedRequest::InterfaceMoveToNetns {
            interface,
            namespace,
        } => execute_unit(run(&[
            "ip",
            "link",
            "set",
            interface.as_str(),
            "netns",
            namespace.as_str(),
        ])),

        PrivilegedRequest::NetnsExec { namespace, args } => {
            if args.is_empty() {
                return PrivilegedResponse::Error {
                    code: "Validation".into(),
                    message: "empty args".into(),
                };
            }

            let mut command_args: Vec<&str> = vec!["ip", "netns", "exec", namespace.as_str()];
            command_args.extend(args.iter().map(String::as_str));

            debug!(cmd = command_args.join(" "), "exec");
            let output = Command::new(command_args[0])
                .args(&command_args[1..])
                .output();
            match output {
                Ok(out) if out.status.success() => PrivilegedResponse::Unit,
                Ok(out) => PrivilegedResponse::Error {
                    code: "Kernel".into(),
                    message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                },
                Err(e) => PrivilegedResponse::Error {
                    code: "Kernel".into(),
                    message: format!("ip netns exec failed: {}", e),
                },
            }
        }

        PrivilegedRequest::HostIpAddrAdd { interface, cidr } => execute_unit(run(&[
            "ip",
            "addr",
            "add",
            cidr.as_str(),
            "dev",
            interface.as_str(),
        ])),

        PrivilegedRequest::HostIpLinkSetUp { interface } => {
            execute_unit(run(&["ip", "link", "set", "up", "dev", interface.as_str()]))
        }

        PrivilegedRequest::HostIpLinkSetMtu { interface, mtu } => {
            let mtu = mtu.to_string();
            execute_unit(run(&[
                "ip",
                "link",
                "set",
                "dev",
                interface.as_str(),
                "mtu",
                mtu.as_str(),
            ]))
        }

        PrivilegedRequest::HostIpRouteAdd {
            destination,
            via,
            dev,
        } => execute_route("add", destination.as_str(), via.as_deref(), dev.as_str()),

        PrivilegedRequest::HostIpRouteDel {
            destination,
            via,
            dev,
        } => execute_route("del", destination.as_str(), via.as_deref(), dev.as_str()),

        PrivilegedRequest::HostResolvedSetDns {
            interface,
            dns_servers,
        } => execute_unit(run_resolved_set_dns(interface.as_str(), &dns_servers)),

        PrivilegedRequest::HostResolvedRevertDns { interface } => {
            execute_unit(run_resolved_revert_dns(interface.as_str()))
        }

        PrivilegedRequest::WireguardSet {
            interface,
            private_key,
            peer_public_key,
            endpoint,
            allowed_ips,
        } => execute_unit(wg_set(
            interface.as_str(),
            private_key.as_str(),
            peer_public_key.as_str(),
            endpoint.as_str(),
            allowed_ips.as_str(),
        )),

        PrivilegedRequest::WireguardSetPsk {
            interface,
            peer_public_key,
            psk,
        } => execute_unit(set_preshared_key(
            interface.as_str(),
            peer_public_key.as_str(),
            psk.as_str(),
        )),

        PrivilegedRequest::WgQuickRun {
            action,
            interface,
            provider,
            config_content,
            prefer_userspace,
        } => {
            let base = config::privileged_wg_dir().join(provider.as_str());
            if let Err(e) = config::ensure_privileged_directory(&base) {
                return PrivilegedResponse::Error {
                    code: "IO".into(),
                    message: format!("failed creating wg dir: {}", e),
                };
            }

            let config_path = base.join(format!("{interface}.conf"));
            match action {
                WgQuickAction::Up => {
                    match run_wg_quick_up(&config_path, config_content.as_bytes(), prefer_userspace)
                    {
                        Ok(()) => PrivilegedResponse::Unit,
                        Err(e) => PrivilegedResponse::Error {
                            code: categorize_error(&e),
                            message: format!("{}", e),
                        },
                    }
                }
                WgQuickAction::Down => {
                    let result = run_wg_quick_down(&config_path);
                    let _ = std::fs::remove_file(&config_path);
                    match result {
                        Ok(()) => PrivilegedResponse::Unit,
                        Err(e) => PrivilegedResponse::Error {
                            code: categorize_error(&e),
                            message: format!("{}", e),
                        },
                    }
                }
            }
        }

        PrivilegedRequest::GotaTunRun {
            action,
            interface,
            config_content,
        } => match action {
            GotaTunAction::Up => {
                match run_gotatun_up(interface.as_str(), config_content.as_str()) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(e) => PrivilegedResponse::Error {
                        code: categorize_error(&e),
                        message: e.to_string(),
                    },
                }
            }
            GotaTunAction::Down => match run_gotatun_down(interface.as_str()) {
                Ok(()) => PrivilegedResponse::Unit,
                Err(e) => PrivilegedResponse::Error {
                    code: categorize_error(&e),
                    message: e.to_string(),
                },
            },
        },

        PrivilegedRequest::EnsureDir { path, mode } => match std::fs::create_dir_all(&path) {
            Err(e) => PrivilegedResponse::Error {
                code: "IO".into(),
                message: format!("create dir {} failed: {}", path, e),
            },
            Ok(()) => {
                match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(e) => PrivilegedResponse::Error {
                        code: "IO".into(),
                        message: format!("set permissions {} failed: {}", path, e),
                    },
                }
            }
        },

        PrivilegedRequest::WriteFile {
            path,
            contents,
            mode,
        } => {
            if let Err(e) = std::fs::write(&path, contents) {
                PrivilegedResponse::Error {
                    code: "IO".into(),
                    message: format!("write {} failed: {}", path, e),
                }
            } else if let Err(e) =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            {
                PrivilegedResponse::Error {
                    code: "IO".into(),
                    message: format!("chmod {} failed: {}", path, e),
                }
            } else {
                PrivilegedResponse::Unit
            }
        }

        PrivilegedRequest::RemoveDirAll { path } => match std::fs::remove_dir_all(&path) {
            Ok(()) => PrivilegedResponse::Unit,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PrivilegedResponse::Unit,
            Err(e) => PrivilegedResponse::Error {
                code: "IO".into(),
                message: format!("remove_dir_all {} failed: {}", path, e),
            },
        },

        PrivilegedRequest::KillPid { pid, signal } => {
            let managed = match managed_pid_is_current(pid) {
                Ok(managed) => managed,
                Err(e) => {
                    return PrivilegedResponse::Error {
                        code: "IO".into(),
                        message: format!("managed pid check failed: {}", e),
                    };
                }
            };
            if !managed {
                return PrivilegedResponse::Error {
                    code: "Authorization".into(),
                    message: format!("pid {} is not managed by privileged service", pid),
                };
            }
            if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                let exe_str = exe.to_string_lossy();
                let exe_name = exe_str.strip_suffix(" (deleted)").unwrap_or(&exe_str);
                if !exe_name.ends_with("/tunmux") {
                    return PrivilegedResponse::Error {
                        code: "Authorization".into(),
                        message: "target pid not tunmux".into(),
                    };
                }
            } else {
                return PrivilegedResponse::Error {
                    code: "Kernel".into(),
                    message: "failed reading /proc/<pid>/exe".into(),
                };
            }

            let signal = match signal {
                KillSignal::Term => Signal::SIGTERM,
                KillSignal::Kill => Signal::SIGKILL,
            };
            let target = Pid::from_raw(pid as i32);
            match kill(target, signal) {
                Ok(()) => PrivilegedResponse::Unit,
                Err(nix::errno::Errno::ESRCH) => {
                    let _ = unregister_managed_pid(pid);
                    PrivilegedResponse::Unit
                }
                Err(e) => PrivilegedResponse::Error {
                    code: "Kernel".into(),
                    message: format!("kill {} failed: {}", pid, e),
                },
            }
        }

        PrivilegedRequest::SpawnProxyDaemon {
            netns,
            interface,
            socks_port,
            http_port,
            proxy_access_log,
            pid_file,
            log_file,
            startup_status_file,
        } => match spawn_proxy_daemon(
            netns.as_str(),
            interface.as_str(),
            socks_port,
            http_port,
            proxy_access_log,
            pid_file.as_str(),
            log_file.as_str(),
            startup_status_file.as_str(),
        ) {
            Ok(pid) => match register_managed_pid(pid) {
                Ok(()) => PrivilegedResponse::Pid(pid),
                Err(e) => {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    PrivilegedResponse::Error {
                        code: "IO".into(),
                        message: format!("failed to register managed pid {}: {}", pid, e),
                    }
                }
            },
            Err(e) => PrivilegedResponse::Error {
                code: "Proxy".into(),
                message: e.to_string(),
            },
        },

        PrivilegedRequest::LeaseAcquire { token } => {
            control_state.prune_stale_leases();
            control_state.leases.insert(token);
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_acquired");
            PrivilegedResponse::Unit
        }

        PrivilegedRequest::LeaseRelease { token } => {
            control_state.leases.remove(token.as_str());
            control_state.prune_stale_leases();
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_released");
            PrivilegedResponse::Unit
        }

        PrivilegedRequest::ShutdownIfIdle => {
            if !control_state.allow_shutdown {
                return PrivilegedResponse::Error {
                    code: "Control".into(),
                    message: "shutdown control is disabled for this daemon instance".into(),
                };
            }
            control_state.shutdown_requested = true;
            control_state.prune_stale_leases();
            debug!(
                remaining_leases = ?control_state.leases.len(), "privileged_shutdown_if_idle_requested");
            PrivilegedResponse::Bool(control_state.leases.is_empty())
        }

        PrivilegedRequest::WgShow { interface } => match run_wg_show(interface.as_str()) {
            Ok(output) => PrivilegedResponse::Text(output),
            Err(e) => PrivilegedResponse::Error {
                code: categorize_error(&e),
                message: format!("{}", e),
            },
        },
    }
}

fn execute_unit(result: Result<()>) -> PrivilegedResponse {
    match result {
        Ok(()) => PrivilegedResponse::Unit,
        Err(e) => PrivilegedResponse::Error {
            code: categorize_error(&e),
            message: format!("{}", e),
        },
    }
}

fn execute_route(op: &str, destination: &str, via: Option<&str>, dev: &str) -> PrivilegedResponse {
    let args = build_route_args(op, destination, via, dev);
    let output = match run_output(&args) {
        Ok(output) => output,
        Err(error) => return execute_unit(Err(error)),
    };
    if output.status.success() {
        return PrivilegedResponse::Unit;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if op == "add" && route_add_conflicts_with_existing_route(&stderr) {
        let replace_args = build_route_args("replace", destination, via, dev);
        info!(
            destination,
            via = via.unwrap_or(""),
            dev,
            "host_route_add_exists_retrying_replace"
        );
        return execute_unit(run(&replace_args));
    }

    execute_unit(Err(AppError::Other(format_command_failure(
        &args,
        output.status,
        &stderr,
    ))))
}

fn run(args: &[&str]) -> Result<()> {
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

fn run_output(args: &[&str]) -> Result<std::process::Output> {
    debug!(cmd = args.join(" "), "exec");
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|error| AppError::Other(format!("command {} failed to start: {}", args[0], error)))
}

fn build_route_args<'a>(
    op: &'a str,
    destination: &'a str,
    via: Option<&'a str>,
    dev: &'a str,
) -> Vec<&'a str> {
    let is_ipv6_route = destination.contains(':') || via.is_some_and(|gw| gw.contains(':'));
    let mut args = if is_ipv6_route {
        vec!["ip", "-6", "route", op, destination]
    } else {
        vec!["ip", "route", op, destination]
    };
    if let Some(gw) = via {
        args.push("via");
        args.push(gw);
    }
    args.push("dev");
    args.push(dev);
    args
}

fn route_add_conflicts_with_existing_route(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("file exists")
}

fn format_command_failure(args: &[&str], status: std::process::ExitStatus, stderr: &str) -> String {
    if stderr.is_empty() {
        format!("command {} failed: {}", args[0], status)
    } else {
        format!("command {} failed: {} ({})", args[0], status, stderr)
    }
}

fn run_resolved_set_dns(interface: &str, dns_servers: &[String]) -> Result<()> {
    let mut dns_command = vec!["resolvectl", "dns", interface];
    dns_command.extend(dns_servers.iter().map(String::as_str));
    run(&dns_command)?;
    run(&["resolvectl", "domain", interface, "~."])?;
    run(&["resolvectl", "default-route", interface, "yes"])?;
    Ok(())
}

fn run_resolved_revert_dns(interface: &str) -> Result<()> {
    run(&["resolvectl", "revert", interface])
}

fn run_wg_quick_up(
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

fn run_wg_quick_down(path: &std::path::Path) -> Result<()> {
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

fn run_wg_show(interface: &str) -> Result<String> {
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

fn format_wg_show(raw: &str, interface: &str) -> Result<String> {
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

fn wg_hex_to_32(s: &str) -> std::result::Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

fn wg_format_ago(secs: u64) -> String {
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

fn wg_format_bytes(bytes: u64) -> String {
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

fn run_gotatun_up(interface: &str, config_content: &str) -> Result<()> {
    use base64::Engine;

    let exe = self_executable_for_spawn()?;
    let config_b64 = base64::engine::general_purpose::STANDARD.encode(config_content);

    debug!(
        cmd = format!("{} {} [TUNMUX_GOTATUN_HELPER=1]", exe.display(), interface),
        "exec"
    );
    let status = Command::new(exe)
        .env("TUNMUX_GOTATUN_HELPER", "1")
        .env("TUNMUX_GOTATUN_CONFIG_B64", config_b64)
        .arg(interface)
        .status()
        .map_err(|e| AppError::Other(format!("gotatun up failed to start: {}", e)))?;

    if !status.success() {
        return Err(AppError::WireGuard(format!("gotatun up exited {}", status)));
    }
    Ok(())
}

fn run_gotatun_down(interface: &str) -> Result<()> {
    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).map_err(|e| {
            AppError::Other(format!(
                "failed to remove gotatun control socket {}: {}",
                socket_path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wg_set(
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
fn wg_set(
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
fn set_preshared_key(interface: &str, peer_public_key: &str, psk: &str) -> Result<()> {
    crate::wireguard::netlink::wg_set_psk(interface, peer_public_key, psk)
}

#[cfg(not(target_os = "linux"))]
fn set_preshared_key(_interface: &str, _peer_public_key: &str, _psk: &str) -> Result<()> {
    Err(AppError::WireGuard(
        "kernel wireguard backend is only supported on linux".to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn spawn_proxy_daemon(
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

    // Ensure the proxy directory exists (e.g. /var/lib/tunmux/proxy/).
    if let Some(parent) = std::path::Path::new(pid_file).parent() {
        config::ensure_privileged_directory(parent)?;
    }

    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(log_file);
    let _ = std::fs::remove_file(startup_status_file);

    let socks = socks_port.to_string();
    let http = http_port.to_string();

    let mut command = Command::new(exe);
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

fn self_executable_for_spawn() -> Result<std::path::PathBuf> {
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

fn wait_for_pid_file(pid_file: &str, timeout: Duration) -> Result<u32> {
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

fn wait_for_startup_ready(startup_status_file: &str, timeout: Duration) -> bool {
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

fn terminate_managed_process(pid: u32) {
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

fn tail_file(path: &str, lines: usize) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return "<log unavailable>".to_string();
    };
    let mut rows: Vec<&str> = content.lines().collect();
    if rows.len() > lines {
        rows = rows.split_off(rows.len() - lines);
    }
    rows.join("\n")
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

fn managed_pid_registry_dir() -> std::path::PathBuf {
    if let Some(override_dir) = std::env::var_os("TUNMUX_MANAGED_PIDS_DIR") {
        let path = std::path::PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    config::privileged_socket_dir().join("managed-pids")
}

fn managed_pid_entry_path(pid: u32) -> std::path::PathBuf {
    managed_pid_registry_dir().join(format!("{}.start", pid))
}

fn ensure_managed_pid_registry_dir() -> Result<()> {
    let dir = managed_pid_registry_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn register_managed_pid(pid: u32) -> Result<()> {
    let start_ticks = process_start_ticks(pid)
        .ok_or_else(|| AppError::Other(format!("failed reading /proc/{}/stat", pid)))?;
    ensure_managed_pid_registry_dir()?;
    let path = managed_pid_entry_path(pid);
    std::fs::write(&path, format!("{}\n", start_ticks))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn unregister_managed_pid(pid: u32) -> Result<()> {
    let path = managed_pid_entry_path(pid);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn managed_pid_is_current(pid: u32) -> Result<bool> {
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

fn cleanup_stale_managed_pid_registry_entries() -> Result<()> {
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

fn lease_token_is_live(token: &str) -> bool {
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

fn pid_is_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
fn process_start_ticks(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(path).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(not(target_os = "linux"))]
fn process_start_ticks(_pid: u32) -> Option<u64> {
    None
}

fn categorize_error(error: &AppError) -> String {
    if matches!(error, AppError::WireGuard(_)) {
        "WireGuard".into()
    } else if matches!(error, AppError::Namespace(_)) {
        "Namespace".into()
    } else if matches!(error, AppError::Proxy(_)) {
        "Proxy".into()
    } else {
        "Kernel".into()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
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
        assert!(lease_token_is_live(&token));
        assert!(!lease_token_is_live("999999:1"));
        assert!(!lease_token_is_live("invalid-token"));
    }

    #[test]
    fn managed_pid_registry_round_trip_and_stale_cleanup() {
        with_managed_pid_registry_dir(|| {
            let pid = std::process::id();
            register_managed_pid(pid).expect("register managed pid");
            assert!(managed_pid_is_current(pid).expect("check managed pid"));

            let stale = managed_pid_entry_path(999_999);
            std::fs::write(&stale, "1\n").expect("write stale entry");
            cleanup_stale_managed_pid_registry_entries().expect("cleanup stale entries");
            assert!(!stale.exists());
        });
    }

    #[test]
    fn managed_pid_cleanup_removes_invalid_entry_names() {
        with_managed_pid_registry_dir(|| {
            ensure_managed_pid_registry_dir().expect("ensure managed pid registry dir");
            let invalid = managed_pid_registry_dir().join("bad-entry");
            std::fs::write(&invalid, "junk").expect("write invalid entry");
            cleanup_stale_managed_pid_registry_entries().expect("cleanup invalid entries");
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
        assert!(route_add_conflicts_with_existing_route(
            "RTNETLINK answers: File exists"
        ));
        assert!(route_add_conflicts_with_existing_route(
            "rtnetlink answers: file exists"
        ));
        assert!(!route_add_conflicts_with_existing_route(
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

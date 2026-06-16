use std::process::Command;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::{debug, info};

use crate::config;
use crate::error::{AppError, Result};
use crate::privileged_api::{
    GotaTunAction, KillSignal, PrivilegedRequest, PrivilegedResponse, WgQuickAction,
};

use super::commands::{
    run, run_gotatun_down, run_gotatun_up, run_output, run_resolved_revert_dns,
    run_resolved_set_dns, run_wg_quick_down, run_wg_quick_up, run_wg_show, set_preshared_key,
    wg_set,
};
use super::daemon::spawn_proxy_daemon;
use super::managed_pids::{managed_pid_is_current, register_managed_pid, unregister_managed_pid};
use super::ControlState;

pub(super) fn dispatch(
    request: PrivilegedRequest,
    control_state: &mut ControlState,
) -> PrivilegedResponse {
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
            mtu_override,
            debug,
        } => match action {
            GotaTunAction::Up => {
                match run_gotatun_up(
                    interface.as_str(),
                    config_content.as_str(),
                    mtu_override,
                    debug,
                ) {
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
                use std::os::unix::fs::PermissionsExt;
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
            } else {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
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

pub(super) fn route_add_conflicts_with_existing_route(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("file exists")
}

fn format_command_failure(args: &[&str], status: std::process::ExitStatus, stderr: &str) -> String {
    if stderr.is_empty() {
        format!("command {} failed: {}", args[0], status)
    } else {
        format!("command {} failed: {} ({})", args[0], status, stderr)
    }
}

pub(super) fn categorize_error(error: &AppError) -> String {
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

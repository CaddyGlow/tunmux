#![cfg(all(feature = "proxy", target_os = "linux"))]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use slog_scope::info;

use crate::logging;
use crate::netns;

use super::http;
use super::socks5;

/// Run the proxy daemon. This is the entry point for the re-exec'd child process.
///
/// 1. Bind listeners on host namespace (before setns)
/// 2. Daemonize
/// 3. Enter VPN namespace
/// 4. Run single-threaded tokio runtime accepting connections
pub fn run(
    netns_name: &str,
    socks_port: u16,
    http_port: u16,
    pid_file: &str,
    log_file: &str,
) -> anyhow::Result<()> {
    // 1. Bind listeners in host namespace (before entering netns).
    //    Try both IPv4 and IPv6 loopback; at least one of each pair must succeed.
    let socks4 = TcpListener::bind(format!("127.0.0.1:{}", socks_port)).ok();
    let socks6 = TcpListener::bind(format!("[::1]:{}", socks_port)).ok();
    if socks4.is_none() && socks6.is_none() {
        anyhow::bail!(
            "failed to bind SOCKS5 on port {} (neither IPv4 nor IPv6)",
            socks_port
        );
    }

    // UDP relay sockets for SOCKS5 UDP ASSOCIATE (same port as TCP -- no conflict)
    let udp_socks4 = std::net::UdpSocket::bind(format!("127.0.0.1:{}", socks_port)).ok();
    let udp_socks6 = std::net::UdpSocket::bind(format!("[::1]:{}", socks_port)).ok();

    let http4 = TcpListener::bind(format!("127.0.0.1:{}", http_port)).ok();
    let http6 = TcpListener::bind(format!("[::1]:{}", http_port)).ok();
    if http4.is_none() && http6.is_none() {
        anyhow::bail!(
            "failed to bind HTTP on port {} (neither IPv4 nor IPv6)",
            http_port
        );
    }

    for listener in [&socks4, &socks6, &http4, &http6].into_iter().flatten() {
        listener.set_nonblocking(true)?;
    }
    for socket in [&udp_socks4, &udp_socks6].into_iter().flatten() {
        socket.set_nonblocking(true)?;
    }

    // 2. Daemonize: double-fork + setsid
    daemonize()?;

    // 3. Set up file logging first so any subsequent errors are captured.
    let log_fd = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    fs::set_permissions(log_file, fs::Permissions::from_mode(0o644))?;
    drop(log_fd);
    logging::init_file(log_file, false)?;

    // 4. Write PID file (world-readable so the unprivileged parent can poll it)
    let pid = std::process::id();
    fs::write(pid_file, pid.to_string())?;
    fs::set_permissions(pid_file, fs::Permissions::from_mode(0o644))?;

    let mut bound = Vec::new();
    if socks4.is_some() {
        bound.push(format!("socks5=127.0.0.1:{}", socks_port));
    }
    if socks6.is_some() {
        bound.push(format!("socks5=[::1]:{}", socks_port));
    }
    if udp_socks4.is_some() {
        bound.push(format!("socks5-udp=127.0.0.1:{}", socks_port));
    }
    if udp_socks6.is_some() {
        bound.push(format!("socks5-udp=[::1]:{}", socks_port));
    }
    if http4.is_some() {
        bound.push(format!("http=127.0.0.1:{}", http_port));
    }
    if http6.is_some() {
        bound.push(format!("http=[::1]:{}", http_port));
    }
    info!(
        "proxy_daemon_started";
        "pid" => pid,
        "listeners" => bound.join(", "),
        "netns" => netns_name
    );

    // 5. Enter VPN namespace -- all subsequent socket connections go through the VPN.
    //    setns(CLONE_NEWNET) only switches the network namespace; it does NOT
    //    bind-mount /etc/netns/<ns>/resolv.conf over /etc/resolv.conf (that is a
    //    userspace convention of `ip netns exec`).  We replicate it here so that
    //    getaddrinfo inside the daemon uses the VPN's DNS servers.
    if let Err(e) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS) {
        slog_scope::error!(
            "mount_namespace_unshare_failed";
            "error" => e.to_string()
        );
        anyhow::bail!("unshare(CLONE_NEWNS) failed: {}", e);
    }

    // Stop mount propagation from leaking back to the host.  Without this,
    // systemd's default "shared" propagation causes our bind-mounts to
    // override the host's /etc/resolv.conf.  MS_SLAVE|MS_REC matches what
    // `ip netns exec` does.
    if let Err(e) = nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_SLAVE | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    ) {
        slog_scope::error!(
            "mount_root_make_rslave_failed";
            "error" => e.to_string()
        );
        anyhow::bail!("mount --make-rslave / failed: {}", e);
    }

    if let Err(e) = netns::enter(netns_name) {
        slog_scope::error!(
            "network_namespace_enter_failed";
            "namespace" => netns_name,
            "error" => e.to_string()
        );
        return Err(e.into());
    }

    let ns_resolv = format!("/etc/netns/{}/resolv.conf", netns_name);
    if std::path::Path::new(&ns_resolv).exists() {
        let dns_content = std::fs::read_to_string(&ns_resolv)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", ns_resolv, e))?;

        // On systemd-resolved hosts, /etc/resolv.conf is a symlink to
        // /run/systemd/resolve/stub-resolv.conf.  Bind-mounting over the
        // symlink or its target is fragile.  Instead, mount a private tmpfs
        // over the resolve directory and write our DNS content there.  The
        // existing symlink then naturally reads our content.
        let resolve_dir = std::path::Path::new("/run/systemd/resolve");
        if resolve_dir.exists() {
            if let Err(e) = nix::mount::mount(
                Some("tmpfs"),
                resolve_dir,
                Some("tmpfs"),
                nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
                Some("size=1m,mode=0755"),
            ) {
                slog_scope::error!(
                    "systemd_resolve_tmpfs_mount_failed";
                    "error" => e.to_string()
                );
                anyhow::bail!("tmpfs over /run/systemd/resolve failed: {}", e);
            }
            std::fs::write("/run/systemd/resolve/stub-resolv.conf", &dns_content)
                .map_err(|e| anyhow::anyhow!("failed to write stub-resolv.conf: {}", e))?;
            info!(
                "systemd_resolve_stub_replaced";
                "path" => "/run/systemd/resolve/stub-resolv.conf",
                "source" => ns_resolv.as_str()
            );
        } else {
            // No systemd-resolved; try direct bind-mount over /etc/resolv.conf.
            if let Err(e) = nix::mount::mount(
                Some(ns_resolv.as_str()),
                "/etc/resolv.conf",
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            ) {
                slog_scope::error!(
                    "resolv_conf_bind_mount_failed";
                    "source" => ns_resolv.as_str(),
                    "target" => "/etc/resolv.conf",
                    "error" => e.to_string()
                );
                anyhow::bail!(
                    "bind-mount {} over /etc/resolv.conf failed: {}",
                    ns_resolv,
                    e
                );
            }
            info!(
                "resolv_conf_bind_mounted";
                "source" => ns_resolv.as_str(),
                "target" => "/etc/resolv.conf"
            );
        }
    } else {
        slog_scope::warn!(
            "resolv_conf_missing";
            "namespace" => netns_name,
            "path" => ns_resolv.as_str()
        );
    }

    // On systemd-resolved hosts, glibc's nss-resolve module talks to
    // systemd-resolved over D-Bus, bypassing both the network namespace
    // and /etc/resolv.conf entirely.  Hide the D-Bus socket so nss-resolve
    // fails and glibc falls back to the "dns" NSS module (which reads
    // /etc/resolv.conf, now bind-mounted with the VPN's nameservers).
    let dbus_socket = "/run/dbus/system_bus_socket";
    if std::path::Path::new(dbus_socket).exists() {
        if let Err(e) = nix::mount::mount(
            Some("/dev/null"),
            dbus_socket,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        ) {
            slog_scope::warn!(
                "dbus_socket_mask_failed";
                "path" => dbus_socket,
                "error" => e.to_string()
            );
        } else {
            info!("dbus_socket_masked"; "path" => dbus_socket);
        }
    }

    // 6. Build single-threaded tokio runtime (critical: setns affects only the calling thread)
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            slog_scope::error!("tokio_runtime_build_failed"; "error" => e.to_string());
            return Err(e.into());
        }
    };

    rt.block_on(async {
        // Convert whichever listeners we have to async
        let socks4 = match socks4 {
            Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
            None => None,
        };
        let socks6 = match socks6 {
            Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
            None => None,
        };
        let http4 = match http4 {
            Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
            None => None,
        };
        let http6 = match http6 {
            Some(l) => Some(tokio::net::TcpListener::from_std(l)?),
            None => None,
        };

        // Convert UDP relay sockets to async + Arc
        let udp_relay4: Option<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)> =
            match udp_socks4 {
                Some(s) => {
                    let addr = s.local_addr()?;
                    Some((Arc::new(tokio::net::UdpSocket::from_std(s)?), addr))
                }
                None => None,
            };
        let udp_relay6: Option<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)> =
            match udp_socks6 {
                Some(s) => {
                    let addr = s.local_addr()?;
                    Some((Arc::new(tokio::net::UdpSocket::from_std(s)?), addr))
                }
                None => None,
            };

        // Shared UDP association map across all relay tasks and SOCKS5 handlers
        let associations = Arc::new(socks5::UdpAssociations::new());

        // Spawn UDP inbound relay tasks
        if let Some((ref socket, _)) = udp_relay4 {
            tokio::spawn(socks5::run_udp_relay(socket.clone(), associations.clone()));
        }
        if let Some((ref socket, _)) = udp_relay6 {
            tokio::spawn(socks5::run_udp_relay(socket.clone(), associations.clone()));
        }

        info!("proxy_accept_loop_started");

        loop {
            tokio::select! {
                result = accept_opt(&socks4) => {
                    let assoc = associations.clone();
                    let relay = udp_relay4.clone();
                    handle_accept(result, "SOCKS5", move |stream| {
                        socks5::handle_socks5(stream, assoc, relay)
                    });
                }
                result = accept_opt(&socks6) => {
                    let assoc = associations.clone();
                    let relay = udp_relay6.clone();
                    handle_accept(result, "SOCKS5", move |stream| {
                        socks5::handle_socks5(stream, assoc, relay)
                    });
                }
                result = accept_opt(&http4) => {
                    handle_accept(result, "HTTP", http::handle_http);
                }
                result = accept_opt(&http6) => {
                    handle_accept(result, "HTTP", http::handle_http);
                }
            }
        }
    })
}

/// Accept from an optional listener. If the listener is None, pend forever.
async fn accept_opt(
    listener: &Option<tokio::net::TcpListener>,
) -> Option<std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>> {
    match listener {
        Some(l) => Some(l.accept().await),
        None => {
            // Pend forever so this branch never fires in select!
            std::future::pending().await
        }
    }
}

fn handle_accept<F, Fut>(
    result: Option<std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>>,
    label: &'static str,
    handler: F,
) where
    F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let Some(result) = result else { return };
    match result {
        Ok((stream, addr)) => {
            slog_scope::debug!(
                "proxy_connection_accepted";
                "listener" => label,
                "peer_addr" => addr.to_string()
            );
            tokio::spawn(async move {
                if let Err(e) = handler(stream).await {
                    slog_scope::debug!(
                        "proxy_connection_handler_error";
                        "listener" => label,
                        "error" => e.to_string()
                    );
                }
            });
        }
        Err(e) => {
            slog_scope::warn!(
                "proxy_listener_accept_error";
                "listener" => label,
                "error" => e.to_string()
            );
        }
    }
}

/// Double-fork daemonization with setsid.
fn daemonize() -> anyhow::Result<()> {
    use nix::unistd::{fork, setsid, ForkResult};

    // First fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent exits immediately
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("first fork failed: {}", e),
    }

    // New session
    setsid().map_err(|e| anyhow::anyhow!("setsid failed: {}", e))?;

    // Second fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("second fork failed: {}", e),
    }

    // Redirect stdin/stdout/stderr to /dev/null
    use std::os::unix::io::AsRawFd;
    let devnull = std::fs::File::open("/dev/null")?;
    let fd = devnull.as_raw_fd();
    nix::unistd::dup2(fd, 0)?; // stdin
    nix::unistd::dup2(fd, 1)?; // stdout
    nix::unistd::dup2(fd, 2)?; // stderr

    Ok(())
}

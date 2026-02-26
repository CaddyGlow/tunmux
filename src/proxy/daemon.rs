#![cfg(all(feature = "proxy", target_os = "linux"))]

use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use super::dns::{build_dns_resolver_from_resolv_conf, DnsResolver};
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
#[allow(clippy::too_many_arguments)]
pub fn run(
    netns_name: &str,
    interface_name: &str,
    socks_port: u16,
    http_port: u16,
    proxy_access_log: bool,
    pid_file: &str,
    log_file: &str,
    startup_status_file: &str,
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
    fs::write(startup_status_file, "starting\n")?;
    fs::set_permissions(startup_status_file, fs::Permissions::from_mode(0o644))?;

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
        pid = ?pid,
        listeners = ?bound.join(", "),
        netns = ?netns_name,
        access_log = ?proxy_access_log, "proxy_daemon_started");

    // 5. Enter VPN namespace -- all subsequent socket connections go through the VPN.
    //    setns(CLONE_NEWNET) only switches the network namespace; it does NOT
    //    bind-mount /etc/netns/<ns>/resolv.conf over /etc/resolv.conf (that is a
    //    userspace convention of `ip netns exec`).  We replicate it here so that
    //    getaddrinfo inside the daemon uses the VPN's DNS servers.
    if let Err(e) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS) {
        tracing::error!(
            error = ?e.to_string(), "mount_namespace_unshare_failed");
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
        tracing::error!(
            error = ?e.to_string(), "mount_root_make_rslave_failed");
        anyhow::bail!("mount --make-rslave / failed: {}", e);
    }

    if let Err(e) = netns::enter(netns_name) {
        tracing::error!(
            namespace = ?netns_name,
            error = ?e.to_string(), "network_namespace_enter_failed");
        return Err(e.into());
    }

    let mut dns_resolver: Option<DnsResolver> = None;
    let mut dns_probe_servers: Vec<IpAddr> = Vec::new();
    let ns_resolv = format!("/etc/netns/{}/resolv.conf", netns_name);
    if std::path::Path::new(&ns_resolv).exists() {
        let dns_content = std::fs::read_to_string(&ns_resolv)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", ns_resolv, e))?;
        dns_resolver = build_dns_resolver_from_resolv_conf(&dns_content);
        dns_probe_servers = extract_dns_servers(&dns_content);

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
                tracing::error!(
                    error = ?e.to_string(), "systemd_resolve_tmpfs_mount_failed");
                anyhow::bail!("tmpfs over /run/systemd/resolve failed: {}", e);
            }
            std::fs::write("/run/systemd/resolve/stub-resolv.conf", &dns_content)
                .map_err(|e| anyhow::anyhow!("failed to write stub-resolv.conf: {}", e))?;
            info!(
                path = ?"/run/systemd/resolve/stub-resolv.conf",
                source = ?ns_resolv.as_str(), "systemd_resolve_stub_replaced");
        } else {
            // No systemd-resolved; try direct bind-mount over /etc/resolv.conf.
            if let Err(e) = nix::mount::mount(
                Some(ns_resolv.as_str()),
                "/etc/resolv.conf",
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            ) {
                tracing::error!(
                    source = ?ns_resolv.as_str(),
                    target = ?"/etc/resolv.conf",
                    error = ?e.to_string(), "resolv_conf_bind_mount_failed");
                anyhow::bail!(
                    "bind-mount {} over /etc/resolv.conf failed: {}",
                    ns_resolv,
                    e
                );
            }
            info!(
                source = ?ns_resolv.as_str(),
                target = ?"/etc/resolv.conf", "resolv_conf_bind_mounted");
        }
    } else {
        tracing::warn!(
            namespace = ?netns_name,
            path = ?ns_resolv.as_str(), "resolv_conf_missing");
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
            tracing::warn!(
                path = ?dbus_socket,
                error = ?e.to_string(), "dbus_socket_mask_failed");
        } else {
            info!( path = ?dbus_socket, "dbus_socket_masked");
        }
    }

    if let Err(err) =
        wait_for_namespace_handshake(interface_name, &dns_probe_servers, Duration::from_secs(12))
    {
        let _ = fs::write(startup_status_file, "failed\n");
        return Err(err);
    }
    fs::write(startup_status_file, "ready\n")?;
    info!(interface = interface_name, "proxy_handshake_established");

    // 6. Build single-threaded tokio runtime (critical: setns affects only the calling thread)
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!( error = ?e.to_string(), "tokio_runtime_build_failed");
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

        let socks_dns_resolver = dns_resolver.clone();
        let http_dns_resolver = dns_resolver.clone();

        loop {
            tokio::select! {
                result = accept_opt(&socks4) => {
                    let assoc = associations.clone();
                    let relay = udp_relay4.clone();
                    let dns_resolver = socks_dns_resolver.clone();
                    handle_accept(result, "SOCKS5", move |stream| {
                        socks5::handle_socks5(stream, assoc, relay, dns_resolver, proxy_access_log)
                    });
                }
                result = accept_opt(&socks6) => {
                    let assoc = associations.clone();
                    let relay = udp_relay6.clone();
                    let dns_resolver = socks_dns_resolver.clone();
                    handle_accept(result, "SOCKS5", move |stream| {
                        socks5::handle_socks5(stream, assoc, relay, dns_resolver, proxy_access_log)
                    });
                }
                result = accept_opt(&http4) => {
                    let dns_resolver = http_dns_resolver.clone();
                    handle_accept(result, "HTTP", move |stream| {
                        http::handle_http(stream, dns_resolver, proxy_access_log)
                    });
                }
                result = accept_opt(&http6) => {
                    let dns_resolver = http_dns_resolver.clone();
                    handle_accept(result, "HTTP", move |stream| {
                        http::handle_http(stream, dns_resolver, proxy_access_log)
                    });
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
            tracing::debug!(
                listener = ?label,
                peer_addr = ?addr.to_string(), "proxy_connection_accepted");
            tokio::spawn(async move {
                if let Err(e) = handler(stream).await {
                    tracing::debug!(
                        listener = ?label,
                        error = ?e.to_string(), "proxy_connection_handler_error");
                }
            });
        }
        Err(e) => {
            tracing::warn!(
                listener = ?label,
                error = ?e.to_string(), "proxy_listener_accept_error");
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

fn extract_dns_servers(content: &str) -> Vec<IpAddr> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            parts.next()?.trim().parse::<IpAddr>().ok()
        })
        .collect()
}

fn wait_for_namespace_handshake(
    interface_name: &str,
    dns_servers: &[IpAddr],
    timeout: Duration,
) -> anyhow::Result<()> {
    let start = Instant::now();
    while Instant::now().duration_since(start) < timeout {
        if namespace_has_handshake(interface_name)? {
            return Ok(());
        }
        nudge_namespace_traffic(dns_servers);
        std::thread::sleep(Duration::from_millis(250));
    }

    anyhow::bail!(
        "timeout waiting for WireGuard handshake on {} within {}s",
        interface_name,
        timeout.as_secs()
    )
}

fn namespace_has_handshake(interface_name: &str) -> anyhow::Result<bool> {
    let output = std::process::Command::new("wg")
        .args(["show", interface_name, "latest-handshakes"])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run wg show latest-handshakes: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!("wg show latest-handshakes failed: {}", stderr);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().any(|line| {
        let mut cols = line.split_whitespace();
        let _peer = cols.next();
        cols.next()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|epoch| epoch > 0)
    }))
}

fn nudge_namespace_traffic(dns_servers: &[IpAddr]) {
    let mut nudged = false;
    for ip in dns_servers {
        if send_udp_probe(*ip).is_ok() {
            nudged = true;
        }
    }
    if nudged {
        return;
    }
    let _ = send_udp_probe(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
    let _ = send_udp_probe(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
}

fn send_udp_probe(ip: IpAddr) -> std::io::Result<()> {
    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(bind_addr)?;
    let target = SocketAddr::new(ip, 53);
    let _ = sock.send_to(&[0], target);
    debug!(target = %target, "proxy_handshake_nudge_sent");
    Ok(())
}

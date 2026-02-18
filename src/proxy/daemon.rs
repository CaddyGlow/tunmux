use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;

use tracing::info;

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
        anyhow::bail!("failed to bind SOCKS5 on port {} (neither IPv4 nor IPv6)", socks_port);
    }

    let http4 = TcpListener::bind(format!("127.0.0.1:{}", http_port)).ok();
    let http6 = TcpListener::bind(format!("[::1]:{}", http_port)).ok();
    if http4.is_none() && http6.is_none() {
        anyhow::bail!("failed to bind HTTP on port {} (neither IPv4 nor IPv6)", http_port);
    }

    for listener in [&socks4, &socks6, &http4, &http6].into_iter().flatten() {
        listener.set_nonblocking(true)?;
    }

    // 2. Daemonize: double-fork + setsid
    daemonize()?;

    // 3. Write PID file (world-readable so the unprivileged parent can poll it)
    let pid = std::process::id();
    fs::write(pid_file, pid.to_string())?;
    fs::set_permissions(pid_file, fs::Permissions::from_mode(0o644))?;

    // 4. Set up file logging (world-readable so unprivileged user can read diagnostics)
    let log_fd = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    fs::set_permissions(log_file, fs::Permissions::from_mode(0o644))?;
    let file_appender = tracing_subscriber::fmt::writer::BoxMakeWriter::new(log_fd);
    tracing_subscriber::fmt()
        .with_writer(file_appender)
        .with_target(false)
        .with_ansi(false)
        .init();

    let mut bound = Vec::new();
    if socks4.is_some() { bound.push(format!("socks5=127.0.0.1:{}", socks_port)); }
    if socks6.is_some() { bound.push(format!("socks5=[::1]:{}", socks_port)); }
    if http4.is_some() { bound.push(format!("http=127.0.0.1:{}", http_port)); }
    if http6.is_some() { bound.push(format!("http=[::1]:{}", http_port)); }
    info!(
        "Proxy daemon started (pid={}, {}, netns={})",
        pid, bound.join(", "), netns_name
    );

    // 5. Enter VPN namespace -- all subsequent socket connections go through the VPN
    if let Err(e) = netns::enter(netns_name) {
        tracing::error!("Failed to enter namespace: {}", e);
        return Err(e.into());
    }

    // 6. Build single-threaded tokio runtime (critical: setns affects only the calling thread)
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to build tokio runtime: {}", e);
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

        info!("Accepting connections...");

        loop {
            tokio::select! {
                result = accept_opt(&socks4) => {
                    handle_accept(result, "SOCKS5", socks5::handle_socks5);
                }
                result = accept_opt(&socks6) => {
                    handle_accept(result, "SOCKS5", socks5::handle_socks5);
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
            tracing::debug!("{} connection from {}", label, addr);
            tokio::spawn(async move {
                if let Err(e) = handler(stream).await {
                    tracing::debug!("{} handler error: {}", label, e);
                }
            });
        }
        Err(e) => {
            tracing::warn!("{} accept error: {}", label, e);
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

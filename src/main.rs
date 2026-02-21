mod airvpn;
mod cli;
mod config;
mod error;
mod ivpn;
mod local_proxy;
mod logging;
mod mullvad;
#[cfg(target_os = "linux")]
mod netns;
#[cfg(not(target_os = "linux"))]
#[path = "netns_stub.rs"]
mod netns;
mod privileged;
mod privileged_api;
mod privileged_client;
mod proton;
#[cfg(all(feature = "proxy", target_os = "linux"))]
#[path = "proxy/mod.rs"]
mod proxy;
#[cfg(not(all(feature = "proxy", target_os = "linux")))]
#[path = "proxy_stub.rs"]
mod proxy;
mod shared;
mod userspace_helper;
mod wireguard;

use base64::Engine as _;

use clap::Parser;
use tracing::error;

use cli::{Cli, TopCommand};
use wireguard::connection::ConnectionState;

fn main() {
    if userspace_helper::maybe_run_from_env() {
        return;
    }

    let cli = Cli::parse();

    match cli.command {
        // Privileged control server.
        TopCommand::Privileged {
            serve,
            stdio,
            authorized_group,
            idle_timeout_ms,
            autostarted,
        } => {
            init_logging(cli.verbose);
            if !serve {
                eprintln!("privileged mode requires --serve");
                std::process::exit(1);
            }
            let run = if stdio {
                privileged::serve_stdio(idle_timeout_ms, autostarted)
            } else {
                privileged::serve(authorized_group, idle_timeout_ms, autostarted)
            };
            if let Err(e) = run {
                eprintln!("privileged service error: {}", e);
                std::process::exit(1);
            }
        }
        // ProxyDaemon runs its own single-threaded runtime and daemonizes.
        // Do not initialize terminal logging here -- the daemon sets up file logging itself.
        TopCommand::ProxyDaemon {
            netns,
            socks_port,
            http_port,
            proxy_access_log,
            pid_file,
            log_file,
        } => {
            if let Err(e) = proxy::daemon::run(
                &netns,
                socks_port,
                http_port,
                proxy_access_log,
                &pid_file,
                &log_file,
            ) {
                eprintln!("proxy-daemon error: {}", e);
                std::process::exit(1);
            }
        }

        // LocalProxyDaemon: userspace WireGuard, no root/netns required.
        TopCommand::LocalProxyDaemon {
            socks_port: _,
            http_port: _,
            proxy_access_log: _,
            pid_file,
            log_file,
            config_b64,
        } => {
            if let Err(e) = run_local_proxy_daemon(&pid_file, &log_file, &config_b64) {
                eprintln!("local-proxy-daemon error: {}", e);
                std::process::exit(1);
            }
        }

        // Status and Wg are quick sync commands, no tokio needed.
        TopCommand::Status => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_status() {
                error!( command = ?"status", error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Wg => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_wg() {
                error!( command = ?"wg", error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }

        // All other commands use the multi-threaded tokio runtime.
        other => {
            init_logging(cli.verbose);
            let config = config::load_config();
            let _command_scope = privileged_client::CommandScopeGuard::begin(
                config.general.privileged_autostop_mode,
            );

            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = rt.block_on(run(other, config)) {
                error!( error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }
    }
}

fn init_logging(verbose: bool) {
    logging::init_terminal(verbose);
}

async fn run(command: TopCommand, config: config::AppConfig) -> anyhow::Result<()> {
    match command {
        TopCommand::Proton { command } => proton::handlers::dispatch(command, &config).await,
        TopCommand::Airvpn { command } => airvpn::handlers::dispatch(command, &config).await,
        TopCommand::Mullvad { command } => mullvad::handlers::dispatch(command, &config).await,
        TopCommand::Ivpn { command } => ivpn::handlers::dispatch(command, &config).await,
        TopCommand::Status
        | TopCommand::Wg
        | TopCommand::ProxyDaemon { .. }
        | TopCommand::LocalProxyDaemon { .. }
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
}

fn run_local_proxy_daemon(pid_file: &str, log_file: &str, config_b64: &str) -> anyhow::Result<()> {
    // Decode config before daemonizing so errors surface to the shell.
    let json = base64::engine::general_purpose::STANDARD.decode(config_b64)?;
    let cfg: wireguard::proxy_tunnel::LocalProxyConfig = serde_json::from_slice(&json)?;

    // Ensure the user proxy dir exists before daemonizing.
    config::ensure_user_proxy_dir()?;

    let foreground = std::env::var_os("TUNMUX_LOCAL_PROXY_FOREGROUND").is_some();
    if !foreground {
        // Daemonize (double-fork).
        daemonize_local()?;
    }

    if foreground {
        logging::init_terminal(true);
    } else {
        // Init file logging -- all subsequent output goes to the log file.
        logging::init_file(log_file, false)?;
    }

    // Ensure panics are captured in logs instead of disappearing after daemonize.
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.as_str()
        } else {
            "non-string panic payload"
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(
            panic = %payload,
            location = %location,
            backtrace = %backtrace,
            "local_proxy_daemon_panic"
        );
    }));

    // Write PID file.
    let pid = std::process::id();
    std::fs::write(pid_file, pid.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(pid_file, std::fs::Permissions::from_mode(0o644))?;
    }

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 8);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    rt.block_on(wireguard::proxy_tunnel::run_local_proxy(cfg))
}

/// Double-fork daemonize for the local-proxy daemon.
fn daemonize_local() -> anyhow::Result<()> {
    use nix::unistd::{fork, setsid, ForkResult};

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("first fork failed: {}", e),
    }

    setsid().map_err(|e| anyhow::anyhow!("setsid failed: {}", e))?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("second fork failed: {}", e),
    }

    use std::os::unix::io::AsRawFd;
    let devnull = std::fs::File::open("/dev/null")?;
    let fd = devnull.as_raw_fd();
    nix::unistd::dup2(fd, 0)?;
    nix::unistd::dup2(fd, 1)?;
    nix::unistd::dup2(fd, 2)?;

    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let connections = ConnectionState::load_all()?;

    if connections.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    println!(
        "{:<12} {:<9} {:<10} {:<5} {:<9} {:<16} HTTP",
        "Instance", "Provider", "Server", "Exit", "Backend", "SOCKS5"
    );
    println!("{}", "-".repeat(76));

    for conn in &connections {
        let exit = conn
            .server_display_name
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect::<String>();

        let socks = conn
            .socks_port
            .map(|p| format!("127.0.0.1:{}", p))
            .unwrap_or_else(|| "-".to_string());
        let http = conn
            .http_port
            .map(|p| format!("127.0.0.1:{}", p))
            .unwrap_or_else(|| "-".to_string());

        println!(
            "{:<12} {:<9} {:<10} {:<5} {:<9} {:<16} {}",
            conn.instance_name,
            conn.provider,
            conn.server_display_name,
            exit,
            conn.backend,
            socks,
            http,
        );
    }

    Ok(())
}

fn cmd_wg() -> anyhow::Result<()> {
    use wireguard::backend::WgBackend;
    use wireguard::connection::ConnectionState;

    let connections = ConnectionState::load_all()?;
    if connections.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    let mut first = true;
    for conn in &connections {
        if !first {
            println!();
        }
        first = false;

        match conn.backend {
            WgBackend::LocalProxy => print_local_proxy_info(conn),
            _ => match privileged_client::PrivilegedClient::new().wg_show(&conn.interface_name) {
                Ok(output) => print!("{}", output),
                Err(e) => eprintln!("wg show {} failed: {}", conn.interface_name, e),
            },
        }
    }
    Ok(())
}

fn print_local_proxy_info(conn: &wireguard::connection::ConnectionState) {
    let running = conn
        .proxy_pid
        .map(|pid| std::path::Path::new(&format!("/proc/{}", pid)).exists())
        .unwrap_or(false);

    // ── interface block ──────────────────────────────────────────────────────
    println!("interface: {}", conn.instance_name);
    if let Some(ref k) = conn.local_public_key {
        println!("  public key: {}", k);
    }
    println!("  private key: (hidden)");
    println!("  listening port: n/a (userspace)");
    if !conn.virtual_ips.is_empty() {
        println!("  address: {}", conn.virtual_ips.join(", "));
    }
    let socks = conn
        .socks_port
        .map(|p| format!("127.0.0.1:{}", p))
        .unwrap_or_else(|| "-".to_string());
    let http = conn
        .http_port
        .map(|p| format!("127.0.0.1:{}", p))
        .unwrap_or_else(|| "-".to_string());
    println!("  socks5 proxy: {}", socks);
    println!("  http proxy: {}", http);
    match conn.proxy_pid {
        Some(pid) => println!(
            "  pid: {} ({})",
            pid,
            if running { "running" } else { "dead" }
        ),
        None => println!("  pid: unknown"),
    }

    // ── peer block ───────────────────────────────────────────────────────────
    println!();
    match conn.peer_public_key.as_deref() {
        Some(k) => println!("peer: {}", k),
        None => println!("peer: (unknown)"),
    }
    println!("  endpoint: {}", conn.server_endpoint);
    println!("  allowed ips: 0.0.0.0/0, ::/0");
    println!("  latest handshake: (userspace — not available)");
    println!("  transfer: (userspace — not available)");
    if let Some(ka) = conn.keepalive_secs {
        println!("  persistent keepalive: every {} seconds", ka);
    }
}

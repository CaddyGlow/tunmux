mod airvpn;
mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod ivpn;
mod logging;
mod models;
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
mod userspace_helper;
mod wireguard;

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
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
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
    use wireguard::connection::{ConnectionState, DIRECT_INSTANCE};

    let state = ConnectionState::load(DIRECT_INSTANCE)?
        .ok_or_else(|| anyhow::anyhow!("not connected (no active direct connection)"))?;
    let output = privileged_client::PrivilegedClient::new().wg_show(&state.interface_name)?;
    print!("{}", output);
    Ok(())
}

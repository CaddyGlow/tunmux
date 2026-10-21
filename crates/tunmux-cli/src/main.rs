use tunmux_cli::cli;
use tunmux_core::{
    config, logging, privileged, privileged_client, proxy, shared, userspace_helper, wireguard,
};

use clap::Parser;
use tracing::error;

#[cfg(any(
    feature = "proton",
    feature = "airvpn",
    feature = "mullvad",
    feature = "ivpn",
    feature = "wgconf"
))]
use cli::ConnectProviderCommand;
use cli::{Cli, HookBuiltinArg, HookCommand, HookEventArg, TopCommand};
use wireguard::connection::ConnectionState;

fn main() -> std::process::ExitCode {
    // SAFETY: no logging, runtime, or worker threads have been initialized.
    if unsafe { userspace_helper::maybe_run_from_env() } {
        return std::process::ExitCode::SUCCESS;
    }

    shared::progress::set_reporter(|line| println!("{line}"));
    let cli = Cli::parse();
    let operation_args: Vec<String> = std::env::args().skip(1).collect();
    let _operation = match cli::autoconnect::prepare(&operation_args) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("{error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = logging::configure(cli.verbose, cli.log_filter.as_deref()) {
        eprintln!("logging initialization failed: {error:#}");
        return std::process::ExitCode::FAILURE;
    }

    match cli.command {
        // Privileged control server.
        TopCommand::Privileged {
            serve,
            stdio,
            detach,
            authorized_group,
            idle_timeout_ms,
            autostarted,
        } => {
            if !serve {
                eprintln!("privileged mode requires --serve");
                return std::process::ExitCode::FAILURE;
            }
            // Detach before logging starts its worker thread; fork keeps only
            // the calling thread.
            if detach {
                if let Err(e) = shared::daemonize::daemonize(
                    shared::daemonize::OutputPolicy::KeepTerminalAndFiles,
                ) {
                    eprintln!("privileged service detach failed: {}", e);
                    return std::process::ExitCode::FAILURE;
                }
            }
            let _logging_guard = init_logging(cli.verbose);
            let run = if stdio {
                privileged::serve_stdio(idle_timeout_ms, autostarted)
            } else {
                privileged::serve(authorized_group, idle_timeout_ms, autostarted)
            };
            if let Err(e) = run {
                eprintln!("privileged service error: {}", e);
                return std::process::ExitCode::FAILURE;
            }
        }
        // ProxyDaemon runs its own single-threaded runtime and daemonizes.
        // Do not initialize terminal logging here -- the daemon sets up file logging itself.
        TopCommand::ProxyDaemon {
            netns,
            interface,
            socks_port,
            http_port,
            proxy_access_log,
            pid_file,
            log_file,
            startup_status_file,
        } => {
            if let Err(e) = proxy::daemon::run(
                &netns,
                &interface,
                socks_port,
                http_port,
                proxy_access_log,
                &pid_file,
                &log_file,
                &startup_status_file,
            ) {
                eprintln!("proxy-daemon error: {}", e);
                return std::process::ExitCode::FAILURE;
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
            if let Err(e) = tunmux_core::local_proxy::run_daemon(&pid_file, &log_file, &config_b64)
            {
                eprintln!("local-proxy-daemon error: {}", e);
                return std::process::ExitCode::FAILURE;
            }
        }

        // Status and Wg are quick sync commands, no tokio needed.
        TopCommand::Status => {
            let _logging_guard = init_logging(cli.verbose);
            if let Err(e) = cmd_status() {
                error!( command = ?"status", error = ?format!("{e:#}"), "command_failed");
                return std::process::ExitCode::FAILURE;
            }
        }

        TopCommand::Wg => {
            let _logging_guard = init_logging(cli.verbose);
            if let Err(e) = cmd_wg() {
                error!( command = ?"wg", error = ?format!("{e:#}"), "command_failed");
                return std::process::ExitCode::FAILURE;
            }
        }

        // All other commands use the multi-threaded tokio runtime.
        other => {
            let _logging_guard = init_logging(cli.verbose);
            let config = config::load_config();
            let _command_scope = privileged_client::CommandScopeGuard::begin(
                config.general.privileged_autostop_mode,
            );

            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = rt.block_on(run(other, config)) {
                error!( error = ?format!("{e:#}"), "command_failed");
                return cli::autoconnect::failure_exit_code(&e);
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

fn init_logging(verbose: bool) -> logging::LoggingGuard {
    logging::init_terminal(verbose).unwrap_or_else(|error| {
        eprintln!("logging initialization failed: {error:#}");
        std::process::exit(1);
    })
}

async fn run(command: TopCommand, config: config::AppConfig) -> anyhow::Result<()> {
    match command {
        TopCommand::Service { command } => tunmux_core::service::run_action(command.into()),
        TopCommand::Autoconnect { command } => cli::autoconnect::dispatch(command),
        #[cfg(feature = "proton")]
        TopCommand::Proton { command } => cli::commands::proton::dispatch(command, &config).await,
        #[cfg(feature = "airvpn")]
        TopCommand::Airvpn { command } => cli::commands::airvpn::dispatch(command, &config).await,
        #[cfg(feature = "mullvad")]
        TopCommand::Mullvad { command } => cli::commands::mullvad::dispatch(command, &config).await,
        #[cfg(feature = "ivpn")]
        TopCommand::Ivpn { command } => cli::commands::ivpn::dispatch(command, &config).await,
        #[cfg(feature = "wgconf")]
        TopCommand::Wgconf { command } => cli::commands::wgconf::dispatch(command, &config).await,
        #[cfg(any(
            feature = "proton",
            feature = "airvpn",
            feature = "mullvad",
            feature = "ivpn",
            feature = "wgconf"
        ))]
        TopCommand::Connect { provider } => run_connect(provider, &config).await,
        TopCommand::Disconnect {
            instance,
            provider,
            all,
        } => run_disconnect(instance, provider.map(Into::into), all, &config).await,
        TopCommand::Hook { command } => run_hook_command(command),
        TopCommand::Status
        | TopCommand::Wg
        | TopCommand::ProxyDaemon { .. }
        | TopCommand::LocalProxyDaemon { .. }
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
}

fn run_hook_command(command: HookCommand) -> anyhow::Result<()> {
    match command {
        HookCommand::Run { builtin } => cmd_hook_run(builtin),
        HookCommand::Debug {
            instance,
            provider,
            event,
        } => cmd_hook_debug(instance, provider.map(Into::into), event),
    }
}

fn cmd_hook_run(builtin: HookBuiltinArg) -> anyhow::Result<()> {
    let entry = match builtin {
        HookBuiltinArg::Connectivity => "builtin:connectivity",
        HookBuiltinArg::ExternalIp => "builtin:external-ip",
        HookBuiltinArg::DnsDetection => "builtin:dns-detection",
    };

    let connections = ConnectionState::load_all()?;
    if connections.len() == 1 {
        return shared::hooks::run_builtin_for_state(entry, &connections[0]);
    }

    if connections.len() > 1 {
        tracing::warn!(
            active_connections = connections.len(),
            "hook_run_multiple_connections_no_proxy_context"
        );
    }

    shared::hooks::run_builtin(entry)
}

fn cmd_hook_debug(
    instance: Option<String>,
    provider: Option<config::Provider>,
    event: HookEventArg,
) -> anyhow::Result<()> {
    let state = resolve_connection_for_hook_debug(instance, provider)?;
    let provider_cfg = config::Provider::from_dir_name(&state.provider).ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported provider in connection state: {}",
            state.provider
        )
    })?;

    let env = match event {
        HookEventArg::Ifup => shared::hooks::debug_ifup_env(provider_cfg, &state),
        HookEventArg::Ifdown => shared::hooks::debug_ifdown_env(provider_cfg, &state),
    };

    println!(
        "Hook env payload [{}] for {} ({})",
        hook_event_label(event),
        state.instance_name,
        state.provider
    );
    for (key, value) in env {
        println!("{}={}", key, value);
    }

    Ok(())
}

fn resolve_connection_for_hook_debug(
    instance: Option<String>,
    provider: Option<config::Provider>,
) -> anyhow::Result<ConnectionState> {
    if let Some(instance_name) = instance {
        let conn = ConnectionState::load(&instance_name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", instance_name))?;

        if let Some(requested) = provider {
            if conn.provider != requested.label() {
                anyhow::bail!(
                    "instance {:?} belongs to provider {:?}, not {:?}",
                    instance_name,
                    conn.provider,
                    requested.label()
                );
            }
        }

        return Ok(conn);
    }

    let mut connections = ConnectionState::load_all()?;
    if let Some(requested) = provider {
        let requested_label = requested.label();
        connections.retain(|conn| conn.provider == requested_label);
    }

    match connections.len() {
        0 => anyhow::bail!("no active connections{}", provider_hint(provider)),
        1 => Ok(connections.remove(0)),
        _ => {
            println!("Multiple active connections. Specify instance for hook debug:\n");
            for conn in &connections {
                println!(
                    "  {:<12} {:<9} {}",
                    conn.instance_name, conn.provider, conn.server_display_name
                );
            }
            println!("\nUsage: tunmux hook debug <instance>");
            println!("       tunmux hook debug --provider <provider>");
            anyhow::bail!("hook debug requires an unambiguous active connection")
        }
    }
}

fn hook_event_label(event: HookEventArg) -> &'static str {
    match event {
        HookEventArg::Ifup => "ifup",
        HookEventArg::Ifdown => "ifdown",
    }
}

fn provider_hint(provider: Option<config::Provider>) -> &'static str {
    if provider.is_some() {
        " for selected provider"
    } else {
        ""
    }
}

#[cfg(any(
    feature = "proton",
    feature = "airvpn",
    feature = "mullvad",
    feature = "ivpn",
    feature = "wgconf"
))]
async fn run_connect(
    provider: ConnectProviderCommand,
    config: &config::AppConfig,
) -> anyhow::Result<()> {
    match provider {
        #[cfg(feature = "proton")]
        ConnectProviderCommand::Proton(args) => {
            cli::commands::proton::dispatch(cli::ProtonCommand::Connect(args), config).await
        }
        #[cfg(feature = "airvpn")]
        ConnectProviderCommand::Airvpn(args) => {
            cli::commands::airvpn::dispatch(cli::AirVpnCommand::Connect(args), config).await
        }
        #[cfg(feature = "mullvad")]
        ConnectProviderCommand::Mullvad(args) => {
            cli::commands::mullvad::dispatch(cli::MullvadCommand::Connect(args), config).await
        }
        #[cfg(feature = "ivpn")]
        ConnectProviderCommand::Ivpn(args) => {
            cli::commands::ivpn::dispatch(cli::IvpnCommand::Connect(args), config).await
        }
        #[cfg(feature = "wgconf")]
        ConnectProviderCommand::Wgconf(args) => {
            cli::commands::wgconf::dispatch(cli::WgconfCommand::Connect(args), config).await
        }
    }
}

async fn run_disconnect(
    instance: Option<String>,
    provider: Option<config::Provider>,
    all: bool,
    config: &config::AppConfig,
) -> anyhow::Result<()> {
    if all {
        if let Some(provider) = provider {
            return dispatch_provider_disconnect(provider, None, true, config).await;
        }

        let connections = ConnectionState::load_all()?;
        if connections.is_empty() {
            println!("Not connected.");
            return Ok(());
        }

        for conn in connections {
            let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported provider in connection state: {}",
                    conn.provider
                )
            })?;
            dispatch_provider_disconnect(resolved, Some(conn.instance_name), false, config).await?;
        }

        return Ok(());
    }

    if let Some(instance_name) = instance {
        let conn = ConnectionState::load(&instance_name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", instance_name))?;
        let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported provider in connection state: {}",
                conn.provider
            )
        })?;

        if let Some(requested) = provider {
            if requested != resolved {
                anyhow::bail!(
                    "instance {:?} belongs to provider {:?}, not {:?}",
                    instance_name,
                    resolved.label(),
                    requested.label()
                );
            }
        }

        return dispatch_provider_disconnect(resolved, Some(instance_name), false, config).await;
    }

    if let Some(provider) = provider {
        return dispatch_provider_disconnect(provider, None, false, config).await;
    }

    let connections = ConnectionState::load_all()?;
    match connections.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &connections[0];
            let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported provider in connection state: {}",
                    conn.provider
                )
            })?;
            dispatch_provider_disconnect(resolved, Some(conn.instance_name.clone()), false, config)
                .await?;
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &connections {
                let ports = match (conn.socks_port, conn.http_port) {
                    (Some(s), Some(h)) => format!("SOCKS5 :{}, HTTP :{}", s, h),
                    _ => "-".to_string(),
                };
                println!(
                    "  {:<12} {:<9} {:<24} {}",
                    conn.instance_name, conn.provider, conn.server_display_name, ports
                );
            }
            println!("\nUsage: tunmux disconnect <instance>");
            println!("       tunmux disconnect --provider <provider> --all");
            println!("       tunmux disconnect --all");
        }
    }

    Ok(())
}

async fn dispatch_provider_disconnect(
    provider: config::Provider,
    _instance: Option<String>,
    _all: bool,
    _config: &config::AppConfig,
) -> anyhow::Result<()> {
    match provider {
        #[cfg(not(feature = "wgconf"))]
        config::Provider::Wgconf => {
            anyhow::bail!("wgconf support is disabled; enable the `wgconf` Cargo feature")
        }
        #[cfg(not(feature = "ivpn"))]
        config::Provider::Ivpn => {
            anyhow::bail!("ivpn support is disabled; enable the `ivpn` Cargo feature")
        }
        #[cfg(not(feature = "mullvad"))]
        config::Provider::Mullvad => {
            anyhow::bail!("mullvad support is disabled; enable the `mullvad` Cargo feature")
        }
        #[cfg(not(feature = "airvpn"))]
        config::Provider::AirVpn => {
            anyhow::bail!("airvpn support is disabled; enable the `airvpn` Cargo feature")
        }
        #[cfg(not(feature = "proton"))]
        config::Provider::Proton => {
            anyhow::bail!("proton support is disabled; enable the `proton` Cargo feature")
        }
        #[cfg(feature = "proton")]
        config::Provider::Proton => {
            cli::commands::proton::dispatch(
                cli::ProtonCommand::Disconnect {
                    instance: _instance,
                    all: _all,
                },
                _config,
            )
            .await
        }
        #[cfg(feature = "airvpn")]
        config::Provider::AirVpn => {
            cli::commands::airvpn::dispatch(
                cli::AirVpnCommand::Disconnect {
                    instance: _instance,
                    all: _all,
                },
                _config,
            )
            .await
        }
        #[cfg(feature = "mullvad")]
        config::Provider::Mullvad => {
            cli::commands::mullvad::dispatch(
                cli::MullvadCommand::Disconnect {
                    instance: _instance,
                    all: _all,
                },
                _config,
            )
            .await
        }
        #[cfg(feature = "ivpn")]
        config::Provider::Ivpn => {
            cli::commands::ivpn::dispatch(
                cli::IvpnCommand::Disconnect {
                    instance: _instance,
                    all: _all,
                },
                _config,
            )
            .await
        }
        #[cfg(feature = "wgconf")]
        config::Provider::Wgconf => {
            cli::commands::wgconf::dispatch(
                cli::WgconfCommand::Disconnect {
                    instance: _instance,
                    all: _all,
                },
                _config,
            )
            .await
        }
    }
}

fn cmd_status() -> anyhow::Result<()> {
    let (connections, corrupt) = ConnectionState::load_all_with_corrupt()?;
    for path in &corrupt {
        println!(
            "Unknown connection state: {} (corrupt saved record; recovery required)",
            path.display()
        );
    }

    if connections.is_empty() {
        if corrupt.is_empty() {
            println!("No active connections.");
        }
        return Ok(());
    }

    println!(
        "{:<12} {:<9} {:<10} {:<5} {:<9} {:<16} HTTP  Health",
        "Instance", "Provider", "Server", "Exit", "Backend", "SOCKS5"
    );
    println!("{}", "-".repeat(76));

    for conn in &connections {
        let health = wireguard::health::inspect(conn);
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
            "{:<12} {:<9} {:<10} {:<5} {:<9} {:<16} {}  {} ({})",
            conn.instance_name,
            conn.provider,
            conn.server_display_name,
            exit,
            conn.backend,
            socks,
            http,
            health.kind,
            health.reason,
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

#[cfg(test)]
mod tests {
    use crate::config;

    #[test]
    fn provider_mapping_includes_wgconf() {
        assert_eq!(
            config::Provider::from_dir_name("wgconf"),
            Some(config::Provider::Wgconf)
        );
        assert_eq!(config::Provider::Wgconf.label(), "wgconf");
    }
}

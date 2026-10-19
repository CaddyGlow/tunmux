use std::path::Path;

use crate::cli::ConnectOptions;
use crate::config::{AppConfig, Provider};
use crate::local_proxy;
use crate::netns;
use crate::proxy;
use crate::shared::hooks;
use crate::wireguard;
use crate::wireguard::backend::WgBackend;
use crate::wireguard::connection::ConnectionState;

/// Owns rollback until startup has successfully persisted its connection state.
struct StartupGuard<F: FnOnce()> {
    rollback: Option<F>,
}

impl<F: FnOnce()> StartupGuard<F> {
    fn new(rollback: F) -> Self {
        Self {
            rollback: Some(rollback),
        }
    }

    fn commit(mut self) {
        self.rollback.take();
    }
}

impl<F: FnOnce()> Drop for StartupGuard<F> {
    fn drop(&mut self) {
        if let Some(rollback) = self.rollback.take() {
            rollback();
        }
    }
}

fn log_cleanup_error(result: anyhow::Result<()>) {
    if let Err(error) = result {
        tracing::warn!(%error, "connection_rollback_failed");
    }
}

/// Describes a selected server for connection routing.
pub struct ResolvedServer<'a> {
    pub instance_seed: &'a str,
    pub display_name: &'a str,
}

/// Resolve the WireGuard backend and validate options from ConnectOptions.
pub fn resolve_opts(opts: &ConnectOptions, default_backend: &str) -> anyhow::Result<WgBackend> {
    if let Some(mtu) = opts.mtu {
        wireguard::config::Mtu::new(mtu)?;
    }
    let backend = resolve_connect_backend(
        opts.backend.as_deref(),
        default_backend,
        opts.proxy,
        opts.local_proxy,
    )?;
    validate_disable_ipv6_direct_kernel(opts.disable_ipv6, opts.proxy, opts.local_proxy, backend)?;
    Ok(backend)
}

/// Resolve the effective proxy_access_log value.
pub fn effective_proxy_access_log(opts: &ConnectOptions, config: &AppConfig) -> bool {
    opts.proxy_access_log || config.general.proxy_access_log
}

/// Route a connection through proxy, local-proxy, or direct mode.
///
/// This consolidates the identical 3-way dispatch (connect_proxy / connect_local_proxy /
/// connect_direct) that was previously duplicated in every provider handler.
pub fn connect_routed(
    server: &ResolvedServer<'_>,
    params: &wireguard::config::WgConfigParams<'_>,
    opts: &ConnectOptions,
    backend: WgBackend,
    provider: Provider,
    interface_name: &str,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let proxy_access_log = effective_proxy_access_log(opts, config);

    if opts.proxy {
        let instance = derive_instance_name(server.instance_seed, "server", server.display_name)?;
        ensure_instance_available(&instance, "server", server.display_name)?;

        let proxy_config = resolve_proxy_config(opts.socks_port, opts.http_port, proxy_access_log)?;
        connect_proxy_via_netns(&ConnectContext {
            provider,
            instance: &instance,
            display_name: server.display_name,
            connect_endpoint: params.server_ip,
            state_endpoint: &wireguard::config::format_endpoint(
                params.server_ip,
                params.server_port,
            ),
            dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
            params,
            proxy_config: &proxy_config,
            config,
        })
    } else if opts.local_proxy {
        let instance = derive_instance_name(server.instance_seed, "server", server.display_name)?;
        ensure_instance_available(&instance, "server", server.display_name)?;

        let proxy_config = resolve_proxy_config(opts.socks_port, opts.http_port, proxy_access_log)?;
        connect_local_proxy_instance(&LocalProxyContext {
            provider,
            instance: &instance,
            display_name: server.display_name,
            connect_endpoint: params.server_ip,
            state_endpoint: &wireguard::config::format_endpoint(
                params.server_ip,
                params.server_port,
            ),
            dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
            virtual_ips: params.addresses.iter().map(|s| s.to_string()).collect(),
            peer_public_key: params.server_public_key,
            params,
            proxy_config: &proxy_config,
            config,
        })
    } else {
        connect_direct_wg(
            params,
            backend,
            interface_name,
            provider,
            server.display_name,
            opts.disable_ipv6,
            config,
        )?;
        println!(
            "Connected to {} [backend: {}]",
            server.display_name, backend
        );
        Ok(())
    }
}

/// Standard provider disconnect: delegates to `disconnect_provider_connections`
/// with `disconnect_one_provider_connection`.
pub fn cmd_disconnect_provider(
    provider: Provider,
    instance: Option<String>,
    all: bool,
    config: &AppConfig,
    remove_namespace_dir: bool,
) -> anyhow::Result<()> {
    disconnect_provider_connections(provider.dir_name(), instance, all, |conn| {
        disconnect_one_provider_connection(conn, provider, config, remove_namespace_dir)
    })
}

pub fn resolve_connect_backend(
    backend_arg: Option<&str>,
    default_backend: &str,
    use_proxy: bool,
    use_local_proxy: bool,
) -> anyhow::Result<WgBackend> {
    let backend_str = backend_arg.unwrap_or(default_backend);

    if use_proxy && use_local_proxy {
        anyhow::bail!("--proxy and --local-proxy are mutually exclusive");
    }

    #[cfg(not(target_os = "linux"))]
    if use_proxy {
        anyhow::bail!("--proxy is available only on Linux");
    }

    if use_proxy && matches!(backend_str, "wg-quick" | "userspace") {
        anyhow::bail!(
            "--proxy requires kernel backend (incompatible with --backend {})",
            backend_str
        );
    }

    if use_proxy {
        Ok(WgBackend::Kernel)
    } else {
        WgBackend::from_str_arg(backend_str)
    }
}

pub fn validate_disable_ipv6_direct_kernel(
    disable_ipv6: bool,
    use_proxy: bool,
    use_local_proxy: bool,
    backend: WgBackend,
) -> anyhow::Result<()> {
    if disable_ipv6 && (use_proxy || use_local_proxy || backend != WgBackend::Kernel) {
        anyhow::bail!(
            "--disable-ipv6 is supported only for direct kernel mode (no --proxy/--local-proxy)"
        );
    }

    Ok(())
}

pub fn disconnect_provider_connections<F>(
    provider_name: &str,
    instance: Option<String>,
    all: bool,
    mut disconnect_one: F,
) -> anyhow::Result<()>
where
    F: FnMut(&ConnectionState) -> anyhow::Result<()>,
{
    if all {
        let connections = ConnectionState::load_all()?;
        let mine: Vec<_> = connections
            .into_iter()
            .filter(|c| c.provider == provider_name)
            .collect();
        if mine.is_empty() {
            println!("No active {} connections.", provider_name);
            return Ok(());
        }
        for conn in mine {
            disconnect_one(&conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        return Ok(());
    }

    if let Some(ref name) = instance {
        let conn = ConnectionState::load(name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", name))?;
        if conn.provider != provider_name {
            anyhow::bail!(
                "instance {:?} belongs to provider {:?}, not {}",
                name,
                conn.provider,
                provider_name
            );
        }
        disconnect_one(&conn)?;
        println!("Disconnected {}", name);
        return Ok(());
    }

    let connections = ConnectionState::load_all()?;
    let mine: Vec<_> = connections
        .into_iter()
        .filter(|c| c.provider == provider_name)
        .collect();

    match mine.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &mine[0];
            disconnect_one(conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &mine {
                let ports = match (conn.socks_port, conn.http_port) {
                    (Some(s), Some(h)) => format!("SOCKS5 :{}, HTTP :{}", s, h),
                    _ => "-".to_string(),
                };
                println!(
                    "  {}  {}  {}",
                    conn.instance_name, conn.server_display_name, ports
                );
            }
            println!("\nUsage: tunmux disconnect <instance>");
            println!(
                "       tunmux disconnect --provider {} --all",
                provider_name
            );
        }
    }

    Ok(())
}

pub fn disconnect_one_provider_connection(
    state: &ConnectionState,
    provider: Provider,
    config: &AppConfig,
    remove_namespace_dir_if_exists: bool,
) -> anyhow::Result<()> {
    let _preparation = lock_connection_preparation(&state.instance_name)?;
    if state.backend == WgBackend::LocalProxy {
        local_proxy::disconnect(state, &state.instance_name)?;
        hooks::run_ifdown(config, provider, state);
        return Ok(());
    }

    if let Some(pid) = state.proxy_pid {
        proxy::stop_daemon(pid)?;
    }

    let pid_path = proxy::pid_file(&state.instance_name);
    let log_path = proxy::log_file(&state.instance_name);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&log_path);

    if let Some(ref ns) = state.namespace_name {
        netns::delete(ns)?;
        if remove_namespace_dir_if_exists {
            let netns_etc = format!("/etc/netns/{}", ns);
            if Path::new(&netns_etc).exists() {
                let _ = netns::remove_namespace_dir(ns);
            }
        } else {
            let _ = netns::remove_namespace_dir(ns);
        }
    }

    if state.namespace_name.is_some() {
        ConnectionState::remove(&state.instance_name)?;
    } else {
        match state.backend {
            WgBackend::Kernel => {
                wireguard::kernel::down(state)?;
            }
            WgBackend::WgQuick => {
                wireguard::wg_quick::down(&state.interface_name, provider)?;
                ConnectionState::remove(&state.instance_name)?;
            }
            WgBackend::Userspace => {
                let id = state.session_id.as_deref().ok_or_else(|| anyhow::anyhow!("legacy connection has no verified session identity; disconnect with the version that started it, then reconnect"))?;
                wireguard::userspace::down_for_session(&state.interface_name, id)?;
                ConnectionState::remove(&state.instance_name)?;
            }
            WgBackend::LocalProxy => unreachable!(),
        }
    }

    hooks::run_ifdown(config, provider, state);
    Ok(())
}

pub fn derive_instance_name(
    instance_seed: &str,
    target_kind: &str,
    target_name: &str,
) -> anyhow::Result<String> {
    if let Some(instance) = crate::automation::managed_instance() {
        return Ok(instance.to_owned());
    }
    let instance = proxy::instance_name(instance_seed);
    if instance.is_empty() {
        anyhow::bail!(
            "unable to derive instance name from {} {}",
            target_kind,
            target_name
        );
    }
    Ok(instance)
}

/// Hold through startup and state persistence to serialize competing connects.
fn lock_connection_preparation(instance: &str) -> anyhow::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    crate::config::ensure_connections_dir()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(crate::config::connections_dir().join(format!("{instance}.prepare.lock")))?;
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(
        |(_, error)| anyhow::anyhow!("another connection operation owns {instance}: {error}"),
    )
}

pub fn ensure_instance_available(
    instance: &str,
    target_kind: &str,
    target_name: &str,
) -> anyhow::Result<()> {
    let _preparation = lock_connection_preparation(instance)?;
    ensure_instance_available_locked(instance, target_kind, target_name)
}

fn ensure_instance_available_locked(
    instance: &str,
    target_kind: &str,
    target_name: &str,
) -> anyhow::Result<()> {
    if let Some(preserved) = ConnectionState::quarantine_corrupt(instance)? {
        anyhow::bail!("corrupt connection state preserved at {}; session ownership remains unknown; explicit recovery required", preserved.display());
    }
    if let Some(state) = ConnectionState::load(instance)? {
        let health = wireguard::health::inspect_for_connect(&state);
        if health.kind == wireguard::health::HealthKind::Inactive
            && state.backend == WgBackend::LocalProxy
        {
            ConnectionState::remove(instance)?;
            return Ok(());
        }
        if health.kind == wireguard::health::HealthKind::Inactive && health.recovery_available {
            let id = state
                .session_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing session identity"))?;
            crate::privileged_client::PrivilegedClient::new()
                .recover_session(&state.interface_name, id)?;
            ConnectionState::remove(instance)?;
            return Ok(());
        }
        anyhow::bail!(
            "instance {:?} is {}: {} ({} {}). Disconnect/recover first or choose a different {}.",
            instance,
            health.kind,
            health.reason,
            target_kind,
            target_name,
            target_kind
        );
    }
    Ok(())
}

pub fn resolve_proxy_config(
    socks_port_arg: Option<u16>,
    http_port_arg: Option<u16>,
    proxy_access_log: bool,
) -> anyhow::Result<proxy::ProxyConfig> {
    if let (Some(sp), Some(hp)) = (socks_port_arg, http_port_arg) {
        return Ok(proxy::ProxyConfig {
            socks_port: sp,
            http_port: hp,
            access_log: proxy_access_log,
        });
    }

    let mut auto = proxy::next_available_ports()?;
    if let Some(sp) = socks_port_arg {
        auto.socks_port = sp;
    }
    if let Some(hp) = http_port_arg {
        auto.http_port = hp;
    }
    auto.access_log = proxy_access_log;
    Ok(auto)
}

/// Connect via WgQuick or Userspace backend in direct (non-proxy) mode.
/// Handles generating the WG config, bringing the interface up, saving state, and running hooks.
pub fn connect_direct_wg(
    params: &wireguard::config::WgConfigParams<'_>,
    backend: WgBackend,
    interface_name: &str,
    provider: Provider,
    display_name: &str,
    disable_ipv6: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    use wireguard::connection::{ConnectionState, DIRECT_INSTANCE};

    if matches!(backend, WgBackend::WgQuick | WgBackend::Userspace) {
        return connect_direct_config(
            &wireguard::config::generate_config(params),
            backend,
            interface_name,
            provider,
            display_name,
            config,
        );
    }

    let _preparation = lock_connection_preparation(DIRECT_INSTANCE)?;
    ensure_instance_available_locked(DIRECT_INSTANCE, "direct VPN", display_name)?;
    wireguard::userspace::prepare_endpoint(interface_name)?;
    if backend != WgBackend::Userspace && wireguard::wg_quick::is_interface_active(interface_name) {
        anyhow::bail!(
            "Already connected. Run `tunmux disconnect --provider {}` first.",
            provider.dir_name()
        );
    }

    println!("Connecting to {} ({})...", display_name, params.server_ip);

    match backend {
        WgBackend::Kernel => {
            wireguard::kernel::up(
                params,
                interface_name,
                provider.dir_name(),
                display_name,
                disable_ipv6,
            )?;
        }
        _ => {
            anyhow::bail!("use --local-proxy flag to start userspace WireGuard proxy mode");
        }
    }

    if let Some(state) = ConnectionState::load(DIRECT_INSTANCE)? {
        hooks::run_ifup(config, provider, &state);
    }

    Ok(())
}

/// Connect a full config without discarding wg-quick directives or additional peers.
pub fn connect_direct_config(
    text: &str,
    backend: WgBackend,
    interface_name: &str,
    provider: Provider,
    display_name: &str,
    config: &AppConfig,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    let _preparation = lock_connection_preparation(DIRECT_INSTANCE)?;
    ensure_instance_available_locked(DIRECT_INSTANCE, "direct VPN", display_name)?;
    wireguard::userspace::prepare_endpoint(interface_name)?;
    if backend != WgBackend::Userspace && wireguard::wg_quick::is_interface_active(interface_name) {
        anyhow::bail!(
            "Already connected. Run `tunmux disconnect --provider {}` first.",
            provider.dir_name()
        );
    }
    let parsed = wireguard::config::parse_config(text)?;
    println!("Connecting to {}...", display_name);
    let (effective_iface, session_id) = match backend {
        WgBackend::WgQuick => (
            wireguard::wg_quick::up(text, interface_name, provider, false)?,
            None,
        ),
        WgBackend::Userspace => (
            interface_name.to_owned(),
            Some(wireguard::userspace::up_raw_with_session(
                text,
                interface_name,
            )?),
        ),
        _ => anyhow::bail!("full config startup requires wg-quick or userspace backend"),
    };
    let rollback = StartupGuard::new(|| {
        let result = if let Some(id) = session_id.as_deref() {
            wireguard::userspace::down_for_session(&effective_iface, id)
        } else {
            wireguard::wg_quick::down(&effective_iface, provider)
        };
        log_cleanup_error(result.map_err(Into::into));
    });
    let state = ConnectionState {
        source_spec: None,
        allow_lan: false,
        session_id: session_id.clone(),
        instance_name: DIRECT_INSTANCE.to_string(),
        provider: provider.dir_name().to_string(),
        interface_name: effective_iface.clone(),
        backend,
        server_endpoint: parsed
            .peers
            .first()
            .and_then(|peer| peer.endpoint.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        server_display_name: display_name.to_string(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: None,
        proxy_pid: None,
        socks_port: None,
        http_port: None,
        dns_servers: parsed.dns_servers,
        peer_public_key: parsed.peers.first().map(|peer| peer.public_key.clone()),
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;
    rollback.commit();
    hooks::run_ifup(config, provider, &state);
    Ok(())
}

/// Disconnect the direct instance for a provider, if it exists.
pub fn disconnect_instance_direct<F>(mut disconnect_one: F) -> anyhow::Result<()>
where
    F: FnMut(&wireguard::connection::ConnectionState) -> anyhow::Result<()>,
{
    use wireguard::connection::{ConnectionState, DIRECT_INSTANCE};
    if let Some(state) = ConnectionState::load(DIRECT_INSTANCE)? {
        disconnect_one(&state)?;
    }
    Ok(())
}

pub struct ConnectContext<'a> {
    pub provider: Provider,
    pub instance: &'a str,
    pub display_name: &'a str,
    pub connect_endpoint: &'a str,
    pub state_endpoint: &'a str,
    pub dns_servers: Vec<String>,
    pub params: &'a wireguard::config::WgConfigParams<'a>,
    pub proxy_config: &'a proxy::ProxyConfig,
    pub config: &'a AppConfig,
}

pub fn connect_proxy_via_netns(ctx: &ConnectContext<'_>) -> anyhow::Result<()> {
    let _preparation = lock_connection_preparation(ctx.instance)?;
    ensure_instance_available_locked(ctx.instance, "server", ctx.display_name)?;
    let ConnectContext {
        provider,
        instance,
        display_name,
        connect_endpoint,
        state_endpoint,
        ref dns_servers,
        params,
        proxy_config,
        config,
    } = *ctx;
    let interface_name = format!("wg-{}", instance);
    let namespace_name = format!("tunmux_{}", instance);

    println!("Connecting to {} ({})...", display_name, connect_endpoint);

    netns::create(&namespace_name)?;
    let namespace_guard = StartupGuard::new(|| {
        log_cleanup_error(netns::delete(&namespace_name).map_err(Into::into));
    });
    wireguard::kernel::up_in_netns(params, &interface_name, &namespace_name)?;
    let pid = proxy::spawn_daemon(instance, &interface_name, &namespace_name, proxy_config)?;
    let daemon_guard = StartupGuard::new(|| {
        log_cleanup_error(proxy::stop_daemon(pid));
        let _ = std::fs::remove_file(proxy::pid_file(instance));
        let _ = std::fs::remove_file(proxy::log_file(instance));
    });

    let state = ConnectionState {
        source_spec: None,
        allow_lan: false,
        session_id: None,
        instance_name: instance.to_string(),
        provider: provider.dir_name().to_string(),
        interface_name,
        backend: WgBackend::Kernel,
        server_endpoint: state_endpoint.to_string(),
        server_display_name: display_name.to_string(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: Some(namespace_name.clone()),
        proxy_pid: Some(pid),
        socks_port: Some(proxy_config.socks_port),
        http_port: Some(proxy_config.http_port),
        dns_servers: dns_servers.clone(),
        peer_public_key: None,
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;
    daemon_guard.commit();
    namespace_guard.commit();
    hooks::run_ifup(config, provider, &state);

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, display_name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

pub struct LocalProxyContext<'a> {
    pub provider: Provider,
    pub instance: &'a str,
    pub display_name: &'a str,
    pub connect_endpoint: &'a str,
    pub state_endpoint: &'a str,
    pub dns_servers: Vec<String>,
    pub virtual_ips: Vec<String>,
    pub peer_public_key: &'a str,
    pub params: &'a wireguard::config::WgConfigParams<'a>,
    pub proxy_config: &'a proxy::ProxyConfig,
    pub config: &'a AppConfig,
}

pub fn connect_local_proxy_instance(ctx: &LocalProxyContext<'_>) -> anyhow::Result<()> {
    let _preparation = lock_connection_preparation(ctx.instance)?;
    ensure_instance_available_locked(ctx.instance, "server", ctx.display_name)?;
    let LocalProxyContext {
        provider,
        instance,
        display_name,
        connect_endpoint,
        state_endpoint,
        ref dns_servers,
        ref virtual_ips,
        peer_public_key,
        params,
        proxy_config,
        config,
    } = *ctx;
    let cfg = local_proxy::local_proxy_config_from_params(
        params,
        Some(25),
        proxy_config.socks_port,
        proxy_config.http_port,
    )?;
    let local_public_key = local_proxy::derive_public_key_b64(params.private_key).ok();

    println!("Connecting to {} ({})...", display_name, connect_endpoint);

    let pid = local_proxy::spawn_daemon(instance, &cfg, proxy_config.access_log)?;
    let daemon_guard = StartupGuard::new(|| {
        log_cleanup_error(local_proxy::stop_daemon(pid));
        let _ = std::fs::remove_file(proxy::local_pid_file(instance));
        let _ = std::fs::remove_file(proxy::local_log_file(instance));
    });

    let state = ConnectionState {
        source_spec: None,
        allow_lan: false,
        session_id: None,
        instance_name: instance.to_string(),
        provider: provider.dir_name().to_string(),
        interface_name: String::new(),
        backend: WgBackend::LocalProxy,
        server_endpoint: state_endpoint.to_string(),
        server_display_name: display_name.to_string(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: None,
        proxy_pid: Some(pid),
        socks_port: Some(proxy_config.socks_port),
        http_port: Some(proxy_config.http_port),
        dns_servers: dns_servers.clone(),
        peer_public_key: Some(peer_public_key.to_string()),
        local_public_key,
        virtual_ips: virtual_ips.clone(),
        keepalive_secs: cfg.keepalive,
    };
    state.save()?;
    daemon_guard.commit();
    hooks::run_ifup(config, provider, &state);

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, display_name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

#[cfg(test)]
mod startup_tests {
    use super::StartupGuard;
    use std::cell::RefCell;

    #[test]
    fn test_failed_startup_rolls_back_in_reverse_order_and_preserves_error() {
        let cleanup = RefCell::new(Vec::new());
        let result: anyhow::Result<()> = (|| {
            let _namespace = StartupGuard::new(|| cleanup.borrow_mut().push("namespace"));
            let _daemon = StartupGuard::new(|| cleanup.borrow_mut().push("daemon"));
            Err(anyhow::anyhow!("state save failed"))?;
            Ok(())
        })();
        assert_eq!(result.unwrap_err().to_string(), "state save failed");
        assert_eq!(*cleanup.borrow(), ["daemon", "namespace"]);
    }

    #[test]
    fn test_successful_startup_keeps_resources() {
        let cleanup = RefCell::new(Vec::new());
        let guard = StartupGuard::new(|| cleanup.borrow_mut().push("daemon"));
        guard.commit();
        assert!(cleanup.borrow().is_empty());
    }
}

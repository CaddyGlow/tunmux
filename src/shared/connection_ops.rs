use std::path::Path;

use crate::config::{AppConfig, Provider};
use crate::local_proxy;
use crate::netns;
use crate::proxy;
use crate::shared::hooks;
use crate::wireguard;
use crate::wireguard::backend::WgBackend;
use crate::wireguard::connection::ConnectionState;

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
                wireguard::userspace::down(&state.interface_name)?;
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

pub fn ensure_instance_available(
    instance: &str,
    target_kind: &str,
    target_name: &str,
) -> anyhow::Result<()> {
    if ConnectionState::exists(instance) {
        anyhow::bail!(
            "instance {:?} already exists ({} {} already connected). Disconnect first or choose a different {}.",
            instance,
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

#[allow(clippy::too_many_arguments)]
pub fn connect_proxy_via_netns(
    provider: Provider,
    instance: &str,
    display_name: &str,
    connect_endpoint: &str,
    state_endpoint: &str,
    dns_servers: Vec<String>,
    params: &wireguard::config::WgConfigParams<'_>,
    proxy_config: &proxy::ProxyConfig,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let interface_name = format!("wg-{}", instance);
    let namespace_name = format!("tunmux_{}", instance);

    println!("Connecting to {} ({})...", display_name, connect_endpoint);

    netns::create(&namespace_name)?;

    if let Err(e) = wireguard::kernel::up_in_netns(params, &interface_name, &namespace_name) {
        netns::delete(&namespace_name)?;
        return Err(e.into());
    }

    let pid = match proxy::spawn_daemon(instance, &interface_name, &namespace_name, proxy_config) {
        Ok(pid) => pid,
        Err(e) => {
            netns::delete(&namespace_name)?;
            return Err(e);
        }
    };

    let state = ConnectionState {
        instance_name: instance.to_string(),
        provider: provider.dir_name().to_string(),
        interface_name,
        backend: WgBackend::Kernel,
        server_endpoint: state_endpoint.to_string(),
        server_display_name: display_name.to_string(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: Some(namespace_name),
        proxy_pid: Some(pid),
        socks_port: Some(proxy_config.socks_port),
        http_port: Some(proxy_config.http_port),
        dns_servers,
        peer_public_key: None,
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;
    hooks::run_ifup(config, provider, &state);

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, display_name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn connect_local_proxy_instance(
    provider: Provider,
    instance: &str,
    display_name: &str,
    connect_endpoint: &str,
    state_endpoint: &str,
    dns_servers: Vec<String>,
    virtual_ips: Vec<String>,
    peer_public_key: &str,
    params: &wireguard::config::WgConfigParams<'_>,
    proxy_config: &proxy::ProxyConfig,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let cfg = local_proxy::local_proxy_config_from_params(
        params,
        Some(25),
        proxy_config.socks_port,
        proxy_config.http_port,
    )?;
    let local_public_key = local_proxy::derive_public_key_b64(params.private_key).ok();

    println!("Connecting to {} ({})...", display_name, connect_endpoint);

    let pid = local_proxy::spawn_daemon(instance, &cfg, proxy_config.access_log)?;

    let state = ConnectionState {
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
        dns_servers,
        peer_public_key: Some(peer_public_key.to_string()),
        local_public_key,
        virtual_ips,
        keepalive_secs: cfg.keepalive,
    };
    state.save()?;
    hooks::run_ifup(config, provider, &state);

    println!(
        "Connected {} ({}) -- SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}",
        instance, display_name, proxy_config.socks_port, proxy_config.http_port
    );
    Ok(())
}

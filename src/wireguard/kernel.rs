use std::net::IpAddr;
use std::process::Command;

use crate::config;
use crate::error::{AppError, Result};
use crate::netns;
use crate::privileged_client::PrivilegedClient;
use tracing::{debug, info, warn};

use super::backend::WgBackend;
use super::config::WgConfigParams;
use super::connection::{ConnectionState, DIRECT_INSTANCE};
use super::handshake;

/// Bring up a WireGuard tunnel using kernel ip/wg commands (host routing).
pub fn up(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    provider: &str,
    server_display_name: &str,
    disable_ipv6: bool,
) -> Result<()> {
    if cfg!(target_os = "macos") {
        return up_macos(
            params,
            interface_name,
            provider,
            server_display_name,
            disable_ipv6,
        );
    }
    if !cfg!(target_os = "linux") {
        return Err(AppError::WireGuard(
            "kernel backend is only supported on linux and macos".to_string(),
        ));
    }

    info!(
        interface = interface_name,
        provider,
        server = server_display_name,
        endpoint_host = params.server_ip,
        endpoint_port = params.server_port,
        "kernel_tunnel_setup_start"
    );

    let (gw_ip, gw_iface) = get_default_gateway()?;
    info!(
        interface = interface_name,
        gateway_ip = gw_ip,
        gateway_iface = gw_iface,
        "kernel_default_gateway_detected"
    );

    let original_resolv = if should_manage_global_resolv_conf() {
        std::fs::read_to_string("/etc/resolv.conf").ok()
    } else {
        None
    };

    if disable_ipv6 && has_ipv6_interface_address(params.addresses) {
        return Err(AppError::WireGuard(
            "--disable-ipv6 can only be used when Interface.Address has no IPv6 entry".into(),
        ));
    }
    if let Some(mtu) = params.mtu {
        validate_mtu(mtu)?;
    }

    let state = ConnectionState {
        instance_name: DIRECT_INSTANCE.to_string(),
        provider: provider.to_string(),
        interface_name: interface_name.to_string(),
        backend: WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: server_display_name.to_string(),
        original_gateway_ip: Some(gw_ip.clone()),
        original_gateway_iface: Some(gw_iface.clone()),
        original_resolv_conf: original_resolv,
        namespace_name: None,
        proxy_pid: None,
        socks_port: None,
        http_port: None,
        dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
        peer_public_key: None,
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;

    if let Err(e) = bring_up(
        params,
        interface_name,
        &gw_ip,
        &gw_iface,
        should_manage_global_resolv_conf(),
    )
    .and_then(|_| {
        let dns_servers: Vec<String> = params
            .dns_servers
            .iter()
            .map(|server| (*server).to_string())
            .collect();
        handshake::wait_for_handshake(interface_name, &dns_servers)
    }) {
        let _ = PrivilegedClient::new().interface_delete(interface_name);
        ConnectionState::remove(DIRECT_INSTANCE)?;
        return Err(e);
    }

    info!(
        interface = interface_name,
        provider,
        server = server_display_name,
        "kernel_tunnel_setup_complete"
    );

    Ok(())
}

/// Bring up a WireGuard tunnel inside a network namespace (no host route changes).
pub fn up_in_netns(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    namespace: &str,
) -> Result<()> {
    if !cfg!(target_os = "linux") {
        let _ = (params, interface_name, namespace);
        return Err(AppError::WireGuard(
            "kernel backend in network namespaces is only supported on linux".to_string(),
        ));
    }

    if let Some(mtu) = params.mtu {
        validate_mtu(mtu)?;
    }

    info!(
        interface = interface_name,
        namespace,
        endpoint_host = params.server_ip,
        endpoint_port = params.server_port,
        mtu = params.mtu,
        "kernel_tunnel_setup_in_namespace_start"
    );

    let client = PrivilegedClient::new();

    log_kernel_setup_command(
        interface_name,
        &format!("ip link add dev {} type wireguard", interface_name),
    );
    client.interface_create_wireguard(interface_name)?;

    let endpoint = format!("{}:{}", params.server_ip, params.server_port);
    let allowed_ips_wg = params.allowed_ips.replace(", ", ",");
    log_kernel_setup_command(
        interface_name,
        &format!(
            "wg set {} peer {} endpoint {} allowed-ips {}",
            interface_name, params.server_public_key, endpoint, allowed_ips_wg
        ),
    );
    if let Err(e) = client.wireguard_set(
        interface_name,
        params.private_key,
        params.server_public_key,
        &endpoint,
        &allowed_ips_wg,
    ) {
        let _ = client.interface_delete(interface_name);
        return Err(e);
    }
    if let Some(psk) = params.preshared_key {
        log_kernel_setup_command(
            interface_name,
            &format!(
                "wg set {} peer {} preshared-key <redacted>",
                interface_name, params.server_public_key
            ),
        );
        client.wireguard_set_psk(interface_name, params.server_public_key, psk)?;
    }
    log_kernel_setup_command(
        interface_name,
        &format!("ip link set {} netns {}", interface_name, namespace),
    );
    if let Err(e) = client.interface_move_to_netns(interface_name, namespace) {
        let _ = client.interface_delete(interface_name);
        return Err(e);
    }

    for addr in params.addresses {
        log_kernel_setup_command(
            interface_name,
            &format!("ip addr add {} dev {}", addr, interface_name),
        );
        if let Err(e) = netns::exec(
            namespace,
            &["ip", "addr", "add", addr, "dev", interface_name],
        ) {
            let _ = netns::delete(namespace);
            let _ = client.interface_delete(interface_name);
            return Err(e);
        }
    }

    log_kernel_setup_command(
        interface_name,
        &format!("ip link set up dev {}", interface_name),
    );
    if let Some(mtu) = params.mtu {
        log_kernel_setup_command(
            interface_name,
            &format!("ip link set dev {} mtu {}", interface_name, mtu),
        );
        let mtu = mtu.to_string();
        if let Err(e) = netns::exec(
            namespace,
            &[
                "ip",
                "link",
                "set",
                "dev",
                interface_name,
                "mtu",
                mtu.as_str(),
            ],
        ) {
            let _ = netns::delete(namespace);
            let _ = client.interface_delete(interface_name);
            return Err(e);
        }
    }
    if let Err(e) = netns::exec(
        namespace,
        &["ip", "link", "set", "up", "dev", interface_name],
    ) {
        let _ = netns::delete(namespace);
        let _ = client.interface_delete(interface_name);
        return Err(e);
    }
    log_kernel_setup_command(
        interface_name,
        &format!("ip route add default dev {}", interface_name),
    );
    if let Err(e) = netns::exec(
        namespace,
        &["ip", "route", "add", "default", "dev", interface_name],
    ) {
        let _ = netns::delete(namespace);
        let _ = client.interface_delete(interface_name);
        return Err(e);
    }

    let has_ipv6 = params.addresses.iter().any(|a| a.contains(':'));
    if has_ipv6 {
        log_kernel_setup_command(
            interface_name,
            &format!("ip -6 route add default dev {}", interface_name),
        );
        if let Err(e) = netns::exec(
            namespace,
            &["ip", "-6", "route", "add", "default", "dev", interface_name],
        ) {
            let _ = netns::delete(namespace);
            let _ = client.interface_delete(interface_name);
            return Err(e);
        }
    }

    let netns_etc = format!("/etc/netns/{}", namespace);
    log_kernel_setup_command(interface_name, &format!("mkdir -p {}", netns_etc));
    client.ensure_dir(&netns_etc, 0o700)?;
    let dns_content: String = params
        .dns_servers
        .iter()
        .map(|d| format!("nameserver {}\n", d))
        .collect();
    log_kernel_setup_command(interface_name, &format!("write {}/resolv.conf", netns_etc));
    client.write_file(
        &format!("{}/resolv.conf", netns_etc),
        dns_content.as_bytes(),
        0o644,
    )?;

    info!(
        interface = interface_name,
        namespace,
        ipv6_default = has_ipv6,
        dns_servers = params.dns_servers.len(),
        "kernel_tunnel_setup_in_namespace_complete"
    );

    Ok(())
}

/// Tear down a kernel WireGuard tunnel.
pub fn down(state: &ConnectionState) -> Result<()> {
    if cfg!(target_os = "macos") {
        return down_macos(state);
    }
    if !cfg!(target_os = "linux") {
        return Err(AppError::WireGuard(
            "kernel backend is only supported on linux and macos".to_string(),
        ));
    }

    let iface = &state.interface_name;
    let client = PrivilegedClient::new();
    let manage_resolv_conf = should_manage_global_resolv_conf();

    info!(
        interface = iface,
        provider = state.provider,
        server = state.server_display_name,
        "kernel_tunnel_teardown_start"
    );

    if !manage_resolv_conf {
        log_kernel_teardown_command(iface, &format!("resolvectl revert {}", iface));
        if let Err(error) = client.host_resolved_revert_dns(iface) {
            warn!(
                interface = iface,
                error = %error,
                "kernel_resolved_revert_failed"
            );
        }
    }

    log_kernel_teardown_command(iface, &format!("ip link delete dev {}", iface));
    let _ = client.interface_delete(iface);

    if let (Some(gw_ip), Some(gw_iface)) =
        (&state.original_gateway_ip, &state.original_gateway_iface)
    {
        let endpoint_ip = state
            .server_endpoint
            .split(':')
            .next()
            .unwrap_or(&state.server_endpoint);
        let host_route = format!("{}/32", endpoint_ip);
        log_kernel_teardown_command(
            iface,
            &format!("ip route del {} via {} dev {}", host_route, gw_ip, gw_iface),
        );
        let _ = client.host_ip_route_del(&host_route, Some(gw_ip), gw_iface);
    }

    if let Some(ref original) = state.original_resolv_conf {
        if manage_resolv_conf {
            log_kernel_teardown_command(iface, "write /etc/resolv.conf");
            client.write_file("/etc/resolv.conf", original.as_bytes(), 0o644)?;
        }
    }

    ConnectionState::remove(&state.instance_name)?;
    info!(
        interface = iface,
        provider = state.provider,
        server = state.server_display_name,
        "kernel_tunnel_teardown_complete"
    );
    Ok(())
}

fn bring_up(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    gw_ip: &str,
    gw_iface: &str,
    manage_resolv_conf: bool,
) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = interface_name,
        endpoint_host = params.server_ip,
        endpoint_port = params.server_port,
        address_count = params.addresses.len(),
        dns_servers = params.dns_servers.len(),
        mtu = params.mtu,
        manage_resolv_conf,
        "kernel_tunnel_apply_start"
    );

    log_kernel_setup_command(
        interface_name,
        &format!("ip link add dev {} type wireguard", interface_name),
    );
    client.interface_create_wireguard(interface_name)?;

    let endpoint = format!("{}:{}", params.server_ip, params.server_port);
    let allowed_ips_wg = params.allowed_ips.replace(", ", ",");
    log_kernel_setup_command(
        interface_name,
        &format!(
            "wg set {} peer {} endpoint {} allowed-ips {}",
            interface_name, params.server_public_key, endpoint, allowed_ips_wg
        ),
    );
    client.wireguard_set(
        interface_name,
        params.private_key,
        params.server_public_key,
        &endpoint,
        &allowed_ips_wg,
    )?;
    if let Some(psk) = params.preshared_key {
        log_kernel_setup_command(
            interface_name,
            &format!(
                "wg set {} peer {} preshared-key <redacted>",
                interface_name, params.server_public_key
            ),
        );
        client.wireguard_set_psk(interface_name, params.server_public_key, psk)?;
    }

    for addr in params.addresses {
        log_kernel_setup_command(
            interface_name,
            &format!("ip addr add {} dev {}", addr, interface_name),
        );
        client.host_ip_addr_add(interface_name, addr)?;
    }

    log_kernel_setup_command(
        interface_name,
        &format!("ip link set up dev {}", interface_name),
    );
    if let Some(mtu) = params.mtu {
        log_kernel_setup_command(
            interface_name,
            &format!("ip link set dev {} mtu {}", interface_name, mtu),
        );
        client.host_ip_link_set_mtu(interface_name, mtu)?;
    }
    client.host_ip_link_set_up(interface_name)?;

    let host_route = format!("{}/32", params.server_ip);
    log_kernel_setup_command(
        interface_name,
        &format!("ip route add {} via {} dev {}", host_route, gw_ip, gw_iface),
    );
    client.host_ip_route_add(&host_route, Some(gw_ip), gw_iface)?;
    log_kernel_setup_command(
        interface_name,
        &format!("ip route add 0.0.0.0/1 dev {}", interface_name),
    );
    client.host_ip_route_add("0.0.0.0/1", None, interface_name)?;
    log_kernel_setup_command(
        interface_name,
        &format!("ip route add 128.0.0.0/1 dev {}", interface_name),
    );
    client.host_ip_route_add("128.0.0.0/1", None, interface_name)?;
    info!(
        interface = interface_name,
        "kernel_ipv4_split_routes_installed"
    );

    if should_install_ipv6_default_routes(params) {
        log_kernel_setup_command(
            interface_name,
            &format!("ip -6 route add ::/1 dev {}", interface_name),
        );
        client.host_ip_route_add("::/1", None, interface_name)?;
        log_kernel_setup_command(
            interface_name,
            &format!("ip -6 route add 8000::/1 dev {}", interface_name),
        );
        client.host_ip_route_add("8000::/1", None, interface_name)?;
        info!(
            interface = interface_name,
            "kernel_ipv6_split_routes_installed"
        );
    } else if should_install_ipv6_fallback_block_routes(params) {
        log_kernel_setup_command(
            interface_name,
            &format!("ip -6 route add ::/1 dev {}", interface_name),
        );
        client.host_ip_route_add("::/1", None, interface_name)?;
        log_kernel_setup_command(
            interface_name,
            &format!("ip -6 route add 8000::/1 dev {}", interface_name),
        );
        client.host_ip_route_add("8000::/1", None, interface_name)?;
        warn!(
            interface = interface_name,
            allowed_ips = params.allowed_ips,
            "kernel_ipv6_default_requested_without_ipv6_interface_address_blocking_host_ipv6"
        );
    }

    let dns_content: String = params
        .dns_servers
        .iter()
        .map(|d| format!("nameserver {}\n", d))
        .collect();
    if manage_resolv_conf {
        log_kernel_setup_command(interface_name, "write /etc/resolv.conf");
        client.write_file("/etc/resolv.conf", dns_content.as_bytes(), 0o644)?;
        info!(
            interface = interface_name,
            dns_servers = params.dns_servers.len(),
            "kernel_resolv_conf_updated"
        );
    } else {
        let dns_list = params.dns_servers.join(" ");
        log_kernel_setup_command(
            interface_name,
            &format!("resolvectl dns {} {}", interface_name, dns_list),
        );
        log_kernel_setup_command(
            interface_name,
            &format!("resolvectl domain {} ~.", interface_name),
        );
        log_kernel_setup_command(
            interface_name,
            &format!("resolvectl default-route {} yes", interface_name),
        );
        client.host_resolved_set_dns(interface_name, params.dns_servers)?;
        info!(
            interface = interface_name,
            dns_servers = params.dns_servers.len(),
            "kernel_resolved_link_dns_updated"
        );
    }

    Ok(())
}

fn provider_from_dir_name(name: &str) -> Option<config::Provider> {
    match name {
        "proton" => Some(config::Provider::Proton),
        "airvpn" => Some(config::Provider::AirVpn),
        "mullvad" => Some(config::Provider::Mullvad),
        "ivpn" => Some(config::Provider::Ivpn),
        "wgconf" => Some(config::Provider::Wgconf),
        _ => None,
    }
}

fn up_macos(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    provider: &str,
    server_display_name: &str,
    disable_ipv6: bool,
) -> Result<()> {
    if disable_ipv6 && has_ipv6_interface_address(params.addresses) {
        return Err(AppError::WireGuard(
            "--disable-ipv6 can only be used when Interface.Address has no IPv6 entry".into(),
        ));
    }
    if let Some(mtu) = params.mtu {
        validate_mtu(mtu)?;
    }

    let provider = provider_from_dir_name(provider)
        .ok_or_else(|| AppError::WireGuard(format!("unsupported provider {:?}", provider)))?;

    let wg_config = super::config::generate_config(params);
    let effective_iface = super::wg_quick::up(&wg_config, interface_name, provider, false)?;

    let state = ConnectionState {
        instance_name: DIRECT_INSTANCE.to_string(),
        provider: provider.dir_name().to_string(),
        interface_name: effective_iface,
        backend: WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: server_display_name.to_string(),
        original_gateway_ip: None,
        original_gateway_iface: None,
        original_resolv_conf: None,
        namespace_name: None,
        proxy_pid: None,
        socks_port: None,
        http_port: None,
        dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
        peer_public_key: None,
        local_public_key: None,
        virtual_ips: vec![],
        keepalive_secs: None,
    };
    state.save()?;

    info!(
        interface = state.interface_name,
        provider = state.provider,
        server = server_display_name,
        "kernel_tunnel_setup_complete_macos"
    );
    Ok(())
}

fn down_macos(state: &ConnectionState) -> Result<()> {
    let provider = provider_from_dir_name(&state.provider)
        .ok_or_else(|| AppError::WireGuard(format!("unsupported provider {:?}", state.provider)))?;
    super::wg_quick::down(&state.interface_name, provider)?;
    ConnectionState::remove(&state.instance_name)?;
    info!(
        interface = state.interface_name,
        provider = state.provider,
        server = state.server_display_name,
        "kernel_tunnel_teardown_complete_macos"
    );
    Ok(())
}

fn should_manage_global_resolv_conf() -> bool {
    !is_systemd_resolved_managed_resolv_conf("/etc/resolv.conf")
}

fn log_kernel_setup_command(interface_name: &str, command: &str) {
    info!(interface = interface_name, command, "kernel_setup_command");
}

fn log_kernel_teardown_command(interface_name: &str, command: &str) {
    info!(
        interface = interface_name,
        command, "kernel_teardown_command"
    );
}

fn should_install_ipv6_default_routes(params: &WgConfigParams<'_>) -> bool {
    has_ipv6_interface_address(params.addresses)
        && allowed_ips_contains_ipv6_default(params.allowed_ips)
}

fn should_install_ipv6_fallback_block_routes(params: &WgConfigParams<'_>) -> bool {
    !has_ipv6_interface_address(params.addresses)
        && allowed_ips_contains_ipv6_default(params.allowed_ips)
}

fn has_ipv6_interface_address(addresses: &[&str]) -> bool {
    addresses.iter().any(|cidr| {
        let ip = cidr.split('/').next().unwrap_or_default().trim();
        ip.parse::<IpAddr>().is_ok_and(|addr| addr.is_ipv6())
    })
}

fn allowed_ips_contains_ipv6_default(allowed_ips: &str) -> bool {
    allowed_ips.split(',').any(|entry| entry.trim() == "::/0")
}

fn validate_mtu(mtu: u16) -> Result<()> {
    if mtu < 576 {
        return Err(AppError::WireGuard(format!(
            "invalid MTU {} (must be >= 576)",
            mtu
        )));
    }
    Ok(())
}

fn is_systemd_resolved_managed_resolv_conf(path: &str) -> bool {
    match std::fs::canonicalize(path) {
        Ok(real_path) => real_path.starts_with("/run/systemd/resolve/"),
        Err(_) => false,
    }
}

/// Parse the default gateway IP and interface from `ip route show default`.
fn get_default_gateway() -> Result<(String, String)> {
    debug!(cmd = "ip route show default", "exec");
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| AppError::WireGuard(format!("failed to run ip route: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_default_route(&stdout)
}

fn parse_default_route(output: &str) -> Result<(String, String)> {
    // Example: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    let line = output
        .lines()
        .find(|l| l.starts_with("default"))
        .ok_or_else(|| AppError::WireGuard("no default route found".into()))?;

    let tokens: Vec<&str> = line.split_whitespace().collect();

    let via_pos = tokens
        .iter()
        .position(|&t| t == "via")
        .ok_or_else(|| AppError::WireGuard("no 'via' in default route".into()))?;
    let gateway = tokens
        .get(via_pos + 1)
        .ok_or_else(|| AppError::WireGuard("no gateway IP after 'via'".into()))?;
    let dev_pos = tokens
        .iter()
        .position(|&t| t == "dev")
        .ok_or_else(|| AppError::WireGuard("no 'dev' in default route".into()))?;
    let iface = tokens
        .get(dev_pos + 1)
        .ok_or_else(|| AppError::WireGuard("no interface name after 'dev'".into()))?;

    Ok(((*gateway).to_string(), (*iface).to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_route() {
        let output = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        let (gw, iface) = parse_default_route(output).unwrap();
        assert_eq!(gw, "192.168.1.1");
        assert_eq!(iface, "eth0");
    }

    #[test]
    fn test_parse_default_route_minimal() {
        let output = "default via 10.0.0.1 dev wlan0\n";
        let (gw, iface) = parse_default_route(output).unwrap();
        assert_eq!(gw, "10.0.0.1");
        assert_eq!(iface, "wlan0");
    }

    #[test]
    fn test_parse_default_route_no_default() {
        let output = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        assert!(parse_default_route(output).is_err());
    }

    #[test]
    fn test_should_install_ipv6_default_routes_true() {
        let addresses = ["10.0.0.2/32", "fd7d:76ee:e68f:a993::2/128"];
        assert!(has_ipv6_interface_address(&addresses));
        assert!(allowed_ips_contains_ipv6_default("0.0.0.0/0, ::/0"));
    }

    #[test]
    fn test_should_install_ipv6_default_routes_false_without_v6_address() {
        let addresses = ["10.0.0.2/32"];
        assert!(!has_ipv6_interface_address(&addresses));
        assert!(allowed_ips_contains_ipv6_default("0.0.0.0/0,::/0"));
    }

    #[test]
    fn test_should_install_ipv6_default_routes_false_without_v6_allowed_ips() {
        let addresses = ["fd7d:76ee:e68f:a993::2/128"];
        assert!(has_ipv6_interface_address(&addresses));
        assert!(!allowed_ips_contains_ipv6_default("0.0.0.0/0"));
    }

    #[test]
    fn test_should_install_ipv6_fallback_block_routes_true_without_v6_address() {
        let params = WgConfigParams {
            private_key: "private",
            addresses: &["10.0.0.2/32"],
            dns_servers: &["10.0.0.1"],
            mtu: None,
            server_public_key: "peer",
            server_ip: "149.102.245.129",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        assert!(should_install_ipv6_fallback_block_routes(&params));
    }

    #[test]
    fn test_should_install_ipv6_fallback_block_routes_false_with_v6_address() {
        let params = WgConfigParams {
            private_key: "private",
            addresses: &["10.0.0.2/32", "fd7d:76ee:e68f:a993::2/128"],
            dns_servers: &["10.0.0.1"],
            mtu: None,
            server_public_key: "peer",
            server_ip: "149.102.245.129",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        assert!(!should_install_ipv6_fallback_block_routes(&params));
    }

    #[test]
    fn test_validate_mtu_rejects_too_small_values() {
        assert!(validate_mtu(575).is_err());
    }

    #[test]
    fn test_validate_mtu_accepts_reasonable_values() {
        assert!(validate_mtu(1280).is_ok());
    }
}

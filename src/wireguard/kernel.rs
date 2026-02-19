use std::process::Command;

use crate::error::{AppError, Result};
use tracing::debug;
use crate::netns;
use crate::privileged_client::PrivilegedClient;

use super::backend::WgBackend;
use super::config::WgConfigParams;
use super::connection::{ConnectionState, DIRECT_INSTANCE};

/// Bring up a WireGuard tunnel using kernel ip/wg commands (host routing).
pub fn up(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    provider: &str,
    server_display_name: &str,
) -> Result<()> {
    let (gw_ip, gw_iface) = get_default_gateway()?;
    let original_resolv = if should_manage_global_resolv_conf() {
        std::fs::read_to_string("/etc/resolv.conf").ok()
    } else {
        None
    };

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
    };
    state.save()?;

    if let Err(e) = bring_up(
        params,
        interface_name,
        &gw_ip,
        &gw_iface,
        should_manage_global_resolv_conf(),
    ) {
        let _ = PrivilegedClient::new().interface_delete(interface_name);
        ConnectionState::remove(DIRECT_INSTANCE)?;
        return Err(e);
    }

    Ok(())
}

/// Bring up a WireGuard tunnel inside a network namespace (no host route changes).
pub fn up_in_netns(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    namespace: &str,
) -> Result<()> {
    let client = PrivilegedClient::new();

    client.interface_create_wireguard(interface_name)?;

    let endpoint = format!("{}:{}", params.server_ip, params.server_port);
    let allowed_ips_wg = params.allowed_ips.replace(", ", ",");
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
        client.wireguard_set_psk(interface_name, params.server_public_key, psk)?;
    }
    if let Err(e) = client.interface_move_to_netns(interface_name, namespace) {
        let _ = client.interface_delete(interface_name);
        return Err(e);
    }

    for addr in params.addresses {
        if let Err(e) = netns::exec(
            namespace,
            &["ip", "addr", "add", addr, "dev", interface_name],
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
    client.ensure_dir(&netns_etc, 0o700)?;
    let dns_content: String = params
        .dns_servers
        .iter()
        .map(|d| format!("nameserver {}\n", d))
        .collect();
    client.write_file(
        &format!("{}/resolv.conf", netns_etc),
        dns_content.as_bytes(),
        0o644,
    )?;

    Ok(())
}

/// Tear down a kernel WireGuard tunnel.
pub fn down(state: &ConnectionState) -> Result<()> {
    let iface = &state.interface_name;
    let client = PrivilegedClient::new();

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
        let _ = client.host_ip_route_del(&host_route, Some(gw_ip), gw_iface);
    }

    if let Some(ref original) = state.original_resolv_conf {
        if should_manage_global_resolv_conf() {
            client.write_file("/etc/resolv.conf", original.as_bytes(), 0o644)?;
        }
    }

    ConnectionState::remove(&state.instance_name)?;
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
    client.interface_create_wireguard(interface_name)?;

    let endpoint = format!("{}:{}", params.server_ip, params.server_port);
    let allowed_ips_wg = params.allowed_ips.replace(", ", ",");
    client.wireguard_set(
        interface_name,
        params.private_key,
        params.server_public_key,
        &endpoint,
        &allowed_ips_wg,
    )?;

    for addr in params.addresses {
        client.host_ip_addr_add(interface_name, addr)?;
    }

    client.host_ip_link_set_up(interface_name)?;

    let host_route = format!("{}/32", params.server_ip);
    client.host_ip_route_add(&host_route, Some(gw_ip), gw_iface)?;
    client.host_ip_route_add("0.0.0.0/1", None, interface_name)?;
    client.host_ip_route_add("128.0.0.0/1", None, interface_name)?;

    let dns_content: String = params
        .dns_servers
        .iter()
        .map(|d| format!("nameserver {}\n", d))
        .collect();
    if manage_resolv_conf {
        client.write_file("/etc/resolv.conf", dns_content.as_bytes(), 0o644)?;
    }

    Ok(())
}

fn should_manage_global_resolv_conf() -> bool {
    !is_systemd_resolved_managed_resolv_conf("/etc/resolv.conf")
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
}

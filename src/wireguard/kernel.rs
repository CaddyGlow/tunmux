use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use tracing::info;

use crate::error::{AppError, Result};

use super::backend::WgBackend;
use super::config::WgConfigParams;
use super::connection::ConnectionState;

/// Bring up a WireGuard tunnel using kernel ip/wg commands.
pub fn up(params: &WgConfigParams<'_>, interface_name: &str, provider: &str) -> Result<()> {
    let (gw_ip, gw_iface) = get_default_gateway()?;
    let original_resolv = fs::read_to_string("/etc/resolv.conf").ok();

    let state = ConnectionState {
        provider: provider.to_string(),
        interface_name: interface_name.to_string(),
        backend: WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        original_gateway_ip: Some(gw_ip.clone()),
        original_gateway_iface: Some(gw_iface.clone()),
        original_resolv_conf: original_resolv,
    };
    state.save()?;

    if let Err(e) = bring_up(params, interface_name, &gw_ip, &gw_iface) {
        // Clean up on failure
        let _ = sudo_run(&["ip", "link", "del", "dev", interface_name]);
        ConnectionState::remove()?;
        return Err(e);
    }

    Ok(())
}

/// Tear down a kernel WireGuard tunnel.
pub fn down(state: &ConnectionState) -> Result<()> {
    let iface = &state.interface_name;

    // Removing the interface also removes its routes and addresses
    sudo_run(&["ip", "link", "del", "dev", iface])?;

    // Remove the endpoint host route
    if let (Some(gw_ip), Some(gw_iface)) =
        (&state.original_gateway_ip, &state.original_gateway_iface)
    {
        let endpoint_ip = state
            .server_endpoint
            .split(':')
            .next()
            .unwrap_or(&state.server_endpoint);
        let host_route = format!("{}/32", endpoint_ip);
        // Best-effort: route may already be gone
        let _ = sudo_run(&["ip", "route", "del", &host_route, "via", gw_ip, "dev", gw_iface]);
    }

    // Restore /etc/resolv.conf
    if let Some(ref original) = state.original_resolv_conf {
        sudo_tee("/etc/resolv.conf", original)?;
        info!("Restored /etc/resolv.conf");
    }

    ConnectionState::remove()?;
    Ok(())
}

fn bring_up(params: &WgConfigParams<'_>, interface_name: &str, gw_ip: &str, gw_iface: &str) -> Result<()> {
    // 1. Create interface
    sudo_run(&["ip", "link", "add", "dev", interface_name, "type", "wireguard"])?;

    // 2. Configure wireguard (pipe private key via stdin)
    let endpoint = format!("{}:{}", params.server_ip, params.server_port);
    // wg set expects comma-separated allowed-ips without spaces
    let allowed_ips_wg = params.allowed_ips.replace(", ", ",");
    wg_set(interface_name, params.private_key, params.server_public_key, &endpoint, &allowed_ips_wg, params.preshared_key)?;

    // 3. Assign addresses
    for addr in params.addresses {
        sudo_run(&["ip", "addr", "add", addr, "dev", interface_name])?;
    }

    // 4. Bring interface up
    sudo_run(&["ip", "link", "set", "up", "dev", interface_name])?;

    // 5. Add host route for the server endpoint via original gateway
    let host_route = format!("{}/32", params.server_ip);
    sudo_run(&[
        "ip", "route", "add", &host_route, "via", gw_ip, "dev", gw_iface,
    ])?;

    // 6. Split-route trick: 0/1 + 128/1 covers all traffic without replacing the default route
    sudo_run(&["ip", "route", "add", "0.0.0.0/1", "dev", interface_name])?;
    sudo_run(&["ip", "route", "add", "128.0.0.0/1", "dev", interface_name])?;

    // 7. Set DNS
    let dns_content: String = params
        .dns_servers
        .iter()
        .map(|d| format!("nameserver {}\n", d))
        .collect();
    sudo_tee("/etc/resolv.conf", &dns_content)?;

    info!("Kernel WireGuard tunnel brought up on {}", interface_name);
    Ok(())
}

fn wg_set(interface_name: &str, private_key: &str, peer_pubkey: &str, endpoint: &str, allowed_ips: &str, preshared_key: Option<&str>) -> Result<()> {
    info!("Running: sudo wg set {} ...", interface_name);

    let args = vec![
        "wg", "set", interface_name,
        "private-key", "/dev/stdin",
        "peer", peer_pubkey,
        "allowed-ips", allowed_ips,
        "endpoint", endpoint,
    ];

    let mut child = Command::new("sudo")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::WireGuard(format!("failed to run wg set: {}", e)))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(private_key.as_bytes())
            .map_err(|e| AppError::WireGuard(format!("failed to write private key: {}", e)))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::WireGuard(format!("wg set failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::WireGuard(format!(
            "wg set failed: {}",
            stderr.trim()
        )));
    }

    // Handle preshared key as a separate wg set call if needed
    if let Some(psk) = preshared_key {
        set_preshared_key(interface_name, peer_pubkey, psk)?;
    }

    Ok(())
}

fn set_preshared_key(interface_name: &str, peer_pubkey: &str, psk: &str) -> Result<()> {
    let mut child = Command::new("sudo")
        .args([
            "wg", "set", interface_name,
            "peer", peer_pubkey,
            "preshared-key", "/dev/stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::WireGuard(format!("failed to set preshared key: {}", e)))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(psk.as_bytes())
            .map_err(|e| AppError::WireGuard(format!("failed to write preshared key: {}", e)))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::WireGuard(format!("wg set preshared-key failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::WireGuard(format!(
            "wg set preshared-key failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

fn sudo_run(args: &[&str]) -> Result<()> {
    info!("Running: sudo {}", args.join(" "));
    let output = Command::new("sudo")
        .args(args)
        .output()
        .map_err(|e| AppError::WireGuard(format!("failed to run sudo {}: {}", args[0], e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::WireGuard(format!(
            "sudo {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

fn sudo_tee(path: &str, content: &str) -> Result<()> {
    let mut child = Command::new("sudo")
        .args(["tee", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| AppError::WireGuard(format!("failed to run sudo tee {}: {}", path, e)))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(content.as_bytes())
            .map_err(|e| AppError::WireGuard(format!("failed to write to {}: {}", path, e)))?;
    }

    let status = child
        .wait()
        .map_err(|e| AppError::WireGuard(format!("sudo tee {} failed: {}", path, e)))?;

    if !status.success() {
        return Err(AppError::WireGuard(format!(
            "sudo tee {} exited with {}",
            path, status
        )));
    }

    Ok(())
}

/// Parse the default gateway IP and interface from `ip route show default`.
fn get_default_gateway() -> Result<(String, String)> {
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

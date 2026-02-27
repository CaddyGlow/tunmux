use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::thread;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use tracing::info;
use tracing::{debug, warn};

#[cfg(target_os = "linux")]
use crate::error::AppError;
use crate::error::Result;
#[cfg(target_os = "linux")]
use crate::privileged_client::PrivilegedClient;

const HANDSHAKE_WAIT_TIMEOUT: Duration = Duration::from_secs(12);
const HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Wait until `wg show` reports at least one peer with a non-empty latest handshake.
pub fn wait_for_handshake(interface: &str, dns_servers: &[String]) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface, dns_servers);
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let client = PrivilegedClient::new();
        let deadline = Instant::now() + HANDSHAKE_WAIT_TIMEOUT;
        let mut last_output = String::new();

        loop {
            match client.wg_show(interface) {
                Ok(output) => {
                    if has_latest_handshake(&output) {
                        info!(interface, "wireguard_handshake_established");
                        return Ok(());
                    }
                    last_output = output;
                }
                Err(err) => {
                    warn!(
                        interface,
                        error = %err,
                        "wireguard_handshake_poll_failed"
                    );
                }
            }

            if Instant::now() >= deadline {
                break;
            }

            nudge_tunnel_traffic(dns_servers);
            thread::sleep(HANDSHAKE_POLL_INTERVAL);
        }

        let detail = handshake_timeout_detail(&last_output);
        Err(AppError::WireGuard(format!(
            "timeout waiting for WireGuard handshake on {} within {}s{}",
            interface,
            HANDSHAKE_WAIT_TIMEOUT.as_secs(),
            detail
        )))
    }
}

#[must_use]
pub fn dns_servers_from_config(config_content: &str) -> Vec<String> {
    match super::config::parse_config(config_content) {
        Ok(parsed) => parsed
            .dns_servers
            .into_iter()
            .map(|server| server.trim().to_string())
            .filter(|server| server.parse::<IpAddr>().is_ok())
            .collect(),
        Err(err) => {
            warn!(
                error = %err,
                "wireguard_config_parse_failed_for_handshake_dns"
            );
            Vec::new()
        }
    }
}

fn has_latest_handshake(output: &str) -> bool {
    output.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("latest handshake:") && !trimmed.contains("(none)")
    })
}

fn handshake_timeout_detail(last_output: &str) -> String {
    if last_output.trim().is_empty() {
        return String::new();
    }

    let mut lines: Vec<&str> = last_output.lines().collect();
    if lines.len() > 12 {
        lines = lines.split_off(lines.len() - 12);
    }
    format!(". Last `wg show` output:\n{}", lines.join("\n"))
}

fn nudge_tunnel_traffic(dns_servers: &[String]) {
    let mut sent_any = false;

    for server in dns_servers {
        let Ok(ip) = server.parse::<IpAddr>() else {
            continue;
        };
        if nudge_ip(ip).is_ok() {
            sent_any = true;
        }
    }

    if sent_any {
        return;
    }

    // Fallback probes for profiles that omit DNS entries.
    let _ = nudge_ip(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
    let _ = nudge_ip(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
}

fn nudge_ip(ip: IpAddr) -> std::io::Result<()> {
    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(bind_addr)?;
    let target = SocketAddr::new(ip, 53);
    let _ = sock.send_to(&[0], target);
    debug!(target = %target, "wireguard_handshake_nudge_sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::has_latest_handshake;

    #[test]
    fn test_has_latest_handshake_true() {
        let sample = "peer: abc\n  latest handshake: 3 seconds\n";
        assert!(has_latest_handshake(sample));
    }

    #[test]
    fn test_has_latest_handshake_false_for_none() {
        let sample = "peer: abc\n  latest handshake: (none)\n";
        assert!(!has_latest_handshake(sample));
    }
}

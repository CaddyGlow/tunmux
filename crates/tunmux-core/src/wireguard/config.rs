use crate::error::{AppError, Result};

/// Validated IP interface MTU. The backend default remains in use when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mtu(u16);

impl Mtu {
    pub fn new(value: u16) -> Result<Self> {
        if value < 576 {
            return Err(AppError::WireGuard(format!(
                "invalid MTU {value} (must be >= 576)"
            )));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Resolve explicit CLI values before profile values, preserving backend defaults.
pub fn resolve_mtu(override_value: Option<u16>, configured: Option<Mtu>) -> Result<Option<Mtu>> {
    override_value
        .map(Mtu::new)
        .transpose()
        .map(|value| value.or(configured))
}

/// Replace the interface MTU while preserving provider and wg-quick directives.
pub fn with_mtu_override(config: &str, mtu: Mtu) -> String {
    let mut result = String::new();
    let mut in_interface = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_interface = trimmed.eq_ignore_ascii_case("[Interface]");
            result.push_str(line);
            result.push('\n');
            if in_interface {
                result.push_str(&format!("MTU = {}\n", mtu.get()));
            }
            continue;
        }
        if in_interface
            && trimmed
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("mtu"))
        {
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

/// Parsed WireGuard config with owned data.
#[derive(Debug, Clone)]
pub struct WgParsedConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: Option<Mtu>,
    pub peers: Vec<WgParsedPeer>,
}

/// A single parsed `[Peer]` section.
#[derive(Debug, Clone)]
pub struct WgParsedPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
}

impl WgParsedConfig {
    /// Extract the first peer's endpoint as `(host, port)`.
    #[must_use]
    pub fn endpoint(&self) -> Option<(&str, u16)> {
        self.peers.first()?.endpoint()
    }
}

impl WgParsedPeer {
    /// Parse this peer's endpoint as `(host, port)`.
    #[must_use]
    pub fn endpoint(&self) -> Option<(&str, u16)> {
        let ep = self.endpoint.as_deref()?;
        let colon = ep.rfind(':')?;
        let port: u16 = ep[colon + 1..].parse().ok()?;
        Some((&ep[..colon], port))
    }
}

/// Parse a WireGuard `.conf` file into a [`WgParsedConfig`].
pub fn parse_config(input: &str) -> Result<WgParsedConfig> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;
    let mut private_key: Option<String> = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut mtu = None;
    let mut peers: Vec<WgParsedPeer> = Vec::new();

    // Per-peer accumulators
    let mut peer_pubkey: Option<String> = None;
    let mut peer_psk: Option<String> = None;
    let mut peer_allowed: Option<String> = None;
    let mut peer_endpoint: Option<String> = None;

    let flush_peer = |peers: &mut Vec<WgParsedPeer>,
                      pubkey: &mut Option<String>,
                      psk: &mut Option<String>,
                      allowed: &mut Option<String>,
                      endpoint: &mut Option<String>|
     -> Result<()> {
        let public_key = pubkey
            .take()
            .ok_or_else(|| AppError::WireGuard("peer section missing PublicKey".into()))?;
        let allowed_ips = allowed
            .take()
            .ok_or_else(|| AppError::WireGuard("peer section missing AllowedIPs".into()))?;
        peers.push(WgParsedPeer {
            public_key,
            preshared_key: psk.take(),
            allowed_ips,
            endpoint: endpoint.take(),
        });
        Ok(())
    };

    for line in input.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.eq_ignore_ascii_case("[interface]") {
            if section == Section::Peer {
                flush_peer(
                    &mut peers,
                    &mut peer_pubkey,
                    &mut peer_psk,
                    &mut peer_allowed,
                    &mut peer_endpoint,
                )?;
            }
            section = Section::Interface;
            continue;
        }
        if line.eq_ignore_ascii_case("[peer]") {
            if section == Section::Peer {
                flush_peer(
                    &mut peers,
                    &mut peer_pubkey,
                    &mut peer_psk,
                    &mut peer_allowed,
                    &mut peer_endpoint,
                )?;
            }
            section = Section::Peer;
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match section {
            Section::Interface => match key.to_ascii_lowercase().as_str() {
                "mtu" => {
                    let value = value.parse::<u16>().map_err(|_| {
                        AppError::WireGuard("MTU must be an integer between 576 and 65535".into())
                    })?;
                    mtu = Some(Mtu::new(value)?);
                }
                "privatekey" => private_key = Some(value.into()),
                "address" => {
                    addresses.extend(value.split(',').map(|s| s.trim().to_owned()));
                }
                "dns" => {
                    dns_servers.extend(value.split(',').map(|s| s.trim().to_owned()));
                }
                _ => {} // ignore unknown keys
            },
            Section::Peer => match key.to_ascii_lowercase().as_str() {
                "publickey" => peer_pubkey = Some(value.into()),
                "presharedkey" => peer_psk = Some(value.into()),
                "allowedips" => peer_allowed = Some(value.into()),
                "endpoint" => peer_endpoint = Some(value.into()),
                _ => {}
            },
            Section::None => {}
        }
    }

    // Flush last peer if we were in a peer section
    if section == Section::Peer {
        flush_peer(
            &mut peers,
            &mut peer_pubkey,
            &mut peer_psk,
            &mut peer_allowed,
            &mut peer_endpoint,
        )?;
    }

    let private_key = private_key
        .ok_or_else(|| AppError::WireGuard("missing PrivateKey in [Interface]".into()))?;
    if addresses.is_empty() {
        return Err(AppError::WireGuard("missing Address in [Interface]".into()));
    }
    if peers.is_empty() {
        return Err(AppError::WireGuard("no [Peer] sections found".into()));
    }

    Ok(WgParsedConfig {
        private_key,
        addresses,
        dns_servers,
        mtu,
        peers,
    })
}

/// Owned connection parameters shared by imported and provider configurations.
/// Intentionally does not implement Debug because it contains private keys.
pub struct WgConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub server_public_key: String,
    pub server_ip: String,
    pub server_port: u16,
    pub preshared_key: Option<String>,
    pub allowed_ips: String,
}

impl WgConfig {
    /// Borrow parameters for the duration of a backend operation.
    pub fn with_params<T>(
        &self,
        mtu: Option<u16>,
        operation: impl FnOnce(&WgConfigParams<'_>) -> T,
    ) -> T {
        let addresses: Vec<_> = self.addresses.iter().map(String::as_str).collect();
        let dns_servers: Vec<_> = self.dns_servers.iter().map(String::as_str).collect();
        operation(&WgConfigParams {
            private_key: &self.private_key,
            addresses: &addresses,
            dns_servers: &dns_servers,
            mtu,
            server_public_key: &self.server_public_key,
            server_ip: &self.server_ip,
            server_port: self.server_port,
            preshared_key: self.preshared_key.as_deref(),
            allowed_ips: &self.allowed_ips,
        })
    }
}

/// Format a hostname or IP endpoint, including IPv6 brackets exactly once.
#[must_use]
pub fn format_endpoint(host: &str, port: u16) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parameters needed to generate a WireGuard config.
pub struct WgConfigParams<'a> {
    pub private_key: &'a str,
    pub addresses: &'a [&'a str],
    pub dns_servers: &'a [&'a str],
    pub mtu: Option<u16>,
    pub server_public_key: &'a str,
    pub server_ip: &'a str,
    pub server_port: u16,
    pub preshared_key: Option<&'a str>,
    pub allowed_ips: &'a str,
}

/// Generate the content of a WireGuard .conf file.
#[must_use]
pub fn generate_config(params: &WgConfigParams<'_>) -> String {
    let addresses = params.addresses.join(", ");
    let dns = params.dns_servers.join(", ");

    let mut config = format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {addresses}\n\
         DNS = {dns}\n",
        private_key = params.private_key,
        addresses = addresses,
        dns = dns,
    );

    if let Some(mtu) = params.mtu {
        config.push_str(&format!("MTU = {}\n", mtu));
    }

    config.push_str("\n[Peer]\n");
    config.push_str(&format!("PublicKey = {}\n", params.server_public_key));

    if let Some(psk) = params.preshared_key {
        config.push_str(&format!("PresharedKey = {}\n", psk));
    }

    config.push_str(&format!(
        "AllowedIPs = {allowed_ips}\n\
         Endpoint = {endpoint}\n",
        allowed_ips = params.allowed_ips,
        endpoint = format_endpoint(params.server_ip, params.server_port),
    ));

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_formatting_supports_hostnames_and_ipv6() {
        for (host, expected) in [
            ("vpn.example", "vpn.example:51820"),
            ("192.0.2.1", "192.0.2.1:51820"),
            ("2001:db8::1", "[2001:db8::1]:51820"),
            ("[2001:db8::1]", "[2001:db8::1]:51820"),
        ] {
            assert_eq!(format_endpoint(host, 51820), expected);
        }
    }

    #[test]
    fn test_owned_config_generates_parseable_ipv6_configuration() {
        let config = WgConfig {
            private_key: "private".into(),
            addresses: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
            dns_servers: vec!["10.0.0.1".into(), "fd00::1".into()],
            server_public_key: "public".into(),
            server_ip: "2001:db8::1".into(),
            server_port: 51820,
            preshared_key: Some("preshared".into()),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
        };
        let text = config.with_params(Some(1380), generate_config);
        let parsed = parse_config(&text).unwrap();
        assert_eq!(parsed.private_key, config.private_key);
        assert_eq!(parsed.addresses, config.addresses);
        assert_eq!(parsed.dns_servers, config.dns_servers);
        assert_eq!(parsed.mtu, Some(Mtu::new(1380).unwrap()));
        assert_eq!(parsed.peers[0].public_key, config.server_public_key);
        assert_eq!(parsed.peers[0].preshared_key, config.preshared_key);
        assert_eq!(parsed.peers[0].allowed_ips, config.allowed_ips);
        assert_eq!(
            parsed.peers[0].endpoint.as_deref(),
            Some("[2001:db8::1]:51820")
        );
    }

    #[test]
    fn test_mtu_validation_and_override_precedence() {
        let configured = Mtu::new(1280).unwrap();
        assert_eq!(
            resolve_mtu(Some(1420), Some(configured))
                .unwrap()
                .unwrap()
                .get(),
            1420
        );
        assert_eq!(
            resolve_mtu(None, Some(configured)).unwrap(),
            Some(configured)
        );
        assert_eq!(resolve_mtu(None, None).unwrap(), None);
        assert!(resolve_mtu(Some(575), Some(configured)).is_err());
    }

    #[test]
    fn test_config_mtu_roundtrip_and_invalid_values() {
        let input = "[Interface]\nPrivateKey = key\nAddress = 10.0.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = peer\nAllowedIPs = 0.0.0.0/0\n";
        assert_eq!(parse_config(input).unwrap().mtu.unwrap().get(), 1280);
        let overridden = with_mtu_override(input, Mtu::new(1420).unwrap());
        assert_eq!(parse_config(&overridden).unwrap().mtu.unwrap().get(), 1420);
        assert_eq!(overridden.matches("MTU =").count(), 1);
        for invalid in ["0", "575", "65536", "auto", "-1"] {
            assert!(parse_config(&input.replace("1280", invalid)).is_err());
        }
    }

    #[test]
    fn test_wg_config_generation() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
            mtu: None,
            server_public_key: "c2VydmVyLXB1YmxpYy1rZXk=",
            server_ip: "198.51.100.1",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);

        assert!(config.contains("[Interface]"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PrivateKey = cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0="));
        assert!(config.contains("Address = 10.2.0.2/32"));
        assert!(config.contains("DNS = 10.2.0.1"));
        assert!(config.contains("PublicKey = c2VydmVyLXB1YmxpYy1rZXk="));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("Endpoint = 198.51.100.1:51820"));
        assert!(!config.contains("PresharedKey"));
    }

    #[test]
    fn test_wg_config_with_preshared_key() {
        let params = WgConfigParams {
            private_key: "cHJpdmtleQ==",
            addresses: &["10.5.0.1/32", "fd7d:76ee:e68f:a993::1/128"],
            dns_servers: &["10.5.0.1", "fd7d:76ee:e68f:a993::1"],
            mtu: None,
            server_public_key: "cHVia2V5",
            server_ip: "1.2.3.4",
            server_port: 1637,
            preshared_key: Some("cHNr"),
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);

        assert!(config.contains("Address = 10.5.0.1/32, fd7d:76ee:e68f:a993::1/128"));
        assert!(config.contains("DNS = 10.5.0.1, fd7d:76ee:e68f:a993::1"));
        assert!(config.contains("PresharedKey = cHNr"));
    }

    #[test]
    fn test_wg_config_with_mtu() {
        let params = WgConfigParams {
            private_key: "priv",
            addresses: &["10.0.0.2/32"],
            dns_servers: &["10.0.0.1"],
            mtu: Some(1280),
            server_public_key: "pub",
            server_ip: "1.2.3.4",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);
        assert!(config.contains("MTU = 1280"));
    }

    #[test]
    fn test_parse_config_roundtrip() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
            mtu: None,
            server_public_key: "c2VydmVyLXB1YmxpYy1rZXk=",
            server_ip: "198.51.100.1",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);
        let parsed = parse_config(&config).unwrap();

        assert_eq!(parsed.private_key, params.private_key);
        assert_eq!(parsed.addresses, &["10.2.0.2/32"]);
        assert_eq!(parsed.dns_servers, &["10.2.0.1"]);
        assert_eq!(parsed.peers.len(), 1);

        let peer = &parsed.peers[0];
        assert_eq!(peer.public_key, params.server_public_key);
        assert!(peer.preshared_key.is_none());
        assert_eq!(peer.allowed_ips, params.allowed_ips);
        assert_eq!(peer.endpoint.as_deref(), Some("198.51.100.1:51820"));

        let (host, port) = peer.endpoint().unwrap();
        assert_eq!(host, params.server_ip);
        assert_eq!(port, params.server_port);
    }

    #[test]
    fn test_parse_config_roundtrip_with_psk_and_dual_stack() {
        let params = WgConfigParams {
            private_key: "cHJpdmtleQ==",
            addresses: &["10.5.0.1/32", "fd7d:76ee:e68f:a993::1/128"],
            dns_servers: &["10.5.0.1", "fd7d:76ee:e68f:a993::1"],
            mtu: None,
            server_public_key: "cHVia2V5",
            server_ip: "1.2.3.4",
            server_port: 1637,
            preshared_key: Some("cHNr"),
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);
        let parsed = parse_config(&config).unwrap();

        assert_eq!(parsed.private_key, "cHJpdmtleQ==");
        assert_eq!(
            parsed.addresses,
            &["10.5.0.1/32", "fd7d:76ee:e68f:a993::1/128"]
        );
        assert_eq!(parsed.dns_servers, &["10.5.0.1", "fd7d:76ee:e68f:a993::1"]);
        assert_eq!(parsed.peers.len(), 1);

        let peer = &parsed.peers[0];
        assert_eq!(peer.public_key, "cHVia2V5");
        assert_eq!(peer.preshared_key.as_deref(), Some("cHNr"));
        assert_eq!(peer.allowed_ips, "0.0.0.0/0, ::/0");

        let (host, port) = peer.endpoint().unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 1637);
    }

    #[test]
    fn test_parse_config_missing_private_key() {
        let input =
            "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = abc\nAllowedIPs = 0.0.0.0/0\n";
        let err = parse_config(input).unwrap_err();
        assert!(err.to_string().contains("PrivateKey"));
    }

    #[test]
    fn test_parse_config_no_peers() {
        let input = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.1/32\n";
        let err = parse_config(input).unwrap_err();
        assert!(err.to_string().contains("Peer"));
    }
}

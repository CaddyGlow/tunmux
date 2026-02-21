use crate::error::{AppError, Result};

/// Parsed WireGuard config with owned data.
#[derive(Debug, Clone)]
pub struct WgParsedConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
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
    let mut peers: Vec<WgParsedPeer> = Vec::new();

    // Per-peer accumulators
    let mut peer_pubkey: Option<String> = None;
    let mut peer_psk: Option<String> = None;
    let mut peer_allowed: Option<String> = None;
    let mut peer_endpoint: Option<String> = None;

    let flush_peer =
        |peers: &mut Vec<WgParsedPeer>,
         pubkey: &mut Option<String>,
         psk: &mut Option<String>,
         allowed: &mut Option<String>,
         endpoint: &mut Option<String>|
         -> Result<()> {
            let public_key = pubkey.take().ok_or_else(|| {
                AppError::WireGuard("peer section missing PublicKey".into())
            })?;
            let allowed_ips = allowed.take().ok_or_else(|| {
                AppError::WireGuard("peer section missing AllowedIPs".into())
            })?;
            peers.push(WgParsedPeer {
                public_key,
                preshared_key: psk.take(),
                allowed_ips,
                endpoint: endpoint.take(),
            });
            Ok(())
        };

    for line in input.lines() {
        let line = line.trim();
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
        return Err(AppError::WireGuard(
            "missing Address in [Interface]".into(),
        ));
    }
    if peers.is_empty() {
        return Err(AppError::WireGuard("no [Peer] sections found".into()));
    }

    Ok(WgParsedConfig {
        private_key,
        addresses,
        dns_servers,
        peers,
    })
}

/// Parameters needed to generate a WireGuard config.
pub struct WgConfigParams<'a> {
    pub private_key: &'a str,
    pub addresses: &'a [&'a str],
    pub dns_servers: &'a [&'a str],
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
         DNS = {dns}\n\
         \n\
         [Peer]\n\
         PublicKey = {server_public_key}\n",
        private_key = params.private_key,
        addresses = addresses,
        dns = dns,
        server_public_key = params.server_public_key,
    );

    if let Some(psk) = params.preshared_key {
        config.push_str(&format!("PresharedKey = {}\n", psk));
    }

    config.push_str(&format!(
        "AllowedIPs = {allowed_ips}\n\
         Endpoint = {server_ip}:{server_port}\n",
        allowed_ips = params.allowed_ips,
        server_ip = params.server_ip,
        server_port = params.server_port,
    ));

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_config_generation() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
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
    fn test_parse_config_roundtrip() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
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
        assert_eq!(
            parsed.dns_servers,
            &["10.5.0.1", "fd7d:76ee:e68f:a993::1"]
        );
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
        let input = "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = abc\nAllowedIPs = 0.0.0.0/0\n";
        let err = parse_config(input).unwrap_err();
        assert!(err.to_string().contains("PrivateKey"));
    }

    #[test]
    fn test_parse_config_no_peers() {
        let input =
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.1/32\n";
        let err = parse_config(input).unwrap_err();
        assert!(err.to_string().contains("Peer"));
    }
}

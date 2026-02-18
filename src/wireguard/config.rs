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
}

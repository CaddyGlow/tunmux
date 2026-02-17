// Generate WireGuard configuration files for Proton VPN.
//
// Reference addresses from the Python code:
// - IPv4: 10.2.0.2/32, DNS 10.2.0.1
// - IPv6: 2a07:b944::2:2/128, DNS 2a07:b944::2:1

const WG_ADDRESS: &str = "10.2.0.2/32";
const WG_DNS: &str = "10.2.0.1";
const WG_ALLOWED_IPS: &str = "0.0.0.0/0, ::/0";

/// Parameters needed to generate a WireGuard config.
pub struct WgConfigParams<'a> {
    pub private_key: &'a str,
    pub server_public_key: &'a str,
    pub server_ip: &'a str,
    pub server_port: u16,
}

/// Generate the content of a WireGuard .conf file.
#[must_use]
pub fn generate_config(params: &WgConfigParams<'_>) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {address}\n\
         DNS = {dns}\n\
         \n\
         [Peer]\n\
         PublicKey = {server_public_key}\n\
         AllowedIPs = {allowed_ips}\n\
         Endpoint = {server_ip}:{server_port}\n",
        private_key = params.private_key,
        address = WG_ADDRESS,
        dns = WG_DNS,
        server_public_key = params.server_public_key,
        allowed_ips = WG_ALLOWED_IPS,
        server_ip = params.server_ip,
        server_port = params.server_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_config_generation() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            server_public_key: "c2VydmVyLXB1YmxpYy1rZXk=",
            server_ip: "198.51.100.1",
            server_port: 51820,
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
    }
}

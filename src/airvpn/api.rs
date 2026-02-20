use tracing::warn;

use crate::error::{AppError, Result};

use super::crypto::AirVpnCrypto;
use super::models::{AirManifest, AirServer, AirSession, AirWgKey, AirWgMode};

const BOOTSTRAP_URLS: &[&str] = &[
    "http://54.93.175.114",
    "http://54.246.124.152",
    "http://54.225.156.17",
    "http://95.211.138.143",
];

const SOFTWARE_ID: &str = "EddieDesktop_2.24.6";
const VERSION_INT: &str = "296";
const USER_AGENT: &str = "Eddie/2.24.6";

pub struct AirVpnClient {
    http: reqwest::Client,
    crypto: AirVpnCrypto,
}

impl AirVpnClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::AirVpnApi(format!("HTTP client error: {}", e)))?;
        let crypto = AirVpnCrypto::new()?;
        Ok(Self { http, crypto })
    }

    /// Send an encrypted API request and return the decrypted XML string.
    async fn request(&self, params: &[(&str, &str)]) -> Result<String> {
        let (s_param, d_param, session) = self.crypto.encrypt_request(params)?;

        let form = [("s", s_param.as_str()), ("d", d_param.as_str())];

        let mut last_err = None;

        for url in BOOTSTRAP_URLS {
            match self.http.post(*url).form(&form).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "<unreadable>".to_string());
                        warn!(
                            status = ?status.as_u16(),
                            url = ?*url,
                            body = ?body, "airvpn_bootstrap_http_error");
                        last_err =
                            Some(AppError::AirVpnApi(format!("HTTP {} from {}", status, url)));
                        continue;
                    }

                    let body = match resp.bytes().await {
                        Ok(body) => body,
                        Err(e) => {
                            last_err =
                                Some(AppError::AirVpnApi(format!("failed to read response: {}", e)));
                            continue;
                        }
                    };

                    // Response is raw AES-CBC ciphertext (same key/IV as request)
                    match self.crypto.decrypt_response(&body, &session) {
                        Ok(xml) => return Ok(xml),
                        Err(e) => {
                            warn!(
                                url = ?*url,
                                error = ?e.to_string(),
                                "airvpn_bootstrap_decrypt_error"
                            );
                            last_err = Some(e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(AppError::AirVpnApi(format!(
                        "request to {} failed: {}",
                        url, e
                    )));
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AppError::AirVpnApi("all bootstrap URLs failed".into())))
    }

    /// Authenticate and fetch user info (act=user).
    pub async fn login(&self, username: &str, password: &str) -> Result<AirSession> {
        let arch = system_arch();
        let system = system_code();
        let params = [
            ("act", "user"),
            ("login", username),
            ("password", password),
            ("software", SOFTWARE_ID),
            ("version", VERSION_INT),
            ("arch", arch.as_str()),
            ("system", system.as_str()),
        ];

        let xml = self.request(&params).await?;
        parse_user_response(&xml, username, password)
    }

    /// Fetch the server manifest (act=manifest).
    pub async fn fetch_manifest(&self, username: &str, password: &str) -> Result<AirManifest> {
        let arch = system_arch();
        let system = system_code();
        let params = [
            ("act", "manifest"),
            ("login", username),
            ("password", password),
            ("software", SOFTWARE_ID),
            ("version", VERSION_INT),
            ("arch", arch.as_str()),
            ("system", system.as_str()),
            ("ts", "0"),
        ];

        let xml = self.request(&params).await?;
        parse_manifest_response(&xml)
    }
}

/// Return normalized architecture string matching Eddie's convention.
fn system_arch() -> String {
    let arch = std::env::consts::ARCH;
    match arch {
        "x86_64" | "amd64" => "x64".to_string(),
        "x86" | "i686" => "x86".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

/// Return system code matching Eddie's convention: "<os>_<arch>".
fn system_code() -> String {
    let os = std::env::consts::OS; // "linux", "macos", "windows"
    format!("{}_{}", os, system_arch())
}

fn parse_user_response(xml: &str, username: &str, password: &str) -> Result<AirSession> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| AppError::Xml(format!("user response: {}", e)))?;

    let root = doc.root_element();

    // Check for error
    if let Some(msg) = root.attribute("message") {
        if !msg.is_empty() {
            return Err(AppError::AirVpnApi(msg.to_string()));
        }
    }

    // Check login attribute exists (indicates successful auth)
    if root.attribute("login").is_none() {
        return Err(AppError::Auth("AirVPN authentication failed".into()));
    }

    let wg_public_key = root.attribute("wg_public_key").unwrap_or("").to_string();

    // Parse WireGuard keys from <keys><key .../></keys>
    let mut keys = Vec::new();
    for node in root.descendants() {
        if node.has_tag_name("key") {
            keys.push(AirWgKey {
                name: node.attribute("name").unwrap_or("default").to_string(),
                wg_private_key: node.attribute("wg_private_key").unwrap_or("").to_string(),
                wg_ipv4: node.attribute("wg_ipv4").unwrap_or("").to_string(),
                wg_ipv6: node.attribute("wg_ipv6").unwrap_or("").to_string(),
                wg_dns_ipv4: node.attribute("wg_dns_ipv4").unwrap_or("").to_string(),
                wg_dns_ipv6: node.attribute("wg_dns_ipv6").unwrap_or("").to_string(),
                wg_preshared: node.attribute("wg_preshared").unwrap_or("").to_string(),
            });
        }
    }

    if keys.is_empty() {
        return Err(AppError::AirVpnApi(
            "no WireGuard keys in user response".into(),
        ));
    }

    Ok(AirSession {
        username: username.to_string(),
        password: password.to_string(),
        wg_public_key,
        keys,
        api_key: None,
    })
}

fn parse_manifest_response(xml: &str) -> Result<AirManifest> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| AppError::Xml(format!("manifest response: {}", e)))?;

    let root = doc.root_element();

    // Check for error attribute
    if let Some(err) = root.attribute("error") {
        if !err.is_empty() {
            return Err(AppError::AirVpnApi(err.to_string()));
        }
    }

    let mut servers = Vec::new();
    let mut wg_modes = Vec::new();
    let mut api_urls = Vec::new();

    for node in root.descendants() {
        if node.has_tag_name("server")
            && node
                .parent_element()
                .map(|p| p.has_tag_name("servers"))
                .unwrap_or(false)
        {
            let ips_str = node.attribute("ips_entry").unwrap_or("");
            let ips_entry: Vec<String> = ips_str
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect();

            servers.push(AirServer {
                name: node.attribute("name").unwrap_or("").to_string(),
                ips_entry,
                country_code: node.attribute("country_code").unwrap_or("").to_string(),
                location: node.attribute("location").unwrap_or("").to_string(),
                bandwidth: node
                    .attribute("bw")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                bandwidth_max: node
                    .attribute("bw_max")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1),
                users: node
                    .attribute("users")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                users_max: node
                    .attribute("users_max")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
                group: node.attribute("group").unwrap_or("").to_string(),
            });
        }

        if node.has_tag_name("mode") {
            let mode_type = node.attribute("type").unwrap_or("");
            if mode_type == "wireguard" {
                let protocol = node.attribute("protocol").unwrap_or("UDP").to_string();
                let port: u16 = node
                    .attribute("port")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1637);
                let entry_index: u16 = node
                    .attribute("entry_index")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);

                wg_modes.push(AirWgMode {
                    protocol,
                    port,
                    entry_index,
                });
            }
        }

        if node.has_tag_name("url") {
            if let Some(addr) = node.attribute("address") {
                if !addr.is_empty() {
                    api_urls.push(addr.to_string());
                }
            }
        }
    }

    Ok(AirManifest {
        servers,
        wg_modes,
        api_urls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_response() {
        let xml = r#"<user login="testuser" wg_public_key="PUBKEY123">
            <keys>
                <key name="default"
                     wg_private_key="PRIVKEY"
                     wg_ipv4="10.5.0.1/32"
                     wg_ipv6="fd7d::1/128"
                     wg_dns_ipv4="10.5.0.1"
                     wg_dns_ipv6="fd7d::1"
                     wg_preshared="PRESHARED" />
            </keys>
        </user>"#;

        let session = parse_user_response(xml, "testuser", "pass").unwrap();
        assert_eq!(session.username, "testuser");
        assert_eq!(session.wg_public_key, "PUBKEY123");
        assert_eq!(session.keys.len(), 1);
        assert_eq!(session.keys[0].wg_private_key, "PRIVKEY");
        assert_eq!(session.keys[0].wg_ipv4, "10.5.0.1/32");
        assert_eq!(session.keys[0].wg_preshared, "PRESHARED");
    }

    #[test]
    fn test_parse_user_response_error() {
        let xml = r#"<user message="Invalid credentials" />"#;
        let result = parse_user_response(xml, "test", "pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_manifest_response() {
        let xml = r#"<manifest time="123">
            <servers>
                <server name="Castor" ips_entry="1.2.3.4,5.6.7.8"
                        country_code="NL" location="Amsterdam"
                        bw="50000" bw_max="100000"
                        users="15" users_max="200" group="earth" />
                <server name="Vega" ips_entry="9.10.11.12"
                        country_code="US" location="New York"
                        bw="30000" bw_max="100000"
                        users="50" users_max="200" group="earth" />
            </servers>
            <modes>
                <mode type="wireguard" protocol="UDP" port="1637" entry_index="0" />
                <mode type="wireguard" protocol="UDP" port="443" entry_index="0" />
                <mode type="openvpn" protocol="UDP" port="443" entry_index="0" />
            </modes>
            <urls>
                <url address="http://10.0.0.1" />
            </urls>
        </manifest>"#;

        let manifest = parse_manifest_response(xml).unwrap();
        assert_eq!(manifest.servers.len(), 2);
        assert_eq!(manifest.servers[0].name, "Castor");
        assert_eq!(manifest.servers[0].ips_entry, vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(manifest.servers[0].country_code, "NL");
        assert_eq!(manifest.servers[0].bandwidth, 50000);
        assert_eq!(manifest.wg_modes.len(), 2); // only wireguard modes
        assert_eq!(manifest.wg_modes[0].port, 1637);
        assert_eq!(manifest.api_urls, vec!["http://10.0.0.1"]);
    }
}

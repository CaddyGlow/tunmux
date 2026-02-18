use serde::{Deserialize, Serialize};

/// Persisted AirVPN session. Stores credentials because AirVPN has no token
/// auth -- the encrypted API always requires username+password.
#[derive(Debug, Serialize, Deserialize)]
pub struct AirSession {
    pub username: String,
    pub password: String,
    pub wg_public_key: String,
    pub keys: Vec<AirWgKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirWgKey {
    pub name: String,
    pub wg_private_key: String,
    pub wg_ipv4: String,
    pub wg_ipv6: String,
    pub wg_dns_ipv4: String,
    pub wg_dns_ipv6: String,
    pub wg_preshared: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirServer {
    pub name: String,
    pub ips_entry: Vec<String>,
    pub country_code: String,
    pub location: String,
    pub bandwidth: i64,
    pub bandwidth_max: i64,
    pub users: i64,
    pub users_max: i64,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirWgMode {
    pub protocol: String,
    pub port: u16,
    pub entry_index: u16,
}

#[derive(Debug, Clone)]
pub struct ForwardedPort {
    pub port: u16,
    pub pool: u16,
    pub protocol: String,
    pub local_port: u16,
    pub enabled: bool,
    pub device: String,
    pub ddns: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AirManifest {
    pub servers: Vec<AirServer>,
    pub wg_modes: Vec<AirWgMode>,
    pub api_urls: Vec<String>,
}

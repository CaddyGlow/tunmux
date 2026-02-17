#![allow(dead_code)]

use serde::Deserialize;
use std::fmt;

/// Feature bitmask values from the Proton API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFeature {
    SecureCore = 1,
    Tor = 2,
    P2P = 4,
    Streaming = 8,
    Ipv6 = 16,
}

/// Tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Free = 0,
    Plus = 2,
    Pm = 3,
}

impl Tier {
    #[must_use]
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Tier::Free,
            2 => Tier::Plus,
            3 => Tier::Pm,
            _ => Tier::Plus,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Free => write!(f, "Free"),
            Tier::Plus => write!(f, "Plus"),
            Tier::Pm => write!(f, "PM"),
        }
    }
}

/// Physical server within a logical server
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PhysicalServer {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "EntryIP")]
    pub entry_ip: String,
    #[serde(rename = "ExitIP")]
    pub exit_ip: String,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "X25519PublicKey")]
    pub x25519_public_key: Option<String>,
}

impl PhysicalServer {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.status == 1
    }
}

/// Location nested object
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Location {
    pub lat: Option<f64>,
    pub long: Option<f64>,
}

/// Logical server from GET /vpn/v1/logicals
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogicalServer {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    pub entry_country: String,
    pub exit_country: String,
    pub host_country: Option<String>,
    pub domain: String,
    pub tier: i32,
    pub features: i32,
    pub region: Option<String>,
    pub city: Option<String>,
    pub score: f64,
    pub load: i32,
    pub status: i32,
    pub servers: Vec<PhysicalServer>,
    pub location: Option<Location>,
}

impl LogicalServer {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.status == 1
    }

    #[must_use]
    pub fn has_feature(&self, feature: ServerFeature) -> bool {
        self.features & (feature as i32) != 0
    }

    #[must_use]
    pub fn tier_enum(&self) -> Tier {
        Tier::from_i32(self.tier)
    }

    /// Get the first enabled physical server with a WireGuard key
    #[must_use]
    pub fn best_physical(&self) -> Option<&PhysicalServer> {
        self.servers
            .iter()
            .find(|s| s.is_enabled() && s.x25519_public_key.is_some())
    }

    #[must_use]
    pub fn feature_tags(&self) -> String {
        let mut tags = Vec::new();
        if self.has_feature(ServerFeature::SecureCore) {
            tags.push("SC");
        }
        if self.has_feature(ServerFeature::Tor) {
            tags.push("TOR");
        }
        if self.has_feature(ServerFeature::P2P) {
            tags.push("P2P");
        }
        if self.has_feature(ServerFeature::Streaming) {
            tags.push("STREAM");
        }
        tags.join(",")
    }
}

impl fmt::Display for LogicalServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tier = self.tier_enum();
        let features = self.feature_tags();
        let features_col = if features.is_empty() {
            String::new()
        } else {
            format!(" [{}]", features)
        };
        write!(
            f,
            "{:<16} {:>2}  {:>3}%  {:.1}  {}{}",
            self.name, self.exit_country, self.load, self.score, tier, features_col
        )
    }
}

/// API response wrapper for GET /vpn/v1/logicals
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogicalsResponse {
    pub code: i64,
    pub logical_servers: Vec<LogicalServer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_filtering() {
        let servers = vec![
            make_server("US#1", "US", 0, 4, 30, 1.0, 1),  // Free, P2P
            make_server("US#2", "US", 2, 0, 50, 2.0, 1),  // Plus
            make_server("CH#1", "CH", 0, 0, 20, 0.5, 1),  // Free
            make_server("JP#1", "JP", 2, 1, 10, 0.3, 0),  // Plus, SecureCore, disabled
        ];

        // Filter by country
        let us: Vec<_> = servers.iter().filter(|s| s.exit_country == "US").collect();
        assert_eq!(us.len(), 2);

        // Filter free only
        let free: Vec<_> = servers.iter().filter(|s| s.tier == 0).collect();
        assert_eq!(free.len(), 2);

        // Filter P2P
        let p2p: Vec<_> = servers
            .iter()
            .filter(|s| s.has_feature(ServerFeature::P2P))
            .collect();
        assert_eq!(p2p.len(), 1);
        assert_eq!(p2p[0].name, "US#1");

        // Filter enabled only
        let enabled: Vec<_> = servers.iter().filter(|s| s.is_enabled()).collect();
        assert_eq!(enabled.len(), 3);

        // Sort by score (lower is better)
        let mut sorted = servers.clone();
        sorted.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
        assert_eq!(sorted[0].name, "JP#1");
    }

    fn make_server(
        name: &str,
        country: &str,
        tier: i32,
        features: i32,
        load: i32,
        score: f64,
        status: i32,
    ) -> LogicalServer {
        LogicalServer {
            id: format!("id-{}", name),
            name: name.to_string(),
            entry_country: country.to_string(),
            exit_country: country.to_string(),
            host_country: None,
            domain: format!("{}.protonvpn.net", name.to_lowercase()),
            tier,
            features,
            region: None,
            city: None,
            score,
            load,
            status,
            servers: vec![PhysicalServer {
                id: format!("phys-{}", name),
                entry_ip: "1.2.3.4".to_string(),
                exit_ip: "1.2.3.5".to_string(),
                domain: format!("{}.protonvpn.net", name.to_lowercase()),
                status: 1,
                x25519_public_key: Some(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                ),
            }],
            location: Some(Location {
                lat: Some(0.0),
                long: Some(0.0),
            }),
        }
    }
}

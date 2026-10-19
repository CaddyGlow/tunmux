use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config;
use crate::error::Result;

use super::backend::WgBackend;

/// Reserved instance name for the traditional all-traffic VPN mode.
pub const DIRECT_INSTANCE: &str = "_direct";

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionState {
    pub instance_name: String,
    pub provider: String,
    pub interface_name: String,
    pub backend: WgBackend,
    pub server_endpoint: String,
    pub server_display_name: String,
    pub original_gateway_ip: Option<String>,
    pub original_gateway_iface: Option<String>,
    pub original_resolv_conf: Option<String>,
    pub namespace_name: Option<String>,
    pub proxy_pid: Option<u32>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Base64-encoded WireGuard public key of the remote peer (local-proxy mode).
    #[serde(default)]
    pub peer_public_key: Option<String>,
    /// Base64-encoded WireGuard public key of this client (local-proxy mode).
    #[serde(default)]
    pub local_public_key: Option<String>,
    /// Virtual IP/CIDR strings assigned to this client (local-proxy mode).
    #[serde(default)]
    pub virtual_ips: Vec<String>,
    /// WireGuard persistent keepalive interval in seconds (local-proxy mode).
    #[serde(default)]
    pub keepalive_secs: Option<u16>,
}

impl ConnectionState {
    /// Save to ~/.config/tunmux/connections/<instance>.json
    pub fn save(&self) -> Result<()> {
        config::ensure_connections_dir()?;
        let path = config::connections_dir().join(format!("{}.json", self.instance_name));
        let json = serde_json::to_string_pretty(self)?;
        atomic_write(&path, json.as_bytes())?;
        info!( path = ?path.display().to_string(), "connection_state_saved");
        Ok(())
    }

    /// Load a specific instance.
    pub fn load(instance: &str) -> Result<Option<Self>> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(&path)?;
        parse_or_quarantine(&path, &json)
    }

    /// Load all active connections.
    pub fn load_all() -> Result<Vec<Self>> {
        let dir = config::connections_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut connections = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let json = fs::read_to_string(&path)?;
                if let Some(state) = parse_or_quarantine(&path, &json)? {
                    connections.push(state);
                }
            }
        }
        Ok(connections)
    }

    /// Remove a specific instance's state file.
    pub fn remove(instance: &str) -> Result<()> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        if path.exists() {
            fs::remove_file(&path)?;
            info!( instance = ?instance, "connection_state_removed");
        }
        Ok(())
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn parse_or_quarantine(path: &Path, json: &str) -> Result<Option<ConnectionState>> {
    match serde_json::from_str(json) {
        Ok(state) => Ok(Some(state)),
        Err(error) => {
            let quarantine = path.with_extension(format!("corrupt-{}", rand::random::<u64>()));
            fs::rename(path, &quarantine)?;
            tracing::warn!(path = %path.display(), quarantine = %quarantine.display(), %error, "connection_state_quarantined");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_atomic_write_replaces_restrictively() {
        let path = std::env::temp_dir().join(format!("tunmux-state-{}", rand::random::<u64>()));
        atomic_write(&path, b"old").unwrap();
        atomic_write(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_corrupt_state_is_preserved_in_quarantine() {
        let dir = std::env::temp_dir().join(format!("tunmux-state-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("broken.json");
        fs::write(&path, b"broken").unwrap();
        assert!(parse_or_quarantine(&path, "broken").unwrap().is_none());
        assert!(!path.exists());
        let preserved = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read(preserved).unwrap(), b"broken");
        fs::remove_dir_all(dir).unwrap();
    }
}

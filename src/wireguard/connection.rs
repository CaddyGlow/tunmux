use std::fs;
use std::os::unix::fs::PermissionsExt;

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
}

impl ConnectionState {
    /// Save to ~/.config/tunmux/connections/<instance>.json
    pub fn save(&self) -> Result<()> {
        config::ensure_connections_dir()?;
        let path = config::connections_dir().join(format!("{}.json", self.instance_name));
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, &json)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        info!("Connection state saved to {}", path.display());
        Ok(())
    }

    /// Load a specific instance.
    pub fn load(instance: &str) -> Result<Option<Self>> {
        migrate_legacy_state()?;
        let path = config::connections_dir().join(format!("{}.json", instance));
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(&path)?;
        let state: Self = serde_json::from_str(&json)?;
        Ok(Some(state))
    }

    /// Load all active connections.
    pub fn load_all() -> Result<Vec<Self>> {
        migrate_legacy_state()?;
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
                match serde_json::from_str::<Self>(&json) {
                    Ok(state) => connections.push(state),
                    Err(e) => {
                        tracing::warn!("skipping {}: {}", path.display(), e);
                    }
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
            info!("Connection state removed for {}", instance);
        }
        Ok(())
    }

    /// Check if an instance name is already in use.
    #[must_use]
    pub fn exists(instance: &str) -> bool {
        config::connections_dir()
            .join(format!("{}.json", instance))
            .exists()
    }
}

/// Migrate legacy single connection.json to connections/ directory.
fn migrate_legacy_state() -> Result<()> {
    let legacy = config::connection_state_path();
    let new_dir = config::connections_dir();
    if legacy.exists() && !new_dir.exists() {
        config::ensure_connections_dir()?;

        let json = fs::read_to_string(&legacy)?;
        // Try to parse as old format (no instance_name field) and add it
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&json) {
            if let Some(obj) = value.as_object_mut() {
                if !obj.contains_key("instance_name") {
                    obj.insert(
                        "instance_name".to_string(),
                        serde_json::Value::String(DIRECT_INSTANCE.to_string()),
                    );
                }
                if !obj.contains_key("server_display_name") {
                    let display = obj
                        .get("server_endpoint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    obj.insert(
                        "server_display_name".to_string(),
                        serde_json::Value::String(display),
                    );
                }
                // Ensure new optional fields exist
                for key in ["namespace_name", "proxy_pid", "socks_port", "http_port"] {
                    if !obj.contains_key(key) {
                        obj.insert(key.to_string(), serde_json::Value::Null);
                    }
                }
            }
            let migrated = serde_json::to_string_pretty(&value)?;
            let dest = new_dir.join(format!("{}.json", DIRECT_INSTANCE));
            fs::write(&dest, &migrated)?;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
            fs::remove_file(&legacy)?;
            info!("Migrated connection.json to connections/{}.json", DIRECT_INSTANCE);
        }
    }
    Ok(())
}

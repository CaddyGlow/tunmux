use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config;
use crate::error::Result;

use super::backend::WgBackend;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionState {
    pub provider: String,
    pub interface_name: String,
    pub backend: WgBackend,
    pub server_endpoint: String,
    pub original_gateway_ip: Option<String>,
    pub original_gateway_iface: Option<String>,
    pub original_resolv_conf: Option<String>,
}

impl ConnectionState {
    pub fn save(&self) -> Result<()> {
        config::ensure_app_config_dir()?;
        let path = config::connection_state_path();
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, &json)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        info!("Connection state saved to {}", path.display());
        Ok(())
    }

    pub fn load() -> Result<Option<Self>> {
        let path = config::connection_state_path();
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(&path)?;
        let state: Self = serde_json::from_str(&json)?;
        Ok(Some(state))
    }

    pub fn remove() -> Result<()> {
        let path = config::connection_state_path();
        if path.exists() {
            fs::remove_file(&path)?;
            info!("Connection state removed");
        }
        Ok(())
    }
}

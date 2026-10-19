use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config;
use crate::error::{AppError, Result};
use crate::shared::persistence::write_private_atomic;

use super::backend::WgBackend;

/// Reserved instance name for the traditional all-traffic VPN mode.
pub const DIRECT_INSTANCE: &str = "_direct";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    #[cfg(not(target_os = "android"))]
    #[serde(default)]
    pub source_spec: Option<crate::automation::ConnectionSpec>,
    #[serde(default)]
    pub allow_lan: bool,
    pub instance_name: String,
    #[serde(default)]
    pub session_id: Option<String>,
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
        let mut state = self.clone();
        #[cfg(not(target_os = "android"))]
        if state.backend == WgBackend::LocalProxy && state.session_id.is_none() {
            state.session_id = Some(
                crate::local_proxy_control::session_id(&state.instance_name)
                    .map_err(|e| AppError::Other(e.to_string()))?,
            );
        }
        #[cfg(not(target_os = "android"))]
        if let Some(spec) = crate::automation::active_spec() {
            state.allow_lan = spec.allow_lan();
            state.source_spec = Some(spec);
        }
        let json = serde_json::to_string_pretty(&state)?;
        write_private_atomic(&path, json.as_bytes())?;
        info!( path = ?path.display().to_string(), "connection_state_saved");
        Ok(())
    }

    /// Load a specific instance.
    pub fn load(instance: &str) -> Result<Option<Self>> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        load_path(&path)
    }

    /// Load valid saved connections without changing unreadable or corrupt records.
    pub fn load_all() -> Result<Vec<Self>> {
        Self::load_all_with_corrupt().map(|(states, _)| states)
    }

    /// Include corrupt record paths so read-only callers can report unknown state.
    pub fn load_all_with_corrupt() -> Result<(Vec<Self>, Vec<PathBuf>)> {
        load_directory(&config::connections_dir())
    }

    /// Preserve a corrupt record during explicit connection preparation/recovery.
    /// Existing quarantine receipts keep blocking retries until recovery is resolved and
    /// receipts removed, or an explicitly repaired valid JSON record supersedes them.
    /// This does not establish ownership or authorize replacing a live session.
    pub fn quarantine_corrupt(instance: &str) -> Result<Option<PathBuf>> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        quarantine_corrupt_path(&path)
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

fn load_path(path: &Path) -> Result<Option<ConnectionState>> {
    let json = match fs::read_to_string(path) {
        Ok(json) => json,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    serde_json::from_str(&json).map(Some).map_err(|error| {
        AppError::Other(format!(
            "Corrupt connection state {}: {error}",
            path.display()
        ))
    })
}

fn load_directory(dir: &Path) -> Result<(Vec<ConnectionState>, Vec<PathBuf>)> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), Vec::new()))
        }
        Err(error) => return Err(error.into()),
    };
    let mut states = Vec::new();
    let mut corrupt = Vec::new();
    let mut receipts = Vec::new();
    let mut valid_paths = std::collections::HashSet::new();
    for entry in entries {
        let path = entry?.path();
        if is_quarantine_receipt(&path) {
            receipts.push(path);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let json = fs::read_to_string(&path)?;
        match serde_json::from_str(&json) {
            Ok(state) => {
                valid_paths.insert(path.clone());
                states.push(state);
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "connection_state_corrupt");
                corrupt.push(path);
            }
        }
    }
    corrupt.extend(
        receipts
            .into_iter()
            .filter(|receipt| !valid_paths.contains(&receipt.with_extension("json"))),
    );
    Ok((states, corrupt))
}

fn is_quarantine_receipt(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.starts_with("corrupt-"))
}

fn existing_quarantine(path: &Path) -> Result<Option<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let receipt = entry?.path();
        if is_quarantine_receipt(&receipt) && receipt.with_extension("json") == path {
            return Ok(Some(receipt));
        }
    }
    Ok(None)
}

fn quarantine_corrupt_path(path: &Path) -> Result<Option<PathBuf>> {
    match load_path(path) {
        Ok(Some(_)) => Ok(None),
        Ok(None) => existing_quarantine(path),
        Err(AppError::Other(_)) => {
            let quarantine =
                path.with_extension(format!("corrupt-{:032x}", rand::random::<u128>()));
            fs::rename(path, &quarantine)?;
            if let Some(parent) = path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            tracing::warn!(path = %path.display(), quarantine = %quarantine.display(), "connection_state_quarantined");
            Ok(Some(quarantine))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_atomic_write_replaces_restrictively() {
        let path = std::env::temp_dir().join(format!("tunmux-state-{}", rand::random::<u64>()));
        write_private_atomic(&path, b"old").unwrap();
        write_private_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_legacy_state_loads_without_session_identity_and_valid_state_is_not_quarantined() {
        let dir = std::env::temp_dir().join(format!("tunmux-state-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("legacy.json");
        let json = serde_json::json!({
            "instance_name": "legacy", "provider": "test", "interface_name": "wg0",
            "backend": "kernel", "server_endpoint": "192.0.2.1:51820",
            "server_display_name": "test", "original_gateway_ip": null,
            "original_gateway_iface": null, "original_resolv_conf": null,
            "namespace_name": null, "proxy_pid": null, "socks_port": null, "http_port": null
        });
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(load_path(&path).unwrap().unwrap().session_id.is_none());
        assert!(quarantine_corrupt_path(&path).unwrap().is_none());
        assert!(path.exists());
        let receipt = path.with_extension("corrupt-previous");
        fs::write(&receipt, b"old broken state").unwrap();
        assert!(quarantine_corrupt_path(&path).unwrap().is_none());
        let (states, corrupt) = load_directory(&dir).unwrap();
        assert_eq!(states.len(), 1);
        assert!(corrupt.is_empty());
        assert!(receipt.exists()); // Repair supersedes receipts without deleting evidence.
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_corrupt_state_load_is_read_only_and_explicit_quarantine_preserves_bytes() {
        let dir = std::env::temp_dir().join(format!("tunmux-state-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("broken.json");
        fs::write(&path, b"broken").unwrap();
        assert!(load_path(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        let (states, corrupt) = load_directory(&dir).unwrap();
        assert!(states.is_empty());
        assert_eq!(corrupt, vec![path.clone()]);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let preserved = quarantine_corrupt_path(&path).unwrap().unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&preserved).unwrap(), b"broken");
        // A retry must keep blocking rather than interpreting the moved JSON as absence.
        assert_eq!(
            quarantine_corrupt_path(&path).unwrap(),
            Some(preserved.clone())
        );
        let (states, corrupt) = load_directory(&dir).unwrap();
        assert!(states.is_empty());
        assert_eq!(corrupt, vec![preserved.clone()]);
        fs::remove_file(preserved).unwrap();
        assert!(quarantine_corrupt_path(&path).unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }
}

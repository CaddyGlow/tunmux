use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{AppError, Result};

const APP_DIR: &str = "tunmux";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Proton,
    AirVpn,
}

impl Provider {
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Provider::Proton => "proton",
            Provider::AirVpn => "airvpn",
        }
    }
}

/// Root config directory: ~/.config/tunmux/
#[must_use]
pub fn app_config_dir() -> PathBuf {
    xdg_config_home().join(APP_DIR)
}

/// Provider-specific config directory: ~/.config/tunmux/<provider>/
#[must_use]
pub fn config_dir(provider: Provider) -> PathBuf {
    app_config_dir().join(provider.dir_name())
}

/// Session file path: ~/.config/tunmux/<provider>/session.json
#[must_use]
pub fn session_path(provider: Provider) -> PathBuf {
    config_dir(provider).join("session.json")
}

/// Connection state file (provider-neutral): ~/.config/tunmux/connection.json
#[must_use]
pub fn connection_state_path() -> PathBuf {
    app_config_dir().join("connection.json")
}

fn xdg_config_home() -> PathBuf {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(config)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        PathBuf::from("/tmp")
    }
}

pub fn ensure_config_dir(provider: Provider) -> Result<()> {
    let dir = config_dir(provider);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn ensure_app_config_dir() -> Result<()> {
    let dir = app_config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn save_session<T: Serialize>(provider: Provider, session: &T) -> Result<()> {
    ensure_config_dir(provider)?;
    let path = session_path(provider);
    let json = serde_json::to_string_pretty(session)?;
    fs::write(&path, &json)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    tracing::info!("Session saved to {}", path.display());
    Ok(())
}

pub fn load_session<T: DeserializeOwned>(provider: Provider) -> Result<T> {
    let path = session_path(provider);
    if !path.exists() {
        return Err(AppError::NotLoggedIn);
    }
    let json = fs::read_to_string(&path)?;
    let session: T = serde_json::from_str(&json)?;
    Ok(session)
}

pub fn delete_session(provider: Provider) -> Result<()> {
    let path = session_path(provider);
    if path.exists() {
        fs::remove_file(&path)?;
        tracing::info!("Session deleted");
    }
    Ok(())
}

/// Save an arbitrary file into a provider's config directory.
pub fn save_provider_file(provider: Provider, filename: &str, data: &[u8]) -> Result<()> {
    ensure_config_dir(provider)?;
    let path = config_dir(provider).join(filename);
    fs::write(&path, data)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Load an arbitrary file from a provider's config directory.
pub fn load_provider_file(provider: Provider, filename: &str) -> Result<Option<Vec<u8>>> {
    let path = config_dir(provider).join(filename);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(&path)?))
}

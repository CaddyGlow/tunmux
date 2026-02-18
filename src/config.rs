use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

const APP_DIR: &str = "tunmux";

// ── TOML config ────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub proton: ProtonConfig,
    pub airvpn: AirVpnConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub backend: String,
    pub credential_store: String,
    pub proxy: bool,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            backend: "auto".to_string(),
            credential_store: "file".to_string(),
            proxy: false,
            socks_port: None,
            http_port: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProtonConfig {
    pub default_country: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AirVpnConfig {
    pub default_country: Option<String>,
    pub default_device: Option<String>,
}

pub fn load_config() -> AppConfig {
    let path = app_config_dir().join("config.toml");
    match fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!("failed to parse {}: {}", path.display(), e);
            AppConfig::default()
        }),
        Err(_) => AppConfig::default(),
    }
}

// ── Provider enum ──────────────────────────────────────────────

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

// ── Path helpers ───────────────────────────────────────────────

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

/// Connections directory: ~/.config/tunmux/connections/
#[must_use]
pub fn connections_dir() -> PathBuf {
    app_config_dir().join("connections")
}

pub fn ensure_connections_dir() -> Result<()> {
    let dir = connections_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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


// ── Session persistence (file + keyring dispatch) ──────────────

pub fn save_session<T: Serialize>(provider: Provider, session: &T, config: &AppConfig) -> Result<()> {
    let json = serde_json::to_string_pretty(session)?;

    #[cfg(feature = "keyring")]
    if config.general.credential_store == "keyring" {
        return save_session_keyring(provider, &json);
    }

    let _ = config;
    save_session_file(provider, &json)
}

pub fn load_session<T: DeserializeOwned>(provider: Provider, config: &AppConfig) -> Result<T> {
    #[cfg(feature = "keyring")]
    if config.general.credential_store == "keyring" {
        return load_session_keyring(provider);
    }

    let _ = config;
    load_session_file(provider)
}

pub fn delete_session(provider: Provider, config: &AppConfig) -> Result<()> {
    #[cfg(feature = "keyring")]
    if config.general.credential_store == "keyring" {
        return delete_session_keyring(provider);
    }

    let _ = config;
    delete_session_file(provider)
}

fn save_session_file(provider: Provider, json: &str) -> Result<()> {
    ensure_config_dir(provider)?;
    let path = session_path(provider);
    fs::write(&path, json)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    tracing::info!("Session saved to {}", path.display());
    Ok(())
}

fn load_session_file<T: DeserializeOwned>(provider: Provider) -> Result<T> {
    let path = session_path(provider);
    if !path.exists() {
        return Err(AppError::NotLoggedIn);
    }
    let json = fs::read_to_string(&path)?;
    let session: T = serde_json::from_str(&json)?;
    Ok(session)
}

fn delete_session_file(provider: Provider) -> Result<()> {
    let path = session_path(provider);
    if path.exists() {
        fs::remove_file(&path)?;
        tracing::info!("Session deleted");
    }
    Ok(())
}

// ── Keyring helpers (feature-gated) ────────────────────────────

#[cfg(feature = "keyring")]
fn save_session_keyring(provider: Provider, json: &str) -> Result<()> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| AppError::Other(format!("keyring error: {}", e)))?;
    entry
        .set_password(json)
        .map_err(|e| AppError::Other(format!("keyring set error: {}", e)))?;
    tracing::info!("Session saved to keyring ({})", provider.dir_name());
    Ok(())
}

#[cfg(feature = "keyring")]
fn load_session_keyring<T: DeserializeOwned>(provider: Provider) -> Result<T> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| AppError::Other(format!("keyring error: {}", e)))?;
    let json = entry
        .get_password()
        .map_err(|_| AppError::NotLoggedIn)?;
    let session: T = serde_json::from_str(&json)?;
    Ok(session)
}

#[cfg(feature = "keyring")]
fn delete_session_keyring(provider: Provider) -> Result<()> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| AppError::Other(format!("keyring error: {}", e)))?;
    let _ = entry.delete_credential();
    tracing::info!("Session deleted from keyring");
    Ok(())
}

// ── Provider file helpers (unchanged) ──────────────────────────

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

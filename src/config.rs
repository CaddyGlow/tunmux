use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
    pub mullvad: MullvadConfig,
    pub ivpn: IvpnConfig,
    pub wgconf: WgconfConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub backend: String,
    pub credential_store: CredentialStore,
    pub proxy_access_log: bool,
    pub privileged_transport: PrivilegedTransport,
    pub privileged_autostart: bool,
    pub privileged_autostart_timeout_ms: u64,
    pub privileged_authorized_group: String,
    pub privileged_autostop_mode: PrivilegedAutostopMode,
    pub privileged_autostop_timeout_ms: u64,
    pub hooks: HookConfig,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            backend: default_backend().to_string(),
            credential_store: default_credential_store(),
            proxy_access_log: false,
            privileged_transport: PrivilegedTransport::Socket,
            privileged_autostart: true,
            privileged_autostart_timeout_ms: 5000,
            privileged_authorized_group: String::new(),
            privileged_autostop_mode: PrivilegedAutostopMode::Never,
            privileged_autostop_timeout_ms: 30000,
            hooks: HookConfig::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HookConfig {
    pub ifup: Vec<String>,
    pub ifdown: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStore {
    #[default]
    File,
    Keyring,
    AndroidKeystore,
    Auto,
}

fn default_backend() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "userspace"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "kernel"
    }
    #[cfg(not(unix))]
    {
        "wg-quick"
    }
}

fn default_credential_store() -> CredentialStore {
    #[cfg(target_os = "android")]
    {
        CredentialStore::Auto
    }
    #[cfg(not(target_os = "android"))]
    {
        CredentialStore::File
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedAutostopMode {
    #[default]
    Never,
    Command,
    Timeout,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedTransport {
    #[default]
    Socket,
    Stdio,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProtonConfig {
    pub default_country: Option<String>,
    pub hooks: HookConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AirVpnConfig {
    pub default_country: Option<String>,
    pub default_device: Option<String>,
    pub hooks: HookConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MullvadConfig {
    pub default_country: Option<String>,
    pub hooks: HookConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct IvpnConfig {
    pub default_country: Option<String>,
    pub hooks: HookConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WgconfConfig {
    pub hooks: HookConfig,
}

pub fn load_config() -> AppConfig {
    let path = app_config_dir().join("config.toml");
    match fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!(
                path = ?path.display().to_string(),
                error = ?e.to_string(), "config_parse_failed");
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
    Mullvad,
    Ivpn,
    Wgconf,
}

impl Provider {
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Provider::Proton => "proton",
            Provider::AirVpn => "airvpn",
            Provider::Mullvad => "mullvad",
            Provider::Ivpn => "ivpn",
            Provider::Wgconf => "wgconf",
        }
    }
}

// ── Path helpers ───────────────────────────────────────────────

/// Root config directory: ~/.config/tunmux/
#[must_use]
pub fn app_config_dir() -> PathBuf {
    xdg_config_home().join(APP_DIR)
}

#[must_use]
pub fn privileged_socket_path() -> PathBuf {
    privileged_socket_dir().join("ctl.sock")
}

#[must_use]
pub fn privileged_socket_dir() -> PathBuf {
    PathBuf::from("/var/run/tunmux")
}

pub fn ensure_privileged_socket_dir() -> Result<()> {
    let dir = privileged_socket_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

#[must_use]
pub fn privileged_runtime_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/var/db/tunmux");
    #[cfg(not(target_os = "macos"))]
    return PathBuf::from("/var/lib/tunmux");
}

pub fn ensure_privileged_runtime_dir() -> Result<()> {
    let dir = privileged_runtime_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[must_use]
pub fn privileged_wg_dir() -> PathBuf {
    privileged_runtime_dir().join("wg")
}

#[must_use]
pub fn privileged_proxy_dir() -> PathBuf {
    privileged_runtime_dir().join("proxy")
}

pub fn ensure_privileged_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

/// Connections directory: ~/.config/tunmux/connections/
#[must_use]
pub fn connections_dir() -> PathBuf {
    app_config_dir().join("connections")
}

/// User-owned proxy runtime directory: ~/.config/tunmux/proxy/
/// Used by local-proxy daemon for pid/log files (no root needed).
#[must_use]
pub fn user_proxy_dir() -> PathBuf {
    app_config_dir().join("proxy")
}

pub fn ensure_user_proxy_dir() -> crate::error::Result<()> {
    let dir = user_proxy_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

pub fn save_session<T: Serialize>(
    provider: Provider,
    session: &T,
    config: &AppConfig,
) -> Result<()> {
    let json = serde_json::to_string_pretty(session)?;
    crate::shared::credential_store::save_session_json(provider, &json, config)
}

pub fn load_session<T: DeserializeOwned>(provider: Provider, config: &AppConfig) -> Result<T> {
    let json = crate::shared::credential_store::load_session_json(provider, config)?
        .ok_or(AppError::NotLoggedIn)?;
    let session: T = serde_json::from_str(&json)?;
    Ok(session)
}

pub fn delete_session(provider: Provider, config: &AppConfig) -> Result<()> {
    crate::shared::credential_store::delete_session_json(provider, config)
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

#[cfg(test)]
mod tests {
    use super::{
        delete_session, load_session, save_session, session_path, AppConfig, CredentialStore,
        Provider,
    };
    use crate::error::AppError;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "tunmux-test-{}-{}-{}",
            name,
            std::process::id(),
            now
        ))
    }

    #[test]
    fn test_load_missing_maps_to_not_logged_in() {
        let _guard = env_lock().lock().expect("test env lock poisoned");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let dir = unique_test_dir("load-missing");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut config = AppConfig::default();
        config.general.credential_store = CredentialStore::File;

        let result = load_session::<serde_json::Value>(Provider::Proton, &config);
        assert!(matches!(result, Err(AppError::NotLoggedIn)));

        if let Some(value) = previous {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_delete_session_is_idempotent() {
        let _guard = env_lock().lock().expect("test env lock poisoned");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let dir = unique_test_dir("delete-idempotent");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut config = AppConfig::default();
        config.general.credential_store = CredentialStore::File;

        delete_session(Provider::Proton, &config).expect("first delete should succeed");
        delete_session(Provider::Proton, &config).expect("second delete should succeed");

        if let Some(value) = previous {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_backend_roundtrip_save_load_delete() {
        let _guard = env_lock().lock().expect("test env lock poisoned");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let dir = unique_test_dir("file-roundtrip");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut config = AppConfig::default();
        config.general.credential_store = CredentialStore::File;

        let session = serde_json::json!({"access_token":"abc123","refresh_token":"def456"});
        save_session(Provider::Proton, &session, &config).expect("save should succeed");

        let loaded: serde_json::Value =
            load_session(Provider::Proton, &config).expect("load should succeed");
        assert_eq!(loaded, session);

        delete_session(Provider::Proton, &config).expect("delete should succeed");
        let missing = load_session::<serde_json::Value>(Provider::Proton, &config);
        assert!(matches!(missing, Err(AppError::NotLoggedIn)));

        if let Some(value) = previous {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_backend_load_corrupted_json_fails() {
        let _guard = env_lock().lock().expect("test env lock poisoned");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let dir = unique_test_dir("file-corrupted-json");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut config = AppConfig::default();
        config.general.credential_store = CredentialStore::File;

        let path = session_path(Provider::Proton);
        let parent = path.parent().expect("session path has parent");
        std::fs::create_dir_all(parent).expect("create provider dir");
        std::fs::write(&path, "{not valid json").expect("write corrupted json");

        let result = load_session::<serde_json::Value>(Provider::Proton, &config);
        assert!(matches!(result, Err(AppError::Json(_))));

        if let Some(value) = previous {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::error::{AppError, Result};
use crate::models::session::Session;

const CONFIG_DIR: &str = "protonvpn-rs";

#[must_use]
pub fn config_dir() -> PathBuf {
    dirs_next().join(CONFIG_DIR)
}

#[must_use]
pub fn session_path() -> PathBuf {
    config_dir().join("session.json")
}

fn dirs_next() -> PathBuf {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(config)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        PathBuf::from("/tmp")
    }
}

pub fn ensure_config_dir() -> Result<()> {
    let dir = config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn save_session(session: &Session) -> Result<()> {
    ensure_config_dir()?;
    let path = session_path();
    let json = serde_json::to_string_pretty(session)?;
    fs::write(&path, &json)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    tracing::info!("Session saved to {}", path.display());
    Ok(())
}

pub fn load_session() -> Result<Session> {
    let path = session_path();
    if !path.exists() {
        return Err(AppError::NotLoggedIn);
    }
    let json = fs::read_to_string(&path)?;
    let session: Session = serde_json::from_str(&json)?;
    Ok(session)
}

pub fn delete_session() -> Result<()> {
    let path = session_path();
    if path.exists() {
        fs::remove_file(&path)?;
        tracing::info!("Session deleted");
    }
    Ok(())
}

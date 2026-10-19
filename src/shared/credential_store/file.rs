use std::fs;

use crate::config::{self, Provider};
use crate::error::Result;

const BACKEND: &str = "file";

pub(super) fn save(provider: Provider, payload_json: &str) -> Result<()> {
    config::ensure_config_dir(provider)?;
    let path = config::session_path(provider);
    crate::shared::persistence::write_private_atomic(&path, payload_json.as_bytes())
        .map_err(|e| super::failure(provider, BACKEND, "save", &e.to_string()))?;
    tracing::info!( path = ?path.display().to_string(), "session_saved");
    Ok(())
}

pub(super) fn load(provider: Provider) -> Result<Option<String>> {
    let path = config::session_path(provider);
    match fs::read_to_string(&path) {
        Ok(json) => Ok(Some(json)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(super::failure(provider, BACKEND, "load", &e.to_string())),
    }
}

pub(super) fn delete(provider: Provider) -> Result<()> {
    let path = config::session_path(provider);
    match fs::remove_file(&path) {
        Ok(()) => {
            tracing::info!( path = ?path.display().to_string(), "session_deleted");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(super::failure(provider, BACKEND, "delete", &e.to_string())),
    }
}

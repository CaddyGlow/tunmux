use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{self, Provider};
use crate::error::Result;

const BACKEND: &str = "file";

pub(super) fn save(provider: Provider, payload_json: &str) -> Result<()> {
    config::ensure_config_dir(provider)?;
    let path = config::session_path(provider);
    let tmp_path = temp_path(provider, &path)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| super::failure(provider, BACKEND, "save", &e.to_string()))?;

    file.write_all(payload_json.as_bytes())
        .map_err(|e| super::failure(provider, BACKEND, "save", &e.to_string()))?;
    file.sync_all()
        .map_err(|e| super::failure(provider, BACKEND, "save", &e.to_string()))?;
    drop(file);

    fs::rename(&tmp_path, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        super::failure(provider, BACKEND, "save", &e.to_string())
    })?;

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
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

fn temp_path(provider: Provider, path: &Path) -> Result<std::path::PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        super::misconfigured(
            provider,
            BACKEND,
            "save",
            "session path has no parent directory",
        )
    })?;
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(
        ".session.json.tmp-{}-{}",
        std::process::id(),
        now_nanos
    )))
}

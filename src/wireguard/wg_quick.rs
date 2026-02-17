use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::info;

use crate::config;
use crate::error::{AppError, Result};

const INTERFACE_NAME: &str = "proton0";

/// Write the WireGuard config and bring up the interface.
pub fn up(config_content: &str) -> Result<()> {
    let path = write_config(config_content)?;
    run_wg_quick("up", &path)
}

/// Bring down the WireGuard interface and remove the config.
pub fn down() -> Result<()> {
    let path = config_file_path();
    run_wg_quick("down", &path)?;
    remove_config()
}

/// Check if the WireGuard interface is currently active.
#[must_use]
pub fn is_active() -> bool {
    Command::new("ip")
        .args(["link", "show", INTERFACE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn write_config(content: &str) -> Result<PathBuf> {
    config::ensure_config_dir()?;
    let path = config_file_path();

    fs::write(&path, content)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    info!("WireGuard config written to {}", path.display());
    Ok(path)
}

fn remove_config() -> Result<()> {
    let path = config_file_path();
    if path.exists() {
        fs::remove_file(&path)?;
        info!("WireGuard config removed");
    }
    Ok(())
}

fn run_wg_quick(action: &str, conf_path: &Path) -> Result<()> {
    let conf_str = conf_path.to_string_lossy();
    info!("Running: sudo wg-quick {} {}", action, conf_str);
    let output = Command::new("sudo")
        .args(["wg-quick", action, &conf_str])
        .output()
        .map_err(|e| AppError::WireGuard(format!("failed to run wg-quick: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::WireGuard(format!(
            "wg-quick {} failed: {}",
            action,
            stderr.trim()
        )));
    }

    info!("wg-quick {} succeeded", action);
    Ok(())
}

fn config_file_path() -> PathBuf {
    config::config_dir().join(format!("{}.conf", INTERFACE_NAME))
}

#![cfg(target_os = "linux")]

use crate::error::{AppError, Result};
use std::path::Path;

use crate::privileged_client::PrivilegedClient;
use nix::sched::CloneFlags;
use tracing::info;

/// Create a network namespace. If a stale namespace with the same name
/// exists (e.g., from a previous failed run), it is deleted first.
pub fn create(name: &str) -> Result<()> {
    if exists(name) {
        info!("Removing stale namespace {}", name);
        let _ = PrivilegedClient::new().namespace_delete(name);
    }
    PrivilegedClient::new().namespace_create(name)
}

/// Delete a network namespace (best-effort, ignores if absent).
pub fn delete(name: &str) -> Result<()> {
    if !exists(name) {
        return Ok(());
    }
    let _ = PrivilegedClient::new().namespace_delete(name);
    Ok(())
}

/// Check if a network namespace exists.
#[must_use]
pub fn exists(name: &str) -> bool {
    Path::new(&format!("/run/netns/{}", name)).exists()
}

/// Execute a command inside a network namespace.
pub fn exec(namespace: &str, args: &[&str]) -> Result<()> {
    PrivilegedClient::new().netns_exec(namespace, args)
}

/// Delete namespace runtime files under /etc/netns.
pub fn remove_namespace_dir(namespace: &str) -> Result<()> {
    let path = format!("/etc/netns/{}", namespace);
    if Path::new(&path).exists() {
        PrivilegedClient::new().remove_dir_all(&path)?;
    }
    Ok(())
}

/// Enter a network namespace on the current thread via setns().
pub fn enter(name: &str) -> Result<()> {
    let path = format!("/run/netns/{}", name);
    let file = std::fs::File::open(&path)
        .map_err(|e| AppError::Namespace(format!("failed to open {}: {}", path, e)))?;
    nix::sched::setns(&file, CloneFlags::CLONE_NEWNET)
        .map_err(|e| AppError::Namespace(format!("setns failed for {}: {}", name, e)))?;
    info!("Entered network namespace {}", name);
    Ok(())
}

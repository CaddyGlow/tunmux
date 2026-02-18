use std::path::Path;
use std::process::{Command, Stdio};

use nix::sched::CloneFlags;
use tracing::info;

use crate::error::{AppError, Result};

/// Create a network namespace. If a stale namespace with the same name
/// exists (e.g., from a previous failed run), it is deleted first.
pub fn create(name: &str) -> Result<()> {
    if exists(name) {
        info!("Removing stale namespace {}", name);
        let _ = sudo_run(&["ip", "netns", "del", name]);
    }
    sudo_run(&["ip", "netns", "add", name])
}

/// Delete a network namespace (best-effort, ignores if absent).
pub fn delete(name: &str) -> Result<()> {
    if !exists(name) {
        return Ok(());
    }
    let _ = sudo_run(&["ip", "netns", "del", name]);
    Ok(())
}

/// Check if a network namespace exists.
#[must_use]
pub fn exists(name: &str) -> bool {
    Path::new(&format!("/run/netns/{}", name)).exists()
}

/// Move a network interface into a namespace.
pub fn move_interface(interface: &str, namespace: &str) -> Result<()> {
    sudo_run(&["ip", "link", "set", interface, "netns", namespace])
}

/// Execute a command inside a network namespace, returning its stdout.
pub fn exec(namespace: &str, args: &[&str]) -> Result<String> {
    sudo_run_output(&["ip", "netns", "exec", namespace], args)
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

fn sudo_run(args: &[&str]) -> Result<()> {
    info!("Running: sudo {}", args.join(" "));
    let output = Command::new("sudo")
        .args(args)
        .output()
        .map_err(|e| AppError::Namespace(format!("failed to run sudo {}: {}", args[0], e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Namespace(format!(
            "sudo {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

fn sudo_run_output(prefix: &[&str], extra: &[&str]) -> Result<String> {
    let mut all_args: Vec<&str> = prefix.to_vec();
    all_args.extend_from_slice(extra);

    info!("Running: sudo {}", all_args.join(" "));
    let output = Command::new("sudo")
        .args(&all_args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            AppError::Namespace(format!("failed to run sudo {}: {}", all_args.join(" "), e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Namespace(format!(
            "sudo {} failed: {}",
            all_args.join(" "),
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

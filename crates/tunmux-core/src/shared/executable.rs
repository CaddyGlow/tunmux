//! The tunmux CLI executable that helpers and daemons are spawned from.
//!
//! The CLI re-runs itself (`privileged --serve`, proxy daemons). A program
//! embedding the library, such as tunmux-gui, is not the CLI, so it names the
//! tunmux binary with [`set_cli_executable`] before connecting.

use std::path::PathBuf;
use std::sync::OnceLock;

static CLI_EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();

/// Spawn helpers from `path` instead of the current executable.
/// Returns false if it was already set; the first value is kept.
pub fn set_cli_executable(path: PathBuf) -> bool {
    CLI_EXECUTABLE.set(path).is_ok()
}

/// The configured CLI executable, or the current executable.
pub fn cli_executable() -> std::io::Result<PathBuf> {
    match CLI_EXECUTABLE.get() {
        Some(path) => Ok(path.clone()),
        None => std::env::current_exe(),
    }
}

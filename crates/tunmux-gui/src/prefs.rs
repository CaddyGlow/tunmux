//! Settings only the GUI uses, kept in ~/.config/tunmux/gui.toml, and the
//! XDG autostart entry for "Start at login".

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::Mode;

pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Mode selected when the window opens.
    pub default_mode: Mode,
    /// The login entry starts the GUI in the tray, without a window.
    pub start_in_tray: bool,
    pub close_to_tray: bool,
    /// Level for tunmux and tunmux-gui logs; RUST_LOG takes precedence.
    pub log_level: String,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            default_mode: Mode::Direct,
            start_in_tray: true,
            close_to_tray: true,
            log_level: "info".into(),
        }
    }
}

fn path() -> PathBuf {
    tunmux_core::config::app_config_dir().join("gui.toml")
}

impl Prefs {
    /// The saved preferences, or the defaults when the file is missing or
    /// does not parse.
    pub fn load() -> Self {
        let path = path();
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).unwrap_or_else(|error| {
                tracing::warn!(path = %path.display(), %error, "gui_prefs_invalid");
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "gui_prefs_unreadable");
                Self::default()
            }
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, toml::to_string(self)?)?;
        Ok(())
    }

    /// Logging filter for this level, or `None` when RUST_LOG is set.
    pub fn log_filter(&self) -> Option<String> {
        if std::env::var_os("RUST_LOG").is_some() || !LOG_LEVELS.contains(&&*self.log_level) {
            return None;
        }
        let level = &self.log_level;
        Some(format!("warn,tunmux={level},tunmux_gui={level}"))
    }
}

fn autostart_path() -> PathBuf {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    config.join("autostart").join("tunmux-gui.desktop")
}

pub fn start_at_login() -> bool {
    autostart_path().is_file()
}

/// Write or remove the autostart entry. It runs this executable, so it
/// follows the binary that was running when the box was ticked.
pub fn set_start_at_login(enabled: bool, hidden: bool) -> anyhow::Result<()> {
    let path = autostart_path();
    if !enabled {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => return Ok(()),
        }
    }
    let exe = std::env::current_exe()?;
    let exec = desktop_quote(&exe.to_string_lossy());
    let args = if hidden { " --hidden" } else { "" };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        &path,
        format!(
            "[Desktop Entry]\nType=Application\nName=tunmux\n\
             Comment=WireGuard VPN tunnels in the system tray\n\
             Exec={exec}{args}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        ),
    )?;
    Ok(())
}

/// Quote an Exec argument as the desktop entry spec requires.
fn desktop_quote(arg: &str) -> String {
    let mut out = String::from("\"");
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    // The file format itself unescapes backslashes once more.
    out.replace('\\', "\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_quoting_escapes_twice() {
        assert_eq!(
            desktop_quote("/usr/bin/tunmux-gui"),
            "\"/usr/bin/tunmux-gui\""
        );
        assert_eq!(desktop_quote("/a b/$x"), "\"/a b/\\\\$x\"");
    }

    #[test]
    fn prefs_round_trip_and_fill_defaults() {
        let prefs = Prefs {
            default_mode: Mode::LocalProxy,
            start_in_tray: false,
            close_to_tray: false,
            log_level: "debug".into(),
        };
        let text = toml::to_string(&prefs).expect("serialize prefs");
        assert_eq!(toml::from_str::<Prefs>(&text).expect("parse prefs"), prefs);
        let partial: Prefs = toml::from_str("close_to_tray = false").expect("parse partial");
        assert_eq!(partial.default_mode, Mode::Direct);
        assert!(!partial.close_to_tray);
    }
}

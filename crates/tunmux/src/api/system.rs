//! Settings kept in config.toml, and the state of the privileged helper.

use std::path::{Path, PathBuf};

use crate::config::AppConfig;

/// The `[general]` settings a front-end may change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSettings {
    /// `kernel`, `wg-quick` or `userspace`.
    pub backend: String,
    pub proxy_access_log: bool,
}

impl GeneralSettings {
    #[must_use]
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            backend: config.general.backend.clone(),
            proxy_access_log: config.general.proxy_access_log,
        }
    }
}

#[must_use]
pub fn config_path() -> PathBuf {
    crate::config::app_config_dir().join("config.toml")
}

/// Write `settings` into config.toml, keeping its other keys, comments and
/// layout. A file that does not parse is left untouched.
pub fn save_general_settings(settings: &GeneralSettings) -> anyhow::Result<()> {
    save_general_settings_at(&config_path(), settings)
}

fn save_general_settings_at(path: &Path, settings: &GeneralSettings) -> anyhow::Result<()> {
    use anyhow::Context;

    crate::wireguard::backend::WgBackend::from_str_arg(&settings.backend)?;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("{} does not parse; fix it first", path.display()))?;
    let general = doc
        .entry("general")
        .or_insert_with(toml_edit::table)
        .as_table_mut()
        .with_context(|| format!("[general] in {} is not a table", path.display()))?;
    set_keeping_comment(general, "backend", settings.backend.as_str().into());
    set_keeping_comment(
        general,
        "proxy_access_log",
        settings.proxy_access_log.into(),
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::shared::persistence::write_private_atomic(path, doc.to_string().as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    tracing::info!(path = %path.display(), "config_general_saved");
    Ok(())
}

fn set_keeping_comment(table: &mut toml_edit::Table, key: &str, value: toml_edit::Value) {
    match table.get_mut(key).and_then(toml_edit::Item::as_value_mut) {
        Some(old) => {
            let decor = old.decor().clone();
            *old = value;
            *old.decor_mut() = decor;
        }
        None => table[key] = toml_edit::Item::Value(value),
    }
}

/// State of the privileged helper, probed without starting it.
#[derive(Debug, Clone)]
pub struct SystemStatus {
    pub helper_socket: PathBuf,
    /// A helper process is running (see [`helper_process_running`]).
    pub helper_running: bool,
    /// The helper is installed as a system service (socket activated);
    /// otherwise it is started with elevation when needed.
    pub service_installed: Result<bool, String>,
}

#[must_use]
pub fn system_status() -> SystemStatus {
    SystemStatus {
        helper_socket: crate::config::privileged_socket_path(),
        helper_running: helper_process_running(),
        service_installed: crate::service::system_service_installed().map_err(|e| format!("{e:#}")),
    }
}

/// Whether a `tunmux privileged --serve` process exists. Read from /proc
/// rather than by connecting, which would start a socket-activated helper.
#[cfg(target_os = "linux")]
#[must_use]
pub fn helper_process_running() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            return false;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        // Match the name loosely: packaging may wrap the binary.
        let program = args
            .first()
            .and_then(|a| a.rsplit(|b| *b == b'/').next())
            .unwrap_or_default();
        program.windows(6).any(|w| w == b"tunmux")
            && args.iter().any(|a| *a == b"privileged")
            && args.iter().any(|a| *a == b"--serve")
    })
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn helper_process_running() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_general_settings_keeps_other_keys_and_comments() {
        let dir = crate::config::tests::unique_test_dir("api-settings");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "# mine\n[general]\nbackend = \"kernel\" # keep\ncredential_store = \"file\"\n\n[airvpn]\ndefault_country = \"ch\"\n",
        )
        .expect("write config");

        let settings = GeneralSettings {
            backend: "userspace".into(),
            proxy_access_log: true,
        };
        save_general_settings_at(&path, &settings).expect("save settings");

        let text = std::fs::read_to_string(&path).expect("read config");
        assert!(text.starts_with("# mine\n"));
        assert!(text.contains("backend = \"userspace\" # keep"));
        assert!(text.contains("credential_store = \"file\""));
        assert!(text.contains("default_country = \"ch\""));
        let config: AppConfig = toml::from_str(&text).expect("config parses");
        assert_eq!(GeneralSettings::from_config(&config), settings);

        assert!(save_general_settings_at(
            &path,
            &GeneralSettings {
                backend: "bogus".into(),
                proxy_access_log: false
            }
        )
        .is_err());
        std::fs::write(&path, "[general\n").expect("write broken config");
        assert!(save_general_settings_at(&path, &settings).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read config"),
            "[general\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

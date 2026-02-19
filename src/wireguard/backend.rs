use std::fmt;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WgBackend {
    WgQuick,
    Userspace,
    Kernel,
}

impl WgBackend {
    /// Parse a CLI argument string into a backend choice.
    pub fn from_str_arg(s: &str) -> anyhow::Result<Self> {
        match s {
            "auto" => Ok(Self::auto_detect()),
            "wg-quick" => Ok(Self::WgQuick),
            "userspace" | "user-space" => Ok(Self::Userspace),
            "kernel" => Ok(Self::Kernel),
            other => anyhow::bail!(
                "unknown backend {:?} (expected auto, wg-quick, userspace, kernel)",
                other
            ),
        }
    }

    /// Pick a backend automatically.
    ///
    /// - macOS: userspace
    /// - Other platforms: wg-quick when available, otherwise kernel
    #[must_use]
    pub fn auto_detect() -> Self {
        if cfg!(target_os = "macos") {
            Self::Userspace
        } else if wg_quick_on_path() {
            Self::WgQuick
        } else {
            Self::Kernel
        }
    }
}

impl fmt::Display for WgBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WgQuick => write!(f, "wg-quick"),
            Self::Userspace => write!(f, "userspace"),
            Self::Kernel => write!(f, "kernel"),
        }
    }
}

fn wg_quick_on_path() -> bool {
    Command::new("which")
        .arg("wg-quick")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

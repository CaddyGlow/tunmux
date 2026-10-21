use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WgBackend {
    WgQuick,
    Userspace,
    Kernel,
    LocalProxy,
}

impl WgBackend {
    /// Parse a CLI argument string into a backend choice.
    pub fn from_str_arg(s: &str) -> anyhow::Result<Self> {
        match s {
            "wg-quick" => Ok(Self::WgQuick),
            "userspace" => Ok(Self::Userspace),
            "kernel" => Ok(Self::Kernel),
            "local-proxy" => Ok(Self::LocalProxy),
            other => anyhow::bail!(
                "unknown backend {:?} (expected wg-quick, userspace, kernel, local-proxy)",
                other
            ),
        }
    }
}

impl fmt::Display for WgBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WgQuick => write!(f, "wg-quick"),
            Self::Userspace => write!(f, "userspace"),
            Self::Kernel => write!(f, "kernel"),
            Self::LocalProxy => write!(f, "local-proxy"),
        }
    }
}

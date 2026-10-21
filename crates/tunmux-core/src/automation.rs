//! Connection identity shared between the CLI's autoconnect controller and
//! the connect paths that record it in connection state.
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionSpec {
    pub provider: String,
    pub args: Vec<String>,
    pub options: BTreeMap<String, Vec<String>>,
}
impl ConnectionSpec {
    pub fn allow_lan(&self) -> bool {
        self.flag("allow_lan")
    }
    fn flag(&self, key: &str) -> bool {
        self.options.get(key).is_some_and(|v| v == &["true"])
    }
    pub fn is_proxy(&self) -> bool {
        self.flag("proxy") || self.flag("local_proxy")
    }
    pub fn matches(&self, other: &Self) -> bool {
        self.provider == other.provider && self.options == other.options
    }
}
static ACTIVE: OnceLock<Mutex<Option<ConnectionSpec>>> = OnceLock::new();
static MANAGED_INSTANCE: OnceLock<String> = OnceLock::new();
pub fn managed_instance() -> Option<&'static str> {
    MANAGED_INSTANCE.get().map(String::as_str)
}
/// Run the connect being prepared under a controller-chosen instance name.
pub fn set_managed_instance(instance: String) {
    let _ = MANAGED_INSTANCE.set(instance);
}
/// Record the identity of the connect being prepared in this process.
pub fn set_active(spec: ConnectionSpec) {
    *ACTIVE.get_or_init(Default::default).lock().unwrap() = Some(spec);
}
pub fn active_spec() -> Option<ConnectionSpec> {
    ACTIVE.get_or_init(Default::default).lock().unwrap().clone()
}

/// Errors worth retrying later: network failures, server errors and failed handshakes.
pub fn is_transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if cause.downcast_ref::<reqwest::Error>().is_some_and(|e|e.is_connect() || e.is_timeout() || e.status().is_some_and(|s|s.is_server_error())) { return true; }
        if cause.downcast_ref::<std::io::Error>().is_some_and(|e|matches!(e.kind(), std::io::ErrorKind::TimedOut|std::io::ErrorKind::ConnectionRefused|std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::NetworkUnreachable)) { return true; }
        matches!(cause.downcast_ref::<crate::error::AppError>(),Some(crate::error::AppError::WireGuard(message)) if message.contains("handshake") && !message.contains("cleanup incomplete"))
    })
}

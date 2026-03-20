#[cfg(not(target_os = "android"))]
pub mod connection_ops;
pub mod credential_store;
pub mod crypto;
pub mod hooks;
pub mod latency;
pub mod util;

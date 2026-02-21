pub mod backend;
#[allow(dead_code)]
pub mod config;
pub mod connection;
pub mod proxy_tunnel;

#[cfg(not(target_os = "android"))]
pub mod kernel;
#[cfg(target_os = "linux")]
pub(crate) mod netlink;
#[cfg(not(target_os = "android"))]
pub mod userspace;
#[cfg(not(target_os = "android"))]
pub mod wg_quick;

// tunmux library crate
//
// Exports portable modules for use by the Android JNI crate and any
// future library consumers. Desktop helpers are excluded on Android; network
// namespaces and namespace proxies have additional Linux and feature guards.

// Provider-agnostic infrastructure
#[cfg(not(target_os = "android"))]
pub mod api;
pub mod config;
pub mod error;
pub mod logging;
pub mod shared;

// Provider modules (handlers inside each mod are cfg-gated for Android)
#[cfg(feature = "airvpn")]
pub mod airvpn;
#[cfg(feature = "ivpn")]
pub mod ivpn;
#[cfg(feature = "mullvad")]
pub mod mullvad;
#[cfg(feature = "proton")]
pub mod proton;
#[cfg(feature = "wgconf")]
pub mod wgconf;

// WireGuard config and connection state (portable);
// backend implementations (kernel, wg_quick, userspace) are cfg-gated inside wireguard/mod.rs
pub mod wireguard;

// Privileged API types (portable serde types only, no unix deps)
pub mod privileged_api;

// Local-proxy helpers (spawn/stop user-owned daemon, signal handling) -- non-Android only
#[cfg(not(target_os = "android"))]
pub mod local_proxy;

// Network namespaces: real implementation on Linux, stub on other non-Android platforms
#[cfg(all(not(target_os = "android"), target_os = "linux"))]
pub mod netns;
#[cfg(all(not(target_os = "android"), not(target_os = "linux")))]
#[path = "netns_stub.rs"]
pub mod netns;
#[cfg(not(target_os = "android"))]
pub mod privileged;
#[cfg(not(target_os = "android"))]
pub mod privileged_client;
// Proxy daemon: real implementation on Linux with the proxy feature, stub otherwise
#[cfg(all(not(target_os = "android"), feature = "proxy", target_os = "linux"))]
#[path = "proxy/mod.rs"]
pub mod proxy;
#[cfg(all(
    not(target_os = "android"),
    not(all(feature = "proxy", target_os = "linux"))
))]
#[path = "proxy_stub.rs"]
pub mod proxy;

#[cfg(not(target_os = "android"))]
pub mod userspace_helper;

#[cfg(not(target_os = "android"))]
pub mod automation;
#[cfg(not(target_os = "android"))]
pub mod network_changes;
#[cfg(not(target_os = "android"))]
pub mod service;

#[cfg(not(target_os = "android"))]
pub mod local_proxy_control;

#[cfg(not(target_os = "android"))]
mod lan;

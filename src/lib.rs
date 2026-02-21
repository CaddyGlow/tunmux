// tunmux library crate
//
// Exports portable modules for use by the Android JNI crate and any
// future library consumers. Linux-only modules (privileged daemon,
// network namespaces, proxy) are gated behind cfg(not(target_os = "android")).

// Provider-agnostic infrastructure
pub mod cli;
pub mod config;
pub mod error;
pub mod logging;

// Proton-specific API/model/crypto layers (portable; handlers are gated below)
pub mod api;
pub mod crypto;
pub mod models;

// Provider modules (handlers inside each mod are cfg-gated for Android)
pub mod airvpn;
pub mod ivpn;
pub mod mullvad;
pub mod proton;

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

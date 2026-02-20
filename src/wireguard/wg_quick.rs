use crate::config;
use crate::error::Result;
use crate::privileged_api::WgQuickAction;
use crate::privileged_client::PrivilegedClient;
use tracing::{debug, info};

/// Write the WireGuard config and bring up the interface.
/// Returns the effective interface name used (may differ from the requested name on macOS,
/// where TUN interfaces must be named `utunN` and the number is assigned by the kernel).
pub fn up(
    config_content: &str,
    interface_name: &str,
    provider: config::Provider,
    prefer_userspace: bool,
) -> Result<String> {
    let effective = platform_interface_name(interface_name);
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick up for {} ({}) [userspace={}]",
        effective,
        provider.dir_name(),
        prefer_userspace
    );
    client.wg_quick_run(
        WgQuickAction::Up,
        &effective,
        provider.dir_name(),
        config_content,
        prefer_userspace,
    )?;
    Ok(effective)
}

/// On macOS, TUN interfaces must be named `utunN`; the kernel assigns the number automatically.
/// Any requested name that is not already a `utun*` name is mapped to `"utun"` so that
/// wg-quick (or the WireGuard network extension) picks the next available slot.
/// On other platforms the name is returned unchanged.
fn platform_interface_name(name: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        if name == "utun" || name.starts_with("utun") {
            return name.to_string();
        }
        "utun".to_string()
    }
    #[cfg(not(target_os = "macos"))]
    name.to_string()
}

/// Bring down the WireGuard interface and remove the config.
pub fn down(interface_name: &str, provider: config::Provider) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick down for {} ({})",
        interface_name,
        provider.dir_name()
    );
    client.wg_quick_run(
        WgQuickAction::Down,
        interface_name,
        provider.dir_name(),
        "",
        false,
    )
}

/// Check if a WireGuard interface is currently active.
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        // On macOS, `ip` is not available and the actual interface is named utunN (kernel-assigned).
        // Use `wg show interfaces` to detect any active WireGuard tunnel.
        let _ = interface_name;
        debug!(cmd = "wg show interfaces", "exec");
        std::process::Command::new("wg")
            .args(["show", "interfaces"])
            .output()
            .map(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        debug!(cmd = format!("ip link show {}", interface_name), "exec");
        std::process::Command::new("ip")
            .args(["link", "show", interface_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn _provider_name(provider: config::Provider) -> &'static str {
    provider.dir_name()
}

// Keep legacy path helpers untouched for compatibility with current call sites
// and tests if needed.
#[must_use]
pub fn _config_file_path(interface_name: &str, provider: config::Provider) -> std::path::PathBuf {
    config::config_dir(provider).join(format!("{}.conf", interface_name))
}

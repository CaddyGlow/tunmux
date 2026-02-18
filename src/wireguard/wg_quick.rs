use crate::config;
use crate::error::Result;
use crate::privileged_api::WgQuickAction;
use crate::privileged_client::PrivilegedClient;
use tracing::info;

/// Write the WireGuard config and bring up the interface.
pub fn up(config_content: &str, interface_name: &str, provider: config::Provider) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick up for {} ({})",
        interface_name,
        provider.dir_name()
    );
    client.wg_quick_run(
        WgQuickAction::Up,
        interface_name,
        provider.dir_name(),
        config_content,
    )
}

/// Bring down the WireGuard interface and remove the config.
pub fn down(interface_name: &str, provider: config::Provider) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick down for {} ({})",
        interface_name,
        provider.dir_name()
    );
    client.wg_quick_run(WgQuickAction::Down, interface_name, provider.dir_name(), "")
}

/// Check if a WireGuard interface is currently active.
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    std::process::Command::new("ip")
        .args(["link", "show", interface_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

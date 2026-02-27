use crate::config;
use crate::error::Result;
use crate::privileged_api::GotaTunAction;
use crate::privileged_client::PrivilegedClient;
use tracing::info;

use super::handshake;

/// Bring up a WireGuard tunnel using the embedded gotatun userspace backend.
pub fn up(
    config_content: &str,
    interface_name: &str,
    provider: config::Provider,
) -> Result<String> {
    let _ = provider;
    up_raw(config_content, interface_name)?;
    Ok(interface_name.to_string())
}

/// Bring up a userspace tunnel directly via gotatun helper.
pub fn up_raw(config_content: &str, interface_name: &str) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace up"
    );
    client.gotatun_run(GotaTunAction::Up, interface_name, config_content)?;
    let dns_servers = handshake::dns_servers_from_config(config_content);
    handshake::wait_for_handshake(interface_name, &dns_servers)
}

/// Tear down a userspace WireGuard tunnel.
pub fn down(interface_name: &str, provider: config::Provider) -> Result<()> {
    let _ = provider;
    down_raw(interface_name)
}

/// Tear down a userspace tunnel directly via gotatun helper.
pub fn down_raw(interface_name: &str) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace down"
    );
    client.gotatun_run(GotaTunAction::Down, interface_name, "")
}

/// Check if a userspace interface appears active by control socket presence.
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    std::path::Path::new("/var/run/wireguard")
        .join(format!("{interface_name}.sock"))
        .exists()
}

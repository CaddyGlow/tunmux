use crate::error::Result;
use crate::privileged_api::GotaTunAction;
use crate::privileged_client::PrivilegedClient;
use tracing::info;

/// Bring up a WireGuard tunnel using the embedded gotatun userspace backend.
pub fn up(config_content: &str, interface_name: &str) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace up"
    );
    client.gotatun_run(GotaTunAction::Up, interface_name, config_content)
}

/// Tear down a userspace WireGuard tunnel.
pub fn down(interface_name: &str) -> Result<()> {
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

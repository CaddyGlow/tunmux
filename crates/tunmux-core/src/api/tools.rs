//! Provider tools: AirVPN account web tools, Proton port forwarding and the
//! certificate, saved WireGuard profiles.

use std::time::SystemTime;

use crate::config::AppConfig;

/// AirVPN forwarded port.
#[derive(Debug, Clone)]
pub struct AirPort {
    pub port: u16,
    pub protocol: String,
    /// 0 when the port is forwarded unchanged.
    pub local_port: u16,
    pub enabled: bool,
    pub device: String,
}

/// AirVPN device (one WireGuard key).
#[derive(Debug, Clone)]
pub struct AirDevice {
    pub id: String,
    pub name: String,
    pub wg_ipv4: String,
}

/// AirVPN API key; only the shortened secret is exposed.
#[derive(Debug, Clone)]
pub struct AirApiKey {
    pub id: String,
    pub name: String,
    pub secret_short: String,
}

/// What the AirVPN client area holds for the account.
#[derive(Debug, Clone, Default)]
pub struct AirOverview {
    pub ports: Vec<AirPort>,
    pub devices: Vec<AirDevice>,
    pub api_keys: Vec<AirApiKey>,
}

/// A change to the AirVPN client area.
#[derive(Debug, Clone)]
pub enum AirAction {
    /// Forward a port; 0 lets AirVPN pick one.
    AddPort(u16),
    RemovePort(u16),
    /// `tcp`, `udp` or `both`.
    SetProtocol(u16, String),
    AddDevice,
    RenameDevice {
        id: String,
        name: String,
    },
    DeleteDevice(String),
    AddApiKey,
    DeleteApiKey(String),
}

#[cfg(feature = "airvpn")]
async fn air_web(config: &AppConfig) -> anyhow::Result<crate::airvpn::web::AirVpnWeb> {
    let session: crate::airvpn::models::AirSession =
        crate::config::load_session(crate::config::Provider::AirVpn, config)?;
    crate::airvpn::web::AirVpnWeb::login_or_restore(&session.username, &session.password).await
}

/// Ports, devices and API keys from the AirVPN client area (network).
#[cfg(feature = "airvpn")]
pub async fn airvpn_overview(config: &AppConfig) -> anyhow::Result<AirOverview> {
    let web = air_web(config).await?;
    let result = async {
        let ports = web.list_ports().await?;
        let devices = web.list_devices().await?;
        let api_keys = web.list_api_keys().await?;
        anyhow::Ok(AirOverview {
            ports: ports
                .into_iter()
                .map(|p| AirPort {
                    port: p.port,
                    protocol: p.protocol,
                    local_port: p.local_port,
                    enabled: p.enabled,
                    device: p.device,
                })
                .collect(),
            devices: devices
                .into_iter()
                .map(|d| AirDevice {
                    id: d.id,
                    name: d.name,
                    wg_ipv4: d.wg_ipv4,
                })
                .collect(),
            api_keys: api_keys
                .into_iter()
                .map(|k| AirApiKey {
                    id: k.id,
                    name: k.name,
                    secret_short: k.secret_short,
                })
                .collect(),
        })
    }
    .await;
    web.save();
    result
}

/// Apply one change to the AirVPN client area (network).
#[cfg(feature = "airvpn")]
pub async fn airvpn_apply(action: &AirAction, config: &AppConfig) -> anyhow::Result<()> {
    let web = air_web(config).await?;
    let result = match action {
        AirAction::AddPort(port) => web.add_port(*port).await.map(|_| ()),
        AirAction::RemovePort(port) => web.remove_port(*port).await,
        AirAction::SetProtocol(port, protocol) => web.set_protocol(*port, protocol).await,
        AirAction::AddDevice => web.add_device().await.map(|_| ()),
        AirAction::RenameDevice { id, name } => web.rename_device(id, name).await,
        AirAction::DeleteDevice(id) => web.delete_device(id).await,
        AirAction::AddApiKey => web.add_api_key().await.map(|_| ()),
        AirAction::DeleteApiKey(id) => web.delete_api_key(id).await,
    };
    web.save();
    result
}

#[cfg(not(feature = "airvpn"))]
pub async fn airvpn_overview(_config: &AppConfig) -> anyhow::Result<AirOverview> {
    Err(super::not_compiled(crate::config::Provider::AirVpn))
}

#[cfg(not(feature = "airvpn"))]
pub async fn airvpn_apply(_action: &AirAction, _config: &AppConfig) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::AirVpn))
}

/// One Proton NAT-PMP mapping that has not expired.
#[derive(Debug, Clone)]
pub struct ProtonForward {
    pub instance: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    pub public_port: u16,
    pub expires_at: SystemTime,
}

/// Proton port forwarding and certificate state, read from local files.
#[derive(Debug, Clone, Default)]
pub struct ProtonPorts {
    pub forwards: Vec<ProtonForward>,
    /// The renewal daemon is running.
    pub daemon_running: bool,
    pub certificate_expires: Option<SystemTime>,
}

#[cfg(feature = "proton")]
pub fn proton_ports(config: &AppConfig) -> anyhow::Result<ProtonPorts> {
    crate::proton::handlers::port_forward_status(config)
}

/// Request a TCP and UDP forwarded port for the active direct Proton
/// connection and keep it renewed in the background.
#[cfg(feature = "proton")]
pub async fn proton_request_port(config: &AppConfig) -> anyhow::Result<()> {
    crate::proton::handlers::request_port(config).await
}

/// Stop renewing and release the mappings of the active connection.
#[cfg(feature = "proton")]
pub async fn proton_release_ports(config: &AppConfig) -> anyhow::Result<()> {
    crate::proton::handlers::release_ports(config).await
}

#[cfg(feature = "proton")]
pub async fn proton_renew_certificate(config: &AppConfig) -> anyhow::Result<()> {
    crate::proton::handlers::renew_certificate(config).await
}

#[cfg(not(feature = "proton"))]
pub fn proton_ports(_config: &AppConfig) -> anyhow::Result<ProtonPorts> {
    Err(super::not_compiled(crate::config::Provider::Proton))
}

#[cfg(not(feature = "proton"))]
pub async fn proton_request_port(_config: &AppConfig) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::Proton))
}

#[cfg(not(feature = "proton"))]
pub async fn proton_release_ports(_config: &AppConfig) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::Proton))
}

#[cfg(not(feature = "proton"))]
pub async fn proton_renew_certificate(_config: &AppConfig) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::Proton))
}

/// A saved WireGuard profile.
#[derive(Debug, Clone)]
pub struct WgProfile {
    pub name: String,
    /// `host:port` of the peer, as written in the file.
    pub endpoint: Option<String>,
}

#[cfg(feature = "wgconf")]
pub fn wgconf_profiles() -> anyhow::Result<Vec<WgProfile>> {
    crate::wgconf::handlers::profiles()
}

/// Save the WireGuard config at `path` as profile `name`, after checking it
/// parses.
#[cfg(feature = "wgconf")]
pub fn wgconf_import(path: &std::path::Path, name: &str) -> anyhow::Result<()> {
    crate::wgconf::handlers::import_profile(path, name)
}

#[cfg(feature = "wgconf")]
pub fn wgconf_remove(name: &str) -> anyhow::Result<()> {
    crate::wgconf::handlers::delete_profile(name)
}

#[cfg(not(feature = "wgconf"))]
pub fn wgconf_profiles() -> anyhow::Result<Vec<WgProfile>> {
    Err(super::not_compiled(crate::config::Provider::Wgconf))
}

#[cfg(not(feature = "wgconf"))]
pub fn wgconf_import(_path: &std::path::Path, _name: &str) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::Wgconf))
}

#[cfg(not(feature = "wgconf"))]
pub fn wgconf_remove(_name: &str) -> anyhow::Result<()> {
    Err(super::not_compiled(crate::config::Provider::Wgconf))
}

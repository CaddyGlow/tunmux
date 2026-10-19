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
    up_raw_with_session(config_content, interface_name).map(|_| ())
}

pub fn up_raw_with_session(config_content: &str, interface_name: &str) -> Result<String> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace up"
    );
    let session_id = client.gotatun_start_session(interface_name, config_content)?;
    let dns_servers = handshake::dns_servers_from_config(config_content);
    finish_startup(
        handshake::wait_for_handshake(interface_name, &dns_servers),
        || down_for_session(interface_name, &session_id),
    )?;
    Ok(session_id)
}

pub(super) fn finish_startup(
    outcome: Result<()>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) => match cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(crate::error::AppError::Other(format!(
                "{error}; startup cleanup incomplete: {cleanup}"
            ))),
        },
    }
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

/// Conservatively check control endpoint occupancy without trusting socket presence.
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    super::health::userspace_endpoint_occupied(interface_name)
}

/// Explicit connect preparation also handles completed recovery whose user-state
/// record was already removed, but whose protected socket nodes survived a crash.
pub fn prepare_endpoint(interface: &str) -> Result<()> {
    if !is_interface_active(interface) {
        return Ok(());
    }
    let client = PrivilegedClient::new();
    let observed = client.inspect_session(interface, None)?;
    if observed.health == crate::privileged_api::SessionHealthKind::Inactive
        && observed.recovery_available
    {
        if let Some(id) = observed.session_id {
            return client.recover_session(interface, &id);
        }
    }
    Err(crate::error::AppError::Other(format!(
        "userspace endpoint {interface} is occupied or its ownership is unknown: {}",
        observed.reason
    )))
}

/// Stop only the helper identified by saved connection state.
pub fn down_for_session(interface: &str, session_id: &str) -> Result<()> {
    PrivilegedClient::new().gotatun_run_for_session(
        GotaTunAction::Down,
        interface,
        "",
        Some(session_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    #[test]
    fn handshake_failure_runs_cleanup_and_reports_both_errors() {
        let mut stopped = false;
        let result = finish_startup(Err(AppError::Other("handshake timed out".into())), || {
            stopped = true;
            Err(AppError::Other("DNS recovery pending".into()))
        });
        assert!(stopped);
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("handshake timed out") && message.contains("DNS recovery pending")
        );
        finish_startup(Ok(()), || panic!("successful startup must not stop device")).unwrap();
    }
}

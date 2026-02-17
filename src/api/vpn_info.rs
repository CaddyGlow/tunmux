use tracing::info;

use crate::api::http::{check_api_response, ProtonClient};
use crate::error::Result;
use crate::models::session::VpnInfoResponse;

/// Fetch VPN account info (username, password, tier, plan).
pub async fn fetch_vpn_info(client: &ProtonClient) -> Result<VpnInfoResponse> {
    info!("Fetching VPN account info");
    let resp = client.get("/vpn/v2").send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let info: VpnInfoResponse = serde_json::from_value(json)?;
    info!(plan = %info.vpn.plan_name, tier = info.vpn.max_tier, "VPN info fetched");
    Ok(info)
}

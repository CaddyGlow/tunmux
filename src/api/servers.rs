use tracing::info;

use crate::api::http::{check_api_response, ProtonClient};
use crate::error::Result;
use crate::models::server::LogicalsResponse;

/// Fetch the full server list from the Proton API.
pub async fn fetch_server_list(client: &ProtonClient) -> Result<LogicalsResponse> {
    info!("Fetching server list");
    let resp = client
        .get("/vpn/v1/logicals?SecureCoreFilter=all")
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;

    let logicals: LogicalsResponse = serde_json::from_value(json)?;
    info!(count = logicals.logical_servers.len(), "Servers fetched");
    Ok(logicals)
}

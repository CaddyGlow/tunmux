use serde_json::json;
use tracing::info;

use crate::api::http::{check_api_response, ProtonClient};
use crate::error::Result;
use crate::models::session::CertificateResponse;

/// Refresh interval for certificates: 7 days in minutes.
const CERT_DURATION_MIN: i64 = 7 * 24 * 60;

/// Fetch a VPN certificate from the API.
/// The ed25519 public key PEM is sent as `ClientPublicKey`.
pub async fn fetch_certificate(
    client: &ProtonClient,
    ed25519_pubkey_pem: &str,
) -> Result<CertificateResponse> {
    info!("fetching_vpn_certificate");
    let body = json!({
        "ClientPublicKey": ed25519_pubkey_pem,
        "Duration": format!("{} min", CERT_DURATION_MIN),
    });

    let resp = client
        .post("/vpn/v1/certificate")
        .json(&body)
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;

    let cert: CertificateResponse = serde_json::from_value(json)?;
    info!( serial = ?cert.serial_number.as_str(), "certificate_fetched");
    Ok(cert)
}

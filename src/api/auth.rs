use serde_json::json;
use tracing::{debug, info};

use crate::api::http::{check_api_response, ProtonClient};
use crate::api::srp;
use crate::error::Result;
use crate::models::session::{AuthInfoResponse, AuthResponse, TwoFactorResponse};

/// Perform SRP login against the Proton API.
///
/// Returns (AuthResponse, ProtonClient with auth headers set).
pub async fn login(
    client: &mut ProtonClient,
    username: &str,
    password: &str,
) -> Result<AuthResponse> {
    // Step 1: Get auth info (salt, server ephemeral, modulus)
    info!( username = ?username, "fetching_auth_info");
    let info_body = json!({ "Username": username });

    let info_resp = client.post("/auth/v4/info").json(&info_body).send().await?;
    let info_json: serde_json::Value = info_resp.json().await?;
    check_api_response(&info_json)?;

    let auth_info: AuthInfoResponse = serde_json::from_value(info_json)?;
    debug!( version = ?auth_info.version, "srp_version");

    // Step 2: Decode modulus, hash password, compute SRP proof
    let (modulus, modulus_le) = srp::decode_modulus(&auth_info.modulus)?;
    let hashed = srp::hash_password(password, &auth_info.salt, &modulus_le)?;
    let (client_ephemeral, client_proof, expected_server_proof) =
        srp::compute_srp_proof(&hashed, &auth_info.server_ephemeral, &modulus)?;

    // Step 3: Submit auth request
    info!("submitting_srp_auth");
    let auth_body = json!({
        "Username": username,
        "ClientEphemeral": client_ephemeral,
        "ClientProof": client_proof,
        "SRPSession": auth_info.srp_session,
    });

    let auth_resp = client.post("/auth/v4").json(&auth_body).send().await?;
    let auth_json: serde_json::Value = auth_resp.json().await?;
    check_api_response(&auth_json)?;

    let auth: AuthResponse = serde_json::from_value(auth_json)?;

    // Step 4: Verify server proof
    srp::verify_server_proof(&expected_server_proof, &auth.server_proof)?;
    info!("server_proof_verified");

    // Set auth credentials on the client
    client.set_auth(&auth.uid, &auth.access_token);

    Ok(auth)
}

/// Submit TOTP 2FA code.
pub async fn submit_2fa(client: &ProtonClient, code: &str) -> Result<TwoFactorResponse> {
    info!("submitting_2fa_code");
    let body = json!({ "TwoFactorCode": code });

    let resp = client.post("/auth/v4/2fa").json(&body).send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;

    let result: TwoFactorResponse = serde_json::from_value(json)?;
    info!("two_fa_accepted");
    Ok(result)
}

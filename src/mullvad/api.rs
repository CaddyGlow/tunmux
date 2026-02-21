use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;

use crate::error::{AppError, Result};
use crate::shared::crypto;

const API_BASE: &str = "https://api.mullvad.net";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MullvadManifest {
    pub locations: std::collections::HashMap<String, MullvadLocation>,
    pub wireguard: MullvadWireguard,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MullvadLocation {
    pub country: String,
    pub city: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MullvadWireguard {
    pub relays: Vec<MullvadRelay>,
    pub port_ranges: Vec<(u16, u16)>,
    pub ipv4_gateway: String,
    #[serde(default)]
    pub ipv6_gateway: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MullvadRelay {
    pub hostname: String,
    pub location: String,
    pub active: bool,
    pub provider: String,
    pub ipv4_addr_in: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct MullvadLoginData {
    pub account_number: String,
    pub access_token: String,
    pub device_id: String,
    pub wg_private_key: String,
    pub ipv4_address: String,
    pub ipv6_address: Option<String>,
    pub manifest: MullvadManifest,
}

#[derive(Debug, serde::Deserialize)]
struct MullvadTokenResponse {
    access_token: String,
}

#[derive(Debug, serde::Deserialize)]
struct MullvadDeviceResponse {
    id: String,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    pubkey: String,
    ipv4_address: String,
    ipv6_address: String,
}

pub fn api_client() -> Result<Client> {
    Ok(Client::builder().user_agent("tunmux").build()?)
}

pub async fn login(account_number: &str) -> Result<MullvadLoginData> {
    let client = api_client()?;
    let access_token = fetch_access_token(&client, account_number).await?;
    login_with_access_token(account_number, &access_token).await
}

pub async fn login_with_access_token(
    account_number: &str,
    access_token: &str,
) -> Result<MullvadLoginData> {
    let client = api_client()?;
    let keys = crypto::keys::VpnKeys::generate()?;
    let wg_public_key = keys.wg_public_key();
    let wg_private_key = keys.wg_private_key();

    let token = access_token.trim();
    if token.is_empty() {
        return Err(AppError::Other(
            "Mullvad access token cannot be empty".to_string(),
        ));
    }
    let device = create_device(&client, token, &wg_public_key).await?;
    let manifest = fetch_manifest(&client).await?;

    Ok(MullvadLoginData {
        account_number: account_number.to_string(),
        access_token: token.to_string(),
        device_id: device.id,
        wg_private_key,
        ipv4_address: device.ipv4_address,
        ipv6_address: if device.ipv6_address.trim().is_empty() {
            None
        } else {
            Some(device.ipv6_address)
        },
        manifest,
    })
}

pub async fn delete_device(account_number: &str, device_id: &str) -> Result<()> {
    let client = api_client()?;
    let access_token = fetch_access_token(&client, account_number).await?;
    let url = format!("{}/accounts/v1/devices/{}", API_BASE, device_id);
    let resp = client.delete(url).bearer_auth(access_token).send().await?;
    if resp.status() == StatusCode::NO_CONTENT {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(AppError::Other(format!(
        "Mullvad device deletion failed ({}): {}",
        status,
        extract_api_error(&body)
    )))
}

async fn fetch_access_token(client: &Client, account_number: &str) -> Result<String> {
    let url = format!("{}/auth/v1/token", API_BASE);
    let resp = client
        .post(url)
        .json(&serde_json::json!({ "account_number": account_number }))
        .send()
        .await?;
    let token: MullvadTokenResponse = parse_api_json(resp, "Mullvad token request").await?;
    Ok(token.access_token)
}

async fn create_device(
    client: &Client,
    access_token: &str,
    public_key: &str,
) -> Result<MullvadDeviceResponse> {
    let url = format!("{}/accounts/v1/devices", API_BASE);
    let resp = client
        .post(url)
        .bearer_auth(access_token)
        .json(&serde_json::json!({
            "pubkey": public_key,
            "hijack_dns": false
        }))
        .send()
        .await?;
    parse_api_json(resp, "Mullvad device creation").await
}

async fn fetch_manifest(client: &Client) -> Result<MullvadManifest> {
    let url = format!("{}/app/v1/relays", API_BASE);
    let resp = client.get(url).send().await?;
    parse_api_json(resp, "Mullvad relay list").await
}

async fn parse_api_json<T: DeserializeOwned>(resp: reqwest::Response, action: &str) -> Result<T> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(AppError::Other(format!(
            "{action} failed ({}): {}",
            status,
            extract_api_error(&body)
        )));
    }
    serde_json::from_str::<T>(&body)
        .map_err(|e| AppError::Other(format!("failed to parse {} response: {}", action, e)))
}

fn extract_api_error(body: &str) -> String {
    if body.trim().is_empty() {
        return "empty response body".to_string();
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["message", "error", "code"] {
            if let Some(v) = value.get(key) {
                if let Some(s) = v.as_str() {
                    return s.to_string();
                }
                return v.to_string();
            }
        }
    }
    body.to_string()
}

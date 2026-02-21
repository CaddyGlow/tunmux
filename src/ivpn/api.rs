use reqwest::Client;
use serde::de::DeserializeOwned;

use crate::error::{AppError, Result};
use crate::shared::crypto;

const API_BASE: &str = "https://api.ivpn.net";
const CODE_SUCCESS: i64 = 200;
const CODE_2FA_REQUIRED: i64 = 70011;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnManifest {
    pub wireguard: Vec<IvpnWireGuardServer>,
    pub config: IvpnConfigInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnWireGuardServer {
    pub gateway: String,
    pub country_code: String,
    pub country: String,
    pub city: String,
    pub hosts: Vec<IvpnWireGuardHost>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnWireGuardHost {
    pub hostname: String,
    pub dns_name: String,
    pub host: String,
    pub public_key: String,
    pub local_ip: String,
    #[serde(default)]
    pub load: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnConfigInfo {
    pub ports: IvpnPortsInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnPortsInfo {
    pub wireguard: Vec<IvpnPortInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnPortInfo {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub range: Option<IvpnPortRange>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IvpnPortRange {
    pub min: u16,
    pub max: u16,
}

#[derive(Debug, Clone)]
pub struct IvpnLoginData {
    pub account_id: String,
    pub session_token: String,
    pub wg_private_key: String,
    pub wg_local_ip: String,
    pub manifest: IvpnManifest,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct IvpnServiceStatus {
    #[allow(dead_code)]
    #[serde(default)]
    is_active: bool,
    #[allow(dead_code)]
    #[serde(default)]
    active_until: i64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct IvpnWireGuardLogin {
    #[serde(default)]
    status: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    ip_address: String,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnSessionNewResponse {
    status: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    token: String,
    #[allow(dead_code)]
    #[serde(default)]
    vpn_username: String,
    #[allow(dead_code)]
    #[serde(default)]
    vpn_password: String,
    #[allow(dead_code)]
    #[serde(default)]
    device_name: String,
    #[allow(dead_code)]
    #[serde(default)]
    service_status: Option<IvpnServiceStatus>,
    #[serde(default)]
    wireguard: Option<IvpnWireGuardLogin>,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnBasicResponse {
    status: i64,
    #[serde(default)]
    message: String,
}

#[derive(Debug, serde::Deserialize)]
struct IvpnSessionStatusResponse {
    status: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    service_status: Option<IvpnServiceStatus>,
}

pub fn api_client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent("tunmux")
        .cookie_store(true)
        .build()?)
}

pub async fn login(account_id: &str, totp: Option<&str>) -> Result<IvpnLoginData> {
    let client = api_client()?;
    let keys = crypto::keys::VpnKeys::generate()?;
    let wg_public_key = keys.wg_public_key();
    let wg_private_key = keys.wg_private_key();

    let mut response = session_new(&client, account_id, &wg_public_key, None).await?;
    if response.status == CODE_2FA_REQUIRED {
        let code = totp.unwrap_or("").trim();
        if code.is_empty() {
            return Err(AppError::Other(
                "2FA code required for this IVPN account".to_string(),
            ));
        }
        response = session_new(&client, account_id, &wg_public_key, Some(code)).await?;
    }

    ensure_api_success(response.status, &response.message, "IVPN login")?;
    let wg_info = response.wireguard.as_ref().ok_or_else(|| {
        AppError::Other("IVPN login response missing wireguard section".to_string())
    })?;
    ensure_api_success(wg_info.status, &wg_info.message, "IVPN WireGuard login")?;
    if wg_info.ip_address.trim().is_empty() {
        return Err(AppError::Other(
            "IVPN login did not return a WireGuard IP address".to_string(),
        ));
    }
    if response.token.trim().is_empty() {
        return Err(AppError::Other(
            "IVPN login did not return a session token".to_string(),
        ));
    }

    let manifest = fetch_manifest(&client).await?;

    Ok(IvpnLoginData {
        account_id: account_id.to_string(),
        session_token: response.token,
        wg_private_key,
        wg_local_ip: wg_info.ip_address.clone(),
        manifest,
    })
}

pub async fn restore_session(
    account_id: &str,
    session_token: &str,
    wg_private_key: &str,
    wg_local_ip: &str,
) -> Result<IvpnLoginData> {
    let account = account_id.trim();
    if account.is_empty() {
        return Err(AppError::Other("missing username".to_string()));
    }
    let token = session_token.trim();
    if token.is_empty() {
        return Err(AppError::Other("IVPN session token is empty".to_string()));
    }
    let private_key = wg_private_key.trim();
    if private_key.is_empty() {
        return Err(AppError::Other(
            "IVPN WireGuard private key is empty".to_string(),
        ));
    }
    let local_ip = wg_local_ip.trim();
    if local_ip.is_empty() {
        return Err(AppError::Other(
            "IVPN WireGuard local IP is empty".to_string(),
        ));
    }

    let client = api_client()?;
    let status = session_status(&client, token).await?;
    ensure_api_success(status.status, &status.message, "IVPN session/status")?;
    if let Some(service) = status.service_status {
        if !service.is_active {
            return Err(AppError::Other(
                "IVPN session token is not active".to_string(),
            ));
        }
    }
    let manifest = fetch_manifest(&client).await?;

    Ok(IvpnLoginData {
        account_id: account.to_string(),
        session_token: token.to_string(),
        wg_private_key: private_key.to_string(),
        wg_local_ip: local_ip.to_string(),
        manifest,
    })
}

pub async fn delete_session(session_token: &str) -> Result<()> {
    let client = api_client()?;
    let url = format!("{}/v4/session/delete", API_BASE);
    let resp = client
        .post(url)
        .json(&serde_json::json!({ "session_token": session_token }))
        .send()
        .await?;
    let parsed: IvpnBasicResponse = parse_api_json(resp, "IVPN session/delete").await?;
    ensure_api_success(parsed.status, &parsed.message, "IVPN logout")
}

async fn session_new(
    client: &Client,
    account_id: &str,
    wg_public_key: &str,
    confirmation: Option<&str>,
) -> Result<IvpnSessionNewResponse> {
    let body = match confirmation {
        Some(code) => serde_json::json!({
            "username": account_id,
            "force": false,
            "wg_public_key": wg_public_key,
            "confirmation": code
        }),
        None => serde_json::json!({
            "username": account_id,
            "force": false,
            "wg_public_key": wg_public_key
        }),
    };
    let url = format!("{}/v4/session/new", API_BASE);
    let resp = client.post(url).json(&body).send().await?;
    parse_api_json(resp, "IVPN session/new").await
}

async fn session_status(client: &Client, session_token: &str) -> Result<IvpnSessionStatusResponse> {
    let url = format!("{}/v4/session/status", API_BASE);
    let resp = client
        .post(url)
        .json(&serde_json::json!({ "session_token": session_token }))
        .send()
        .await?;
    parse_api_json(resp, "IVPN session/status").await
}

async fn fetch_manifest(client: &Client) -> Result<IvpnManifest> {
    let url = format!("{}/v5/servers.json", API_BASE);
    let resp = client.get(url).send().await?;
    parse_api_json(resp, "IVPN server list").await
}

fn ensure_api_success(code: i64, message: &str, action: &str) -> Result<()> {
    if code == CODE_SUCCESS {
        return Ok(());
    }
    if message.trim().is_empty() {
        Err(AppError::Other(format!(
            "{action} failed: API status {code}"
        )))
    } else {
        Err(AppError::Other(format!(
            "{action} failed: [{code}] {message}"
        )))
    }
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

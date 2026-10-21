use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;

use crate::error::{AppError, Result};

const BASE_URL: &str = "https://vpn-api.proton.me";
const APP_VERSION: &str = "linux-vpn-cli@4.14.3+x86_64";
const USER_AGENT: &str = "ProtonVPN/4.14.3 (Linux; linux/unknown)";

/// HTTP client preconfigured with Proton API headers.
#[derive(Debug, Clone)]
pub struct ProtonClient {
    client: Client,
    uid: Option<String>,
    access_token: Option<String>,
}

impl ProtonClient {
    /// Create unauthenticated client (for login).
    pub fn new() -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("x-pm-appversion", HeaderValue::from_static(APP_VERSION));
        headers.insert("User-Agent", HeaderValue::from_static(USER_AGENT));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(AppError::Http)?;

        Ok(Self {
            client,
            uid: None,
            access_token: None,
        })
    }

    /// Create authenticated client from saved session.
    pub fn authenticated(uid: &str, access_token: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("x-pm-appversion", HeaderValue::from_static(APP_VERSION));
        headers.insert("User-Agent", HeaderValue::from_static(USER_AGENT));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(AppError::Http)?;

        Ok(Self {
            client,
            uid: Some(uid.to_string()),
            access_token: Some(access_token.to_string()),
        })
    }

    /// Set auth credentials after login.
    pub fn set_auth(&mut self, uid: &str, access_token: &str) {
        self.uid = Some(uid.to_string());
        self.access_token = Some(access_token.to_string());
    }

    /// Build a GET request with auth headers.
    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", BASE_URL, path);
        let mut req = self.client.get(&url);
        req = self.add_auth_headers(req);
        req
    }

    /// Build a POST request with auth headers.
    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", BASE_URL, path);
        let mut req = self.client.post(&url);
        req = self.add_auth_headers(req);
        req
    }

    fn add_auth_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(uid) = &self.uid {
            req = req.header("x-pm-uid", uid);
        }
        if let Some(token) = &self.access_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req
    }
}

/// Check API response for error codes.
pub fn check_api_response(json: &serde_json::Value) -> Result<()> {
    if let Some(code) = json.get("Code").and_then(|c| c.as_i64()) {
        if code != 1000 {
            let message = json
                .get("Error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown API error")
                .to_string();
            return Err(AppError::Api { code, message });
        }
    }
    Ok(())
}

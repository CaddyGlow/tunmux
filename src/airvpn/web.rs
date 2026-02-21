use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context};
use reqwest::redirect;
use reqwest_cookie_store::{CookieStore, CookieStoreMutex};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::{self, AppConfig, Provider};

use super::models::ForwardedPort;

const BASE_URL: &str = "https://airvpn.org";
const WEB_SESSION_FILE: &str = "web_session.json";

pub struct AirVpnWeb {
    client: reqwest::Client,
    /// Per-path ecsrf tokens (e.g. "/ports/" -> token, "/devices/" -> token).
    /// AirVPN uses page-specific CSRF tokens.
    ecsrf_cache: std::cell::RefCell<HashMap<String, String>>,
    cookie_store: Arc<CookieStoreMutex>,
}

/// Persisted web session: ecsrf tokens + serialized cookie jar.
#[derive(Serialize, Deserialize)]
struct SavedWebSession {
    ecsrf: HashMap<String, String>,
    cookies: String,
}

/// JSON response from the ports AJAX `action=manifest` call.
#[derive(Debug, Deserialize)]
struct PortsManifest {
    ports: Vec<PortEntry>,
    #[serde(default)]
    keys: Vec<ManifestKey>,
}

#[derive(Debug, Deserialize)]
struct ManifestKey {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct PortEntry {
    port: u16,
    #[serde(default)]
    pool: u16,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    local: serde_json::Value,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    device: String,
    #[serde(default)]
    dns: String,
}

/// JSON response from `action=sessions`.
#[derive(Debug, Deserialize)]
struct SessionsResponse {
    items: Vec<PortSession>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortSession {
    #[serde(default)]
    pub pool: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub iplayer: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub server_country: String,
    #[serde(default)]
    pub server_location: String,
    #[serde(default)]
    pub server_ip: String,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub local: serde_json::Value,
    #[serde(default)]
    pub dns_name: String,
}

/// JSON response from `action=test`.
#[derive(Debug, Deserialize)]
pub struct PortTestResult {
    #[serde(default)]
    pub message: String,
}

/// JSON response from `action=insert`.
#[derive(Debug, Deserialize)]
struct InsertResponse {
    port: Option<u16>,
    error: Option<String>,
}

/// JSON response from `action=delete`.
#[derive(Debug, Deserialize)]
struct DeleteResponse {
    #[serde(default)]
    error: Option<String>,
}

/// JSON response from devices `action=manifest`.
#[derive(Debug, Deserialize)]
struct DevicesManifest {
    #[serde(default)]
    keys: Vec<DeviceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub wg_public_key: String,
    #[serde(default)]
    pub wg_ipv4: String,
    #[serde(default)]
    pub wg_ipv6: String,
}

/// JSON response from apisettings `action=manifest`.
#[derive(Debug, Deserialize)]
struct ApiKeysManifest {
    #[serde(default)]
    keys: Vec<ApiKeyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub secret_short: String,
    #[serde(default)]
    pub creation_date: i64,
}

/// JSON response from sessions `action=manifest`.
#[derive(Debug, Deserialize)]
struct SessionsManifest {
    #[serde(default)]
    sessions: Vec<VpnSession>,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VpnSession {
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub server_html: String,
    #[serde(default)]
    pub connected_since: i64,
    #[serde(default)]
    pub bytes_write: u64,
    #[serde(default)]
    pub bytes_read: u64,
    #[serde(default)]
    pub speed_write: u64,
    #[serde(default)]
    pub speed_read: u64,
    #[serde(default)]
    pub software_name: String,
    #[serde(default)]
    pub exit_ipv4: String,
    #[serde(default)]
    pub exit_ipv6: String,
    #[serde(default)]
    pub vpn_ipv4: String,
    #[serde(default)]
    pub vpn_ipv6: String,
    #[serde(default)]
    pub entry_layer: String,
    #[serde(default)]
    pub dns_filter: String,
}

impl VpnSession {
    /// Extract the server name from the server_html field.
    pub fn server_name(&self) -> String {
        let doc = Html::parse_fragment(&self.server_html);
        if let Ok(sel) = Selector::parse(".air_card_server_info_name2 a") {
            if let Some(el) = doc.select(&sel).next() {
                return el.text().collect::<String>().trim().to_string();
            }
        }
        "-".to_string()
    }

    /// Extract the server location from the server_html field.
    pub fn server_location(&self) -> String {
        let doc = Html::parse_fragment(&self.server_html);
        if let Ok(sel) = Selector::parse(".air_card_server_info_location div:first-child") {
            if let Some(el) = doc.select(&sel).next() {
                return el.text().collect::<String>().trim().to_string();
            }
        }
        "-".to_string()
    }
}

impl AirVpnWeb {
    fn build_client(cookie_store: Arc<CookieStoreMutex>) -> anyhow::Result<reqwest::Client> {
        reqwest::Client::builder()
            .cookie_provider(cookie_store)
            .redirect(redirect::Policy::none())
            .user_agent("tunmux/0.1")
            .build()
            .context("failed to build reqwest client")
    }

    /// Try to restore a saved web session. Returns None if no saved session.
    fn restore() -> Option<Self> {
        let data = config::load_provider_file(Provider::AirVpn, WEB_SESSION_FILE).ok()??;
        let saved: SavedWebSession = serde_json::from_slice(&data).ok()?;

        #[allow(deprecated)]
        let store = CookieStore::load_json(saved.cookies.as_bytes()).ok()?;

        // Check that we have at least one real cookie (not just an empty jar).
        store.iter_any().next()?;

        let cookie_store = Arc::new(CookieStoreMutex::new(store));
        let client = Self::build_client(cookie_store.clone()).ok()?;

        debug!(
            ecsrf_cached_count = ?saved.ecsrf.len(), "web_session_restored");

        Some(Self {
            client,
            ecsrf_cache: std::cell::RefCell::new(saved.ecsrf),
            cookie_store,
        })
    }

    /// Persist current cookies + ecsrf tokens to disk.
    pub fn save(&self) {
        let result = (|| -> anyhow::Result<()> {
            let store = self
                .cookie_store
                .lock()
                .map_err(|e| anyhow::anyhow!("cookie store lock poisoned: {}", e))?;
            let mut buf = Vec::new();
            #[allow(deprecated)]
            store
                .save_json(&mut buf)
                .map_err(|e| anyhow::anyhow!("failed to serialize cookies: {}", e))?;
            let cookies = String::from_utf8(buf).context("cookies not utf-8")?;

            let saved = SavedWebSession {
                ecsrf: self.ecsrf_cache.borrow().clone(),
                cookies,
            };
            let json = serde_json::to_string(&saved)?;
            config::save_provider_file(Provider::AirVpn, WEB_SESSION_FILE, json.as_bytes())?;
            debug!("web_session_saved");
            Ok(())
        })();

        if let Err(e) = result {
            debug!( error = ?e.to_string(), "web_session_save_failed");
        }
    }

    /// Try to restore a saved session; fall back to a full login.
    pub async fn login_or_restore(username: &str, password: &str) -> anyhow::Result<Self> {
        if let Some(web) = Self::restore() {
            return Ok(web);
        }
        Self::login(username, password).await
    }

    /// Full web login: GET homepage for csrfKey, POST credentials, extract ecsrf.
    pub async fn login(username: &str, password: &str) -> anyhow::Result<Self> {
        let cookie_store = Arc::new(CookieStoreMutex::new(CookieStore::new(None)));
        let client = Self::build_client(cookie_store.clone())?;

        // Step 1: GET /login/ to extract csrfKey from the login form.
        // follow_redirects handles the anti-bot entry gate automatically.
        let login_page_url = format!("{}/login/", BASE_URL);
        let resp = follow_redirects(&client, &cookie_store, &login_page_url)
            .await
            .context("failed to fetch AirVPN login page")?;
        let body = resp.text().await?;
        let doc = Html::parse_document(&body);

        let csrf_key =
            extract_input_value(&doc, "csrfKey").context("could not find csrfKey in login form")?;
        debug!("login_csrf_key_extracted");

        let ref_value = extract_input_value(&doc, "ref").unwrap_or_default();

        // Step 2: POST login credentials
        let login_url = format!("{}/login/", BASE_URL);
        let form = [
            ("csrfKey", csrf_key.as_str()),
            ("ref", &ref_value),
            ("auth", username),
            ("password", password),
            ("remember_me", "1"),
            ("_processLogin", "usernamepassword"),
        ];

        let resp = client
            .post(&login_url)
            .form(&form)
            .send()
            .await
            .context("login POST failed")?;

        let status = resp.status();
        debug!( status = ?status.as_u16(), "login_response_status");

        if !status.is_redirection() {
            bail!(
                "web login failed -- check username and password (status {})",
                status
            );
        }

        // Follow the full redirect chain to establish session
        if let Some(location) = resp.headers().get("location") {
            let redirect_url = location.to_str().unwrap_or("/");
            let url = if redirect_url.starts_with('/') {
                format!("{}{}", BASE_URL, redirect_url)
            } else {
                redirect_url.to_string()
            };
            let _ = follow_redirects(&client, &cookie_store, &url).await;
        }

        debug!("login_succeeded");

        Ok(Self {
            client,
            ecsrf_cache: std::cell::RefCell::new(HashMap::new()),
            cookie_store,
        })
    }

    // ── Port management ──────────────────────────────────────────────

    /// Fetch the list of forwarded ports via the AJAX manifest endpoint.
    pub async fn list_ports(&self) -> anyhow::Result<Vec<ForwardedPort>> {
        let manifest: PortsManifest = self
            .ajax_post("/ports/", &[("action", "manifest")])
            .await
            .context("failed to fetch ports manifest")?;

        let keys = &manifest.keys;
        let ports = manifest
            .ports
            .into_iter()
            .map(|p| {
                let local_port = match &p.local {
                    serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u16,
                    serde_json::Value::String(s) => s.parse().unwrap_or(0),
                    _ => 0,
                };
                let device = if p.device.is_empty() || p.device == "all" {
                    "All".to_string()
                } else {
                    keys.iter()
                        .find(|k| k.id == p.device)
                        .map(|k| k.name.clone())
                        .unwrap_or(p.device)
                };
                ForwardedPort {
                    port: p.port,
                    pool: p.pool,
                    protocol: p.protocol,
                    local_port,
                    enabled: p.enabled,
                    device,
                    ddns: p.dns,
                }
            })
            .collect();

        Ok(ports)
    }

    /// Add a port forward via AJAX.
    pub async fn add_port(&self, port: u16) -> anyhow::Result<u16> {
        let port_str = port.to_string();

        let resp: InsertResponse = self
            .ajax_post(
                "/ports/",
                &[("action", "insert"), ("port", &port_str), ("pool", "0")],
            )
            .await
            .context("failed to insert port")?;

        if let Some(err) = resp.error {
            bail!("add port failed: {}", err);
        }

        Ok(resp.port.unwrap_or(port))
    }

    /// Change a port's protocol setting via AJAX.
    pub async fn set_protocol(&self, port: u16, protocol: &str) -> anyhow::Result<()> {
        let (port_str, pool_str) = self.lookup_port_pool(port).await?;

        let proto_lower = protocol.to_lowercase();
        let proto_value = match proto_lower.as_str() {
            "tcp" => "tcp",
            "udp" => "udp",
            "both" | "tcp+udp" => "tcp_udp",
            _ => {
                bail!("unknown protocol {:?} -- use tcp, udp, or both", protocol);
            }
        };

        let _: serde_json::Value = self
            .ajax_post(
                "/ports/",
                &[
                    ("action", "edit_protocol"),
                    ("port", &port_str),
                    ("pool", &pool_str),
                    ("value", proto_value),
                ],
            )
            .await
            .context("failed to set protocol")?;

        Ok(())
    }

    /// Fetch active sessions for a forwarded port.
    pub async fn port_sessions(&self, port: u16) -> anyhow::Result<Vec<PortSession>> {
        let (port_str, pool_str) = self.lookup_port_pool(port).await?;

        let resp: SessionsResponse = self
            .ajax_post(
                "/ports/",
                &[
                    ("action", "sessions"),
                    ("port", &port_str),
                    ("pool", &pool_str),
                ],
            )
            .await
            .context("failed to fetch port sessions")?;

        Ok(resp.items)
    }

    /// Test if a port is reachable on a specific server session.
    pub async fn test_port(
        &self,
        server_ip: &str,
        port: u16,
        pool: u16,
        protocol: &str,
    ) -> anyhow::Result<PortTestResult> {
        let port_str = port.to_string();
        let pool_str = pool.to_string();

        self.ajax_post(
            "/ports/",
            &[
                ("action", "test"),
                ("ip", server_ip),
                ("port", &port_str),
                ("pool", &pool_str),
                ("protocol", protocol),
            ],
        )
        .await
        .context("failed to test port")
    }

    /// Set the local port mapping for a forwarded port.
    pub async fn set_local_port(&self, port: u16, local_port: u16) -> anyhow::Result<()> {
        let (port_str, pool_str) = self.lookup_port_pool(port).await?;
        let local_str = local_port.to_string();

        let _: serde_json::Value = self
            .ajax_post(
                "/ports/",
                &[
                    ("action", "edit_localport"),
                    ("port", &port_str),
                    ("pool", &pool_str),
                    ("value", &local_str),
                ],
            )
            .await
            .context("failed to set local port")?;

        Ok(())
    }

    /// Set the DDNS name for a forwarded port.
    /// The name should be the prefix only (without .airdns.org).
    pub async fn set_ddns(&self, port: u16, name: &str) -> anyhow::Result<()> {
        let (port_str, pool_str) = self.lookup_port_pool(port).await?;

        // Strip .airdns.org suffix if the user included it
        let prefix = name.trim_end_matches(".airdns.org").trim_end_matches('.');

        let _: serde_json::Value = self
            .ajax_post(
                "/ports/",
                &[
                    ("action", "edit_ddns"),
                    ("port", &port_str),
                    ("pool", &pool_str),
                    ("value", prefix),
                ],
            )
            .await
            .context("failed to set DDNS name")?;

        Ok(())
    }

    /// Look up a port's pool value from the manifest.
    async fn lookup_port_pool(&self, port: u16) -> anyhow::Result<(String, String)> {
        let ports = self.list_ports().await?;
        let fp = ports
            .iter()
            .find(|p| p.port == port)
            .with_context(|| format!("port {} is not forwarded", port))?;
        Ok((port.to_string(), fp.pool.to_string()))
    }

    /// Remove a forwarded port via AJAX.
    pub async fn remove_port(&self, port: u16) -> anyhow::Result<()> {
        let (port_str, pool_str) = self.lookup_port_pool(port).await?;

        let resp: DeleteResponse = self
            .ajax_post(
                "/ports/",
                &[
                    ("action", "delete"),
                    ("port", &port_str),
                    ("pool", &pool_str),
                ],
            )
            .await
            .context("failed to delete port")?;

        if let Some(err) = resp.error {
            bail!("remove port failed: {}", err);
        }

        Ok(())
    }

    // ── Device management ─────────────────────────────────────────────

    /// Fetch the list of devices (WireGuard keys) via the AJAX manifest endpoint.
    pub async fn list_devices(&self) -> anyhow::Result<Vec<DeviceEntry>> {
        let manifest: DevicesManifest = self
            .ajax_post("/devices/", &[("action", "manifest")])
            .await
            .context("failed to fetch devices manifest")?;

        Ok(manifest.keys)
    }

    /// Add a new device. Returns the new device's ID.
    pub async fn add_device(&self) -> anyhow::Result<String> {
        // action=add returns [] on success; the new device appears in the manifest
        let _: serde_json::Value = self
            .ajax_post("/devices/", &[("action", "add")])
            .await
            .context("failed to add device")?;

        // Fetch manifest to find the newly created device (has name "New device")
        let devices = self.list_devices().await?;
        let new_dev = devices
            .iter()
            .find(|d| d.name == "New device")
            .or_else(|| devices.last())
            .context("could not find newly created device")?;

        Ok(new_dev.id.clone())
    }

    /// Rename a device by its ID.
    pub async fn rename_device(&self, id: &str, name: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .ajax_post(
                "/devices/",
                &[("action", "edit_name"), ("id", id), ("value", name)],
            )
            .await
            .context("failed to rename device")?;

        Ok(())
    }

    /// Delete a device by its ID.
    pub async fn delete_device(&self, id: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .ajax_post("/devices/", &[("action", "delete"), ("id", id)])
            .await
            .context("failed to delete device")?;

        Ok(())
    }

    /// Look up a device ID by name (case-insensitive).
    pub async fn lookup_device_id(&self, name: &str) -> anyhow::Result<String> {
        let devices = self.list_devices().await?;
        let dev = devices
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
            .with_context(|| {
                let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
                format!(
                    "device {:?} not found. Available: {}",
                    name,
                    names.join(", ")
                )
            })?;
        Ok(dev.id.clone())
    }

    // ── API key management ─────────────────────────────────────────

    /// Fetch the list of API keys via the AJAX manifest endpoint.
    pub async fn list_api_keys(&self) -> anyhow::Result<Vec<ApiKeyEntry>> {
        let manifest: ApiKeysManifest = self
            .ajax_post("/apisettings/", &[("action", "manifest")])
            .await
            .context("failed to fetch API keys manifest")?;

        Ok(manifest.keys)
    }

    /// Generate a new API key. Returns the new key's ID.
    pub async fn add_api_key(&self) -> anyhow::Result<String> {
        let _: serde_json::Value = self
            .ajax_post("/apisettings/", &[("action", "add")])
            .await
            .context("failed to add API key")?;

        // Fetch manifest to find the newly created key
        let keys = self.list_api_keys().await?;
        let new_key = keys
            .last()
            .context("could not find newly created API key")?;

        Ok(new_key.id.clone())
    }

    /// Rename an API key by its ID.
    pub async fn rename_api_key(&self, id: &str, name: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .ajax_post(
                "/apisettings/",
                &[("action", "edit_name"), ("id", id), ("value", name)],
            )
            .await
            .context("failed to rename API key")?;

        Ok(())
    }

    /// Delete an API key by its ID.
    pub async fn delete_api_key(&self, id: &str) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .ajax_post("/apisettings/", &[("action", "delete"), ("id", id)])
            .await
            .context("failed to delete API key")?;

        Ok(())
    }

    /// Look up an API key ID by name (case-insensitive).
    pub async fn lookup_api_key_id(&self, name: &str) -> anyhow::Result<String> {
        let keys = self.list_api_keys().await?;
        let key = keys
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
            .with_context(|| {
                let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
                format!(
                    "API key {:?} not found. Available: {}",
                    name,
                    names.join(", ")
                )
            })?;
        Ok(key.id.clone())
    }

    // ── Sessions ───────────────────────────────────────────────────

    /// Fetch the list of active VPN sessions.
    pub async fn list_sessions(&self) -> anyhow::Result<(Vec<VpnSession>, String)> {
        let manifest: SessionsManifest = self
            .ajax_post("/sessions/", &[("action", "manifest")])
            .await
            .context("failed to fetch sessions manifest")?;

        Ok((manifest.sessions, manifest.message))
    }

    /// Fetch the ecsrf token for a given path, caching it.
    async fn get_ecsrf(&self, path: &str) -> anyhow::Result<String> {
        // Check cache first.
        if let Some(token) = self.ecsrf_cache.borrow().get(path) {
            return Ok(token.clone());
        }

        // Fetch the page and extract the ecsrf token.
        let page_url = format!("{}{}", BASE_URL, path);
        let resp = follow_redirects(&self.client, &self.cookie_store, &page_url).await?;
        let body = resp.text().await?;

        let token = extract_ecsrf(&body)
            .with_context(|| format!("could not find ecsrf token on {}", path))?;
        debug!( path = ?path, "ajax_ecsrf_extracted");

        self.ecsrf_cache
            .borrow_mut()
            .insert(path.to_string(), token.clone());
        Ok(token)
    }

    /// POST an AJAX request with ecsrf and render=ajax parameters.
    /// On CSRF error, invalidates the cached token, re-fetches it, and retries once.
    async fn ajax_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        match self.ajax_post_inner(path, params).await {
            Ok(val) => Ok(val),
            Err(e) if e.to_string().contains("Invalid CSRF Token") => {
                debug!( path = ?path, "ajax_csrf_token_expired");
                self.ecsrf_cache.borrow_mut().remove(path);
                self.ajax_post_inner(path, params).await
            }
            Err(e) => Err(e),
        }
    }

    async fn ajax_post_inner<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        let ecsrf = self.get_ecsrf(path).await?;
        let url = format!("{}{}", BASE_URL, path);

        let mut form_params: Vec<(&str, &str)> = params.to_vec();
        form_params.push(("render", "ajax"));
        form_params.push(("ecsrf", &ecsrf));

        debug!(
            path = ?path,
            action = ?params.first().map(|p| p.1).unwrap_or("?"), "ajax_post_request");

        let resp = self.client.post(&url).form(&form_params).send().await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            bail!("AJAX request failed with status {}: {}", status, body);
        }

        debug!(
            status = ?status.as_u16(),
            bytes = ?body.len(),
            body_preview = ?&body[..body.len().min(500)], "ajax_post_response");

        // Detect server-side error responses (e.g. expired CSRF token).
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(err) = obj.get("error").and_then(|v| v.as_str()) {
                let trimmed = err.trim();
                if !trimmed.is_empty() {
                    bail!("server error: {}", trimmed);
                }
            }
        }

        serde_json::from_str(&body).with_context(|| {
            format!(
                "failed to parse AJAX response: {}",
                &body[..body.len().min(200)]
            )
        })
    }
}

/// Extract the value of a hidden input field by name from an HTML document.
fn extract_input_value(doc: &Html, name: &str) -> Option<String> {
    let selector = Selector::parse(&format!("input[name=\"{}\"]", name)).ok()?;
    doc.select(&selector)
        .next()
        .and_then(|el| el.value().attr("value"))
        .map(String::from)
}

/// Extract the ecsrf token from the #eui_data div's data-json attribute.
fn extract_ecsrf(html: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    let selector = Selector::parse("#eui_data, #air_data").ok()?;
    for el in doc.select(&selector) {
        if let Some(json_str) = el.value().attr("data-json") {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(ecsrf) = obj.get("ecsrf").and_then(|v| v.as_str()) {
                    return Some(ecsrf.to_string());
                }
            }
        }
    }
    None
}

/// Compute the af3 cookie value from an aek_id string.
/// Replicates the JavaScript computation in /entry/index.js.
fn compute_af3(aek_id: &str) -> i64 {
    let mut result: i64 = 0;
    for c in aek_id.chars() {
        let code = c as i64;
        let computed = code * code * 30;
        result %= computed;
        result += computed;
        result += 18;
    }
    result
}

/// GET a URL and follow up to 10 redirects, solving entry gates inline.
async fn follow_redirects(
    client: &reqwest::Client,
    cookie_store: &Arc<CookieStoreMutex>,
    url: &str,
) -> anyhow::Result<reqwest::Response> {
    let mut current_url = url.to_string();
    for _ in 0..10 {
        let resp = client
            .get(&current_url)
            .send()
            .await
            .with_context(|| format!("failed to GET {}", current_url))?;

        if resp.status().is_redirection() {
            if let Some(location) = resp.headers().get("location") {
                let loc = location.to_str().unwrap_or("/");
                let redirect_url = if loc.starts_with('/') {
                    format!("{}{}", BASE_URL, loc)
                } else {
                    loc.to_string()
                };

                // Detect entry gate and solve it instead of following to the JS page.
                if redirect_url.contains("/entry/") {
                    if let Ok(parsed) = reqwest::Url::parse(&redirect_url) {
                        if let Some(aek_id) = parsed
                            .query_pairs()
                            .find(|(k, _)| k == "aek_id")
                            .map(|(_, v)| v.to_string())
                        {
                            let af3 = compute_af3(&aek_id);
                            let cookie_url =
                                reqwest::Url::parse("https://airvpn.org/").expect("valid URL");
                            let raw = cookie::Cookie::build(("af3", af3.to_string()))
                                .domain("airvpn.org")
                                .path("/")
                                .secure(true)
                                .build();
                            if let Ok(mut store) = cookie_store.lock() {
                                let _ = store.insert_raw(&raw, &cookie_url);
                            }
                            debug!( af3 = ?af3, "entry_gate_solved");

                            // Redirect to aek_url (the original destination)
                            if let Some(aek_url) = parsed
                                .query_pairs()
                                .find(|(k, _)| k == "aek_url")
                                .map(|(_, v)| v.to_string())
                            {
                                current_url = if aek_url.starts_with('/') {
                                    format!("{}{}", BASE_URL, aek_url)
                                } else {
                                    aek_url
                                };
                                continue;
                            }
                        }
                    }
                }

                current_url = redirect_url;
                debug!( url = ?current_url.as_str(), "redirect_follow");
                continue;
            }
        }
        return Ok(resp);
    }
    bail!("too many redirects following {}", url)
}

// ── REST API client (API key auth) ──────────────────────────────

const API_BASE_URL: &str = "https://airvpn.org/api";
const API_KEY_NAME: &str = "tunmux";

pub struct AirVpnWebApi {
    client: reqwest::Client,
    api_key: String,
}

impl AirVpnWebApi {
    /// Create with an explicit API key.
    pub fn with_key(api_key: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("tunmux/0.1")
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            client,
            api_key: api_key.to_string(),
        })
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Recover an existing API key via web session, or create one if none exist.
    pub async fn from_web(web: &AirVpnWeb) -> anyhow::Result<Self> {
        let keys = web.list_api_keys().await?;

        let secret = if let Some(k) = keys.first() {
            debug!( name = ?k.name.as_str(), "api_key_selected_existing");
            k.secret.clone()
        } else {
            debug!("api_key_create_required");
            let id = web.add_api_key().await?;
            web.rename_api_key(&id, API_KEY_NAME).await?;
            let keys = web.list_api_keys().await?;
            keys.iter()
                .find(|k| k.id == id)
                .context("failed to find newly created API key")?
                .secret
                .clone()
        };

        Self::with_key(&secret)
    }

    /// Build from a stored session, falling back to web provisioning.
    /// Updates the session's api_key field if a new key was provisioned.
    pub async fn from_session(
        session: &mut super::models::AirSession,
        config: &AppConfig,
    ) -> anyhow::Result<Self> {
        // Try stored key first.
        if let Some(ref key) = session.api_key {
            if !key.is_empty() {
                debug!("api_key_selected_stored");
                return Self::with_key(key);
            }
        }

        // Fall back to web provisioning.
        let web = AirVpnWeb::login_or_restore(&session.username, &session.password).await?;
        let api = Self::from_web(&web).await?;
        web.save();

        // Persist the key in the session for next time.
        session.api_key = Some(api.api_key.clone());
        config::save_session(Provider::AirVpn, session, config)?;

        Ok(api)
    }

    /// GET an API endpoint, returning the parsed JSON response.
    #[allow(dead_code)]
    pub async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        let url = format!("{}/{}/", API_BASE_URL, path.trim_matches('/'));
        debug!( url = ?url.as_str(), "api_get_request");

        let resp = self
            .client
            .get(&url)
            .header("api-key", &self.api_key)
            .header("x-requested-with", "XMLHttpRequest")
            .query(query)
            .send()
            .await
            .context("API request failed")?;

        self.parse_response(path, resp).await
    }

    /// POST form data to an API endpoint, returning the parsed JSON response.
    #[allow(dead_code)]
    pub async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        let url = format!("{}/{}/", API_BASE_URL, path.trim_matches('/'));
        debug!( url = ?url.as_str(), "api_post_request");

        let resp = self
            .client
            .post(&url)
            .header("api-key", &self.api_key)
            .header("x-requested-with", "XMLHttpRequest")
            .form(form)
            .send()
            .await
            .context("API request failed")?;

        self.parse_response(path, resp).await
    }

    /// POST form data to an API endpoint, returning the raw text body.
    pub async fn post_text(&self, path: &str, form: &[(&str, &str)]) -> anyhow::Result<String> {
        let url = format!("{}/{}/", API_BASE_URL, path.trim_matches('/'));
        debug!( url = ?url.as_str(), "api_post_request");

        let resp = self
            .client
            .post(&url)
            .header("api-key", &self.api_key)
            .header("x-requested-with", "XMLHttpRequest")
            .form(form)
            .send()
            .await
            .context("API request failed")?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            bail!(
                "API {} returned {}: {}",
                path,
                status,
                &body[..body.len().min(500)]
            );
        }

        debug!(
            status = ?status.as_u16(),
            bytes = ?body.len(), "api_response_received");

        // Check for JSON error responses.
        if body.starts_with('{') {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(err) = obj.get("error").and_then(|v| v.as_str()) {
                    bail!("API error: {}", err);
                }
                if let Some(result) = obj.get("result").and_then(|v| v.as_str()) {
                    if result != "ok" {
                        bail!("generator: {}", result);
                    }
                }
            }
        }

        Ok(body)
    }

    /// POST form data to an API endpoint, returning raw bytes and content-type.
    pub async fn post_bytes(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> anyhow::Result<(Vec<u8>, String)> {
        let url = format!("{}/{}/", API_BASE_URL, path.trim_matches('/'));
        debug!( url = ?url.as_str(), "api_post_bytes_request");

        let resp = self
            .client
            .post(&url)
            .header("api-key", &self.api_key)
            .header("x-requested-with", "XMLHttpRequest")
            .form(form)
            .send()
            .await
            .context("API request failed")?;

        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if !status.is_success() {
            let body = resp.text().await?;
            bail!(
                "API {} returned {}: {}",
                path,
                status,
                &body[..body.len().min(500)]
            );
        }

        let data = resp.bytes().await?.to_vec();
        debug!(
            status = ?status.as_u16(),
            bytes = ?data.len(),
            content_type = ?content_type.as_str(), "api_response_bytes_received");

        // If the server returned JSON, check for errors.
        if content_type.contains("json") || data.first() == Some(&b'{') {
            if let Ok(text) = std::str::from_utf8(&data) {
                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text) {
                    if let Some(err) = obj.get("error").and_then(|v| v.as_str()) {
                        bail!("API error: {}", err);
                    }
                    if let Some(result) = obj.get("result").and_then(|v| v.as_str()) {
                        if result != "ok" {
                            bail!("generator: {}", result);
                        }
                    }
                }
            }
        }

        Ok((data, content_type))
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        resp: reqwest::Response,
    ) -> anyhow::Result<T> {
        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            bail!(
                "API {} returned {}: {}",
                path,
                status,
                &body[..body.len().min(500)]
            );
        }

        debug!(
            status = ?status.as_u16(),
            bytes = ?body.len(), "api_response_received");

        serde_json::from_str(&body).with_context(|| {
            format!(
                "failed to parse API response: {}",
                &body[..body.len().min(300)]
            )
        })
    }
}

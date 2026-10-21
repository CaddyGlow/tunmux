use std::cmp::Ordering;
use std::time::Duration;

use crate::config::{self, AppConfig, Provider};
use crate::error;
use crate::shared::connection_ops::{self, ConnectOptions};
use crate::shared::latency::{self, latency_order};
use crate::wireguard;

use super::api::AirVpnClient;
use super::models::{AirServer, AirSession};

pub const PROVIDER: Provider = Provider::AirVpn;
const INTERFACE_NAME: &str = "airvpn0";
const MANIFEST_FILE: &str = "manifest.json";

/// Parameters for `connect`, the non-clap counterpart of `tunmux connect airvpn`.
#[derive(Clone, Debug, Default)]
pub struct ConnectRequest {
    pub server: Option<String>,
    pub country: Option<String>,
    /// Device key name; `None` uses `airvpn.default_device`.
    pub key: Option<String>,
    /// One of `score`, `load`, `name` or `latency`.
    pub sort: String,
    pub opts: ConnectOptions,
}

/// Log in, then save the session and the server list.
pub async fn login(
    username: &str,
    password: &str,
    config: &AppConfig,
) -> anyhow::Result<crate::api::LoginOutcome> {
    let client = AirVpnClient::new()?;

    // Authenticate
    let session = client.login(username, password).await?;
    crate::progress!(
        "Authenticated as {} ({} WireGuard key(s))",
        username,
        session.keys.len()
    );

    // Fetch manifest (server list)
    let manifest = client.fetch_manifest(username, password).await?;
    crate::progress!("Fetched {} servers", manifest.servers.len());

    // Save session and manifest
    config::save_session(PROVIDER, &session, config)?;
    save_manifest(&manifest)?;

    Ok(crate::api::LoginOutcome::LoggedIn {
        account: username.to_string(),
        detail: format!("{} WireGuard key(s)", session.keys.len()),
    })
}

/// Servers from the list saved at login.
pub fn server_list() -> anyhow::Result<Vec<crate::api::ServerInfo>> {
    let manifest = load_manifest()?;
    Ok(manifest
        .servers
        .iter()
        .map(|s| crate::api::ServerInfo {
            provider: PROVIDER,
            name: s.name.clone(),
            country_code: s.country_code.to_uppercase(),
            city: s.location.clone(),
            load: Some(airvpn_load_perc(s) as f32),
            score: None,
            tags: if airvpn_server_matches_tags(s, &["ipv6".into()]) {
                vec!["ipv6".into()]
            } else {
                Vec::new()
            },
        })
        .collect())
}

pub async fn logout(config: &AppConfig) -> anyhow::Result<()> {
    // Disconnect any direct connection if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME)
        || wireguard::userspace::is_interface_active(INTERFACE_NAME)
    {
        crate::progress!("Disconnecting active VPN connection...");
        disconnect_instance_direct(config)?;
    }

    config::delete_session(PROVIDER, config)?;

    // Also remove manifest
    let manifest_path = config::config_dir(PROVIDER).join(MANIFEST_FILE);
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path)?;
    }

    crate::progress!("Logged out");
    Ok(())
}

pub fn airvpn_load_ratio(server: &super::models::AirServer) -> f64 {
    airvpn_load_perc(server) as f64
}

fn airvpn_load_perc(server: &AirServer) -> i64 {
    if server.bandwidth_max <= 0 {
        return 100;
    }
    let bw_cur_mbit = server
        .bandwidth
        .saturating_mul(2)
        .saturating_mul(8)
        .saturating_div(1_000_000);
    bw_cur_mbit
        .saturating_mul(100)
        .saturating_div(server.bandwidth_max)
        .max(0)
}

fn airvpn_users_perc(server: &AirServer) -> i64 {
    if server.users_max <= 0 {
        return 100;
    }
    server
        .users
        .saturating_mul(100)
        .saturating_div(server.users_max)
        .max(0)
}

pub fn airvpn_eddie_speed_score(server: &AirServer, latency: Option<Duration>) -> i64 {
    let Some(latency) = latency else {
        return 99_995;
    };
    let ping = latency.as_millis().min(i64::MAX as u128) as i64;
    ping.saturating_add(airvpn_load_perc(server))
        .saturating_add(airvpn_users_perc(server))
        .saturating_add(server.score_base.max(0))
}

pub async fn probe_airvpn_latencies(
    servers: &[AirServer],
    entry_idx: usize,
    port: u16,
) -> Vec<Option<Duration>> {
    let mut targets: Vec<(String, u16)> = Vec::new();
    let mut target_indexes: Vec<usize> = Vec::new();
    for (idx, server) in servers.iter().enumerate() {
        if let Some(ip) = server
            .ips_entry
            .get(entry_idx)
            .or_else(|| server.ips_entry.first())
        {
            targets.push((ip.clone(), port));
            target_indexes.push(idx);
        }
    }

    let measured = latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;
    let mut latencies = vec![None; servers.len()];
    for (probe_idx, latency) in measured.into_iter().enumerate() {
        if let Some(server_idx) = target_indexes.get(probe_idx) {
            latencies[*server_idx] = latency;
        }
    }

    latencies
}

pub async fn connect(args: ConnectRequest, config: &AppConfig) -> anyhow::Result<()> {
    let backend = connection_ops::resolve_opts(&args.opts, &config.general.backend)?;

    // Apply config defaults -- CLI flags override config
    let effective_country = args
        .country
        .or_else(|| config.default_country_for(PROVIDER).map(str::to_owned));
    let effective_key = args.key.or_else(|| config.airvpn.default_device.clone());

    let session: AirSession = config::load_session(PROVIDER, config)?;
    let manifest = load_manifest()?;

    // Select WireGuard key by name, or use the first one
    let wg_key = if let Some(ref name) = effective_key {
        session
            .keys
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                let available: Vec<&str> = session.keys.iter().map(|k| k.name.as_str()).collect();
                error::AppError::Other(format!(
                    "key {:?} not found. Available: {}",
                    name,
                    available.join(", ")
                ))
            })?
    } else {
        session
            .keys
            .first()
            .ok_or_else(|| error::AppError::Other("no WireGuard keys in session".into()))?
    };

    // Need at least one WireGuard mode
    let wg_mode = manifest
        .wg_modes
        .first()
        .ok_or_else(|| error::AppError::Other("no WireGuard modes in manifest".into()))?;

    // Select server
    let mut candidates = manifest.servers;

    let server = if let Some(ref name) = args.server {
        candidates
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| error::AppError::NoServerFound)?
    } else {
        // Apply filters
        if let Some(ref cc) = effective_country {
            let cc_upper = cc.to_uppercase();
            candidates.retain(|s| s.country_code.eq_ignore_ascii_case(&cc_upper));
        }

        if args.sort == "latency" || args.sort == "score" {
            let latencies =
                probe_airvpn_latencies(&candidates, wg_mode.entry_index as usize, wg_mode.port)
                    .await;
            candidates
                .iter()
                .zip(latencies)
                .map(|(server, latency)| {
                    let score = airvpn_eddie_speed_score(server, latency);
                    (server, latency, score)
                })
                .min_by(|a, b| match args.sort.as_str() {
                    "latency" => latency_order(&a.1, &b.1)
                        .then_with(|| a.2.cmp(&b.2))
                        .then_with(|| a.0.name.cmp(&b.0.name)),
                    "score" => {
                        a.2.cmp(&b.2)
                            .then_with(|| latency_order(&a.1, &b.1))
                            .then_with(|| a.0.name.cmp(&b.0.name))
                    }
                    _ => unreachable!(),
                })
                .map(|(server, _, _)| server)
                .ok_or(error::AppError::NoServerFound)?
        } else {
            candidates
                .iter()
                .min_by(|a, b| match args.sort.as_str() {
                    "name" => a.name.cmp(&b.name),
                    "load" => airvpn_load_ratio(a)
                        .partial_cmp(&airvpn_load_ratio(b))
                        .unwrap_or(Ordering::Equal)
                        .then_with(|| a.name.cmp(&b.name)),
                    _ => unreachable!(),
                })
                .ok_or(error::AppError::NoServerFound)?
        }
    };

    let server_ip = server
        .ips_entry
        .get(wg_mode.entry_index as usize)
        .or_else(|| server.ips_entry.first())
        .map(String::as_str)
        .ok_or_else(|| error::AppError::NoServerFound)?;
    let mut addresses: Vec<&str> = Vec::new();
    if !wg_key.wg_ipv4.is_empty() {
        addresses.push(wg_key.wg_ipv4.as_str());
    }
    if !wg_key.wg_ipv6.is_empty() {
        addresses.push(wg_key.wg_ipv6.as_str());
    }

    let mut dns_servers: Vec<&str> = Vec::new();
    if !wg_key.wg_dns_ipv4.is_empty() {
        dns_servers.push(wg_key.wg_dns_ipv4.as_str());
    }
    if !wg_key.wg_dns_ipv6.is_empty() {
        dns_servers.push(wg_key.wg_dns_ipv6.as_str());
    }

    let preshared = if wg_key.wg_preshared.is_empty() {
        None
    } else {
        Some(wg_key.wg_preshared.as_str())
    };

    let params = wireguard::config::WgConfigParams {
        private_key: &wg_key.wg_private_key,
        addresses: &addresses,
        dns_servers: &dns_servers,
        mtu: args.opts.mtu,
        server_public_key: &session.wg_public_key,
        server_ip,
        server_port: wg_mode.port,
        preshared_key: preshared,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    let server_name = &server.name;
    connection_ops::connect_routed(
        &connection_ops::ResolvedServer {
            instance_seed: server_name,
            display_name: server_name,
        },
        &params,
        &args.opts,
        backend,
        PROVIDER,
        INTERFACE_NAME,
        config,
    )
}

pub fn airvpn_server_matches_tags(server: &super::models::AirServer, tags: &[String]) -> bool {
    tags.iter().all(|tag| {
        if tag == "ipv6" {
            return server.ips_entry.iter().any(|ip| ip.contains(':'));
        }

        server.name.to_ascii_lowercase().contains(tag)
            || server.country_code.to_ascii_lowercase().contains(tag)
            || server.location.to_ascii_lowercase().contains(tag)
            || server.group.to_ascii_lowercase().contains(tag)
    })
}

pub fn disconnect(instance: Option<String>, all: bool, config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_provider(PROVIDER, instance, all, config, true)
}

fn disconnect_instance_direct(config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_instance_direct(|state| {
        connection_ops::disconnect_one_provider_connection(state, PROVIDER, config, true)
    })
}

fn save_manifest(manifest: &super::models::AirManifest) -> anyhow::Result<()> {
    config::save_manifest(PROVIDER, MANIFEST_FILE, manifest)?;
    Ok(())
}

pub fn load_manifest() -> anyhow::Result<super::models::AirManifest> {
    Ok(config::load_manifest(PROVIDER, MANIFEST_FILE)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server(
        bandwidth: i64,
        bandwidth_max: i64,
        users: i64,
        users_max: i64,
        score_base: i64,
    ) -> AirServer {
        AirServer {
            name: "Castor".to_string(),
            ips_entry: vec!["1.2.3.4".to_string()],
            country_code: "NL".to_string(),
            location: "Amsterdam".to_string(),
            score_base,
            bandwidth,
            bandwidth_max,
            users,
            users_max,
            group: "earth".to_string(),
        }
    }

    #[test]
    fn test_airvpn_load_perc_matches_eddie_formula() {
        let server = make_server(50_000_000, 1000, 10, 100, 0);
        // Eddie formula: load = ((2 * bw * 8) / 1_000_000) * 100 / bw_max.
        assert_eq!(airvpn_load_perc(&server), 80);
    }

    #[test]
    fn test_airvpn_eddie_speed_score_prefers_lower_latency() {
        let server = make_server(25_000_000, 1000, 20, 100, 5);
        let fast = airvpn_eddie_speed_score(&server, Some(Duration::from_millis(20)));
        let slow = airvpn_eddie_speed_score(&server, Some(Duration::from_millis(60)));
        assert!(fast < slow);
    }

    #[test]
    fn test_airvpn_eddie_speed_score_penalizes_missing_latency() {
        let server = make_server(0, 1000, 0, 100, 0);
        let with_ping = airvpn_eddie_speed_score(&server, Some(Duration::from_millis(40)));
        let missing_ping = airvpn_eddie_speed_score(&server, None);
        assert!(with_ping < missing_ping);
        assert_eq!(missing_ping, 99_995);
    }
}

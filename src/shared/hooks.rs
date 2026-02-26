use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::config::{AppConfig, HookConfig, Provider};
use crate::wireguard::connection::ConnectionState;

#[derive(Clone, Copy)]
enum HookEvent {
    IfUp,
    IfDown,
}

#[derive(Clone, Copy)]
enum BuiltinHook {
    Connectivity,
    ExternalIp,
    DnsDetection,
}

#[derive(Debug, Clone, Default)]
struct HookRuntime {
    http_proxy_url: Option<String>,
    all_proxy_url: Option<String>,
    vpn_dns_servers: Vec<String>,
}

impl HookRuntime {
    fn from_state(state: &ConnectionState) -> Self {
        let http_proxy_url = state
            .http_port
            .map(|port| format!("http://127.0.0.1:{}", port));
        let all_proxy_url = state
            .socks_port
            .map(|port| format!("socks5h://127.0.0.1:{}", port));
        let vpn_dns_servers = state
            .dns_servers
            .iter()
            .map(|s| normalize_dns_server(s))
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            http_proxy_url,
            all_proxy_url,
            vpn_dns_servers,
        }
    }

    fn request_proxy_url(&self) -> Option<&str> {
        self.http_proxy_url
            .as_deref()
            .or(self.all_proxy_url.as_deref())
    }

    fn vpn_dns_servers(&self) -> &[String] {
        &self.vpn_dns_servers
    }
}

const DNS_DETECTION_SESSION_LEN: usize = 40;
const DNS_DETECTION_PROBES: u8 = 10;
const DNS_DETECTION_HTTP_TIMEOUT_SECS: u64 = 4;
const DNS_DETECTION_INTER_PROBE_DELAY_MS: u64 = 100;
const DNS_PTR_LOOKUP_CMD_TIMEOUT_MS: u64 = 1200;
const DNS_PTR_MAX_LOOKUP_SERVERS: usize = 1;
const IPINFO_IPV4_URLS: [&str; 2] = ["https://ipinfo.io", "http://ipinfo.io"];
const IPINFO_IPV6_URLS: [&str; 2] = ["https://v6.ipinfo.io", "http://v6.ipinfo.io"];

impl HookEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::IfUp => "ifup",
            Self::IfDown => "ifdown",
        }
    }
}

pub fn run_ifup(config: &AppConfig, provider: Provider, state: &ConnectionState) {
    run_event(config, provider, state, HookEvent::IfUp);
}

pub fn run_ifdown(config: &AppConfig, provider: Provider, state: &ConnectionState) {
    run_event(config, provider, state, HookEvent::IfDown);
}

pub fn run_builtin(entry: &str) -> anyhow::Result<()> {
    run_builtin_with_runtime(entry, None)
}

pub fn run_builtin_for_state(entry: &str, state: &ConnectionState) -> anyhow::Result<()> {
    let runtime = HookRuntime::from_state(state);
    run_builtin_with_runtime(entry, Some(&runtime))
}

pub fn debug_ifup_env(provider: Provider, state: &ConnectionState) -> Vec<(String, String)> {
    debug_env_for_event(provider, state, HookEvent::IfUp)
}

pub fn debug_ifdown_env(provider: Provider, state: &ConnectionState) -> Vec<(String, String)> {
    debug_env_for_event(provider, state, HookEvent::IfDown)
}

fn run_event(config: &AppConfig, provider: Provider, state: &ConnectionState, event: HookEvent) {
    let entries = collect_hook_entries(config, provider, event);
    if entries.is_empty() {
        return;
    }

    let env = build_hook_env(event, provider, state);
    let runtime = HookRuntime::from_state(state);
    for hook_entry in entries {
        if let Err(err) = run_hook_entry(&hook_entry, &env, Some(&runtime)) {
            tracing::warn!(
                provider = provider.dir_name(),
                instance = state.instance_name.as_str(),
                event = event.as_str(),
                hook = hook_entry.as_str(),
                error = %err,
                "hook_execution_failed"
            );
        }
    }
}

fn collect_hook_entries(config: &AppConfig, provider: Provider, event: HookEvent) -> Vec<String> {
    let mut entries = Vec::new();
    entries.extend(
        entries_for_event(&config.general.hooks, event)
            .iter()
            .cloned(),
    );
    entries.extend(
        entries_for_event(provider_hooks(config, provider), event)
            .iter()
            .cloned(),
    );
    entries
}

fn provider_hooks(config: &AppConfig, provider: Provider) -> &HookConfig {
    match provider {
        Provider::Proton => &config.proton.hooks,
        Provider::AirVpn => &config.airvpn.hooks,
        Provider::Mullvad => &config.mullvad.hooks,
        Provider::Ivpn => &config.ivpn.hooks,
        Provider::Wgconf => &config.wgconf.hooks,
    }
}

fn entries_for_event(hooks: &HookConfig, event: HookEvent) -> &[String] {
    match event {
        HookEvent::IfUp => &hooks.ifup,
        HookEvent::IfDown => &hooks.ifdown,
    }
}

fn build_hook_env(
    event: HookEvent,
    provider: Provider,
    state: &ConnectionState,
) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("TUNMUX_HOOK_EVENT".to_string(), event.as_str().to_string());
    env.insert(
        "TUNMUX_PROVIDER".to_string(),
        provider.dir_name().to_string(),
    );
    env.insert(
        "TUNMUX_INSTANCE".to_string(),
        state.instance_name.to_string(),
    );
    env.insert("TUNMUX_BACKEND".to_string(), state.backend.to_string());
    env.insert(
        "TUNMUX_INTERFACE".to_string(),
        state.interface_name.to_string(),
    );
    env.insert(
        "TUNMUX_SERVER".to_string(),
        state.server_display_name.to_string(),
    );
    env.insert(
        "TUNMUX_ENDPOINT".to_string(),
        state.server_endpoint.to_string(),
    );

    if let Some(namespace_name) = &state.namespace_name {
        env.insert("TUNMUX_NAMESPACE".to_string(), namespace_name.to_string());
    }
    if let Some(socks_port) = state.socks_port {
        let socks = socks_port.to_string();
        let all_proxy = format!("socks5h://127.0.0.1:{}", socks_port);
        env.insert("TUNMUX_SOCKS_PORT".to_string(), socks);
        env.insert("ALL_PROXY".to_string(), all_proxy.clone());
        env.insert("all_proxy".to_string(), all_proxy);
    }
    if let Some(http_port) = state.http_port {
        let http = http_port.to_string();
        let http_proxy = format!("http://127.0.0.1:{}", http_port);
        env.insert("TUNMUX_HTTP_PORT".to_string(), http);
        env.insert("HTTP_PROXY".to_string(), http_proxy.clone());
        env.insert("HTTPS_PROXY".to_string(), http_proxy.clone());
        env.insert("http_proxy".to_string(), http_proxy.clone());
        env.insert("https_proxy".to_string(), http_proxy);
    }
    if let Some(proxy_pid) = state.proxy_pid {
        env.insert("TUNMUX_PROXY_PID".to_string(), proxy_pid.to_string());
    }
    if !state.dns_servers.is_empty() {
        env.insert(
            "TUNMUX_DNS_SERVERS".to_string(),
            state.dns_servers.join(","),
        );
    }

    env
}

fn debug_env_for_event(
    provider: Provider,
    state: &ConnectionState,
    event: HookEvent,
) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> =
        build_hook_env(event, provider, state).into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

fn run_builtin_with_runtime(entry: &str, runtime: Option<&HookRuntime>) -> anyhow::Result<()> {
    let builtin = builtin_from_entry(entry)
        .ok_or_else(|| anyhow::anyhow!("unknown builtin hook: {}", entry))?;
    run_builtin_kind(builtin, runtime)
}

fn run_hook_entry(
    entry: &str,
    env: &HashMap<String, String>,
    runtime: Option<&HookRuntime>,
) -> anyhow::Result<()> {
    let hook = entry.trim();
    if hook.is_empty() {
        return Ok(());
    }

    if let Some(builtin) = builtin_from_entry(hook) {
        return run_builtin_kind(builtin, runtime);
    }

    run_shell_hook(hook, env)
}

fn builtin_from_entry(entry: &str) -> Option<BuiltinHook> {
    match entry.trim() {
        "builtin:connectivity" | "connectivity" => Some(BuiltinHook::Connectivity),
        "builtin:external-ip" | "external-ip" => Some(BuiltinHook::ExternalIp),
        "builtin:dns-detection" | "dns-detection" => Some(BuiltinHook::DnsDetection),
        _ => None,
    }
}

fn run_builtin_kind(builtin: BuiltinHook, runtime: Option<&HookRuntime>) -> anyhow::Result<()> {
    match builtin {
        BuiltinHook::Connectivity => run_builtin_connectivity(runtime),
        BuiltinHook::ExternalIp => run_builtin_external_ip(runtime),
        BuiltinHook::DnsDetection => run_builtin_dns_detection(runtime),
    }
}

fn run_shell_hook(command: &str, env: &HashMap<String, String>) -> anyhow::Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .envs(env)
        .status()
        .with_context(|| format!("failed to run hook command {:?}", command))?;

    if status.success() {
        return Ok(());
    }

    anyhow::bail!("hook command {:?} exited with {}", command, status)
}

fn run_builtin_connectivity(runtime: Option<&HookRuntime>) -> anyhow::Result<()> {
    let use_proxy_connectivity = runtime.and_then(HookRuntime::request_proxy_url).is_some();
    let ipv4 = if use_proxy_connectivity {
        Ok(())
    } else {
        ping_ipv4()
    };
    let ipv6 = if use_proxy_connectivity {
        Ok(())
    } else {
        ping_ipv6()
    };
    let (ipv4_info, ipv6_info) = fetch_connectivity_ipinfo_pair(runtime);

    let ipv4_status = if use_proxy_connectivity {
        if ipv4_info.is_some() {
            "ok"
        } else {
            "failed"
        }
    } else if ipv4.is_ok() {
        "ok"
    } else {
        "failed"
    };
    let ipv6_status = if use_proxy_connectivity {
        if ipv6_info.is_some() {
            "ok"
        } else {
            "failed"
        }
    } else if ipv6.is_ok() {
        "ok"
    } else {
        "failed"
    };

    println!(
        "Hook connectivity ipv4: status={} country={} city={} ip={} org={}",
        ipv4_status,
        summary_country(ipv4_info.as_ref()),
        summary_city(ipv4_info.as_ref()),
        summary_ip(ipv4_info.as_ref()),
        summary_org(ipv4_info.as_ref())
    );
    println!(
        "Hook connectivity ipv6: status={} country={} city={} ip={} org={}",
        ipv6_status,
        summary_country(ipv6_info.as_ref()),
        summary_city(ipv6_info.as_ref()),
        summary_ip(ipv6_info.as_ref()),
        summary_org(ipv6_info.as_ref())
    );

    if use_proxy_connectivity {
        if ipv4_info.is_none() {
            anyhow::bail!("ipv4 connectivity check failed via proxy");
        }
        if ipv6_info.is_none() {
            anyhow::bail!("ipv6 connectivity check failed via proxy");
        }
    } else {
        if let Err(err) = ipv4 {
            anyhow::bail!("ipv4 connectivity check failed: {}", err);
        }
        if let Err(err) = ipv6 {
            anyhow::bail!("ipv6 connectivity check failed: {}", err);
        }
    }
    Ok(())
}

fn ping_ipv4() -> anyhow::Result<()> {
    run_command_checked("ping", &["-c", "1", "1.1.1.1"])
}

fn ping_ipv6() -> anyhow::Result<()> {
    run_command_checked("ping", &["-6", "-c", "1", "2606:4700:4700::1111"])
        .or_else(|_| run_command_checked("ping6", &["-c", "1", "2606:4700:4700::1111"]))
}

fn run_builtin_external_ip(runtime: Option<&HookRuntime>) -> anyhow::Result<()> {
    let runtime = runtime.cloned();
    let (ipv4, ipv4_err, ipv6, ipv6_err) = run_hook_blocking(move || {
        run_with_http_client(
            Duration::from_secs(6),
            runtime.as_ref(),
            "external-ip check",
            |client| {
                let (ipv4, ipv4_err) =
                    fetch_ipinfo_summary_optional(client, &IPINFO_IPV4_URLS, "IPv4");
                let (ipv6, ipv6_err) =
                    fetch_ipinfo_summary_optional(client, &IPINFO_IPV6_URLS, "IPv6");

                if ipv4.is_none() && ipv6.is_none() {
                    anyhow::bail!(
                        "external-ip check failed: {} | {}",
                        ipv4_err
                            .as_deref()
                            .unwrap_or("IPv4 lookup failed without details"),
                        ipv6_err
                            .as_deref()
                            .unwrap_or("IPv6 lookup failed without details")
                    );
                }

                Ok((ipv4, ipv4_err, ipv6, ipv6_err))
            },
        )
    })?;

    match ipv4 {
        Some(ipv4) => println!(
            "Hook external-ip ipv4: ip={} country={} city={} org={}",
            ipv4.ip,
            summary_country(Some(&ipv4)),
            summary_city(Some(&ipv4)),
            summary_org(Some(&ipv4))
        ),
        None => println!(
            "Hook external-ip ipv4: unavailable ({})",
            ipv4_err.as_deref().unwrap_or("request failed")
        ),
    }
    match ipv6 {
        Some(ipv6) => println!(
            "Hook external-ip ipv6: ip={} country={} city={} org={}",
            ipv6.ip,
            summary_country(Some(&ipv6)),
            summary_city(Some(&ipv6)),
            summary_org(Some(&ipv6))
        ),
        None => println!(
            "Hook external-ip ipv6: unavailable ({})",
            ipv6_err.as_deref().unwrap_or("request failed")
        ),
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct DnsDetectionResponse {
    session: String,
    #[serde(default, deserialize_with = "deserialize_dns_detection_ip")]
    ip: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug)]
struct DnsResolverEntry {
    ip: String,
    count: u64,
    ptr_name: Option<String>,
}

fn run_builtin_dns_detection(runtime: Option<&HookRuntime>) -> anyhow::Result<()> {
    let session = random_dns_detection_session(DNS_DETECTION_SESSION_LEN);
    let session_for_worker = session.clone();
    let runtime = runtime.cloned();
    let resolvers = run_hook_blocking(move || {
        run_with_http_client(
            Duration::from_secs(DNS_DETECTION_HTTP_TIMEOUT_SECS),
            runtime.as_ref(),
            "dns-detection check",
            |client| {
                let mut aggregate = std::collections::BTreeMap::new();
                for probe in 1..=DNS_DETECTION_PROBES {
                    let response = fetch_dns_detection(client, &session_for_worker, probe)
                        .with_context(|| format!("dns-detection probe {} failed", probe))?;

                    if response.session.len() != session_for_worker.len() {
                        tracing::warn!(
                            expected = session_for_worker.len(),
                            received = response.session.len(),
                            "dns_detection_session_length_mismatch"
                        );
                    }

                    for (ip, count) in response.ip {
                        let slot = aggregate.entry(ip).or_insert(0u64);
                        *slot = (*slot).max(count);
                    }

                    if probe < DNS_DETECTION_PROBES {
                        thread::sleep(Duration::from_millis(DNS_DETECTION_INTER_PROBE_DELAY_MS));
                    }
                }

                let lookup_servers = preferred_lookup_servers(runtime.as_ref(), &aggregate);
                let allow_system_fallback = runtime
                    .as_ref()
                    .and_then(HookRuntime::request_proxy_url)
                    .is_none();
                let mut resolvers = Vec::new();
                for (ip, count) in aggregate {
                    resolvers.push(DnsResolverEntry {
                        ptr_name: reverse_dns_lookup(&ip, &lookup_servers, allow_system_fallback),
                        ip,
                        count,
                    });
                }

                Ok(resolvers)
            },
        )
    })?;

    println!(
        "Hook dns-detection: session={} probes={} resolvers={}",
        session,
        DNS_DETECTION_PROBES,
        resolvers.len()
    );
    for resolver in resolvers {
        println!(
            "  {} ({}) ns={}",
            resolver.ip,
            resolver.count,
            resolver.ptr_name.as_deref().unwrap_or("-")
        );
    }

    Ok(())
}

fn reverse_dns_lookup(
    ip: &str,
    lookup_servers: &[String],
    allow_system_fallback: bool,
) -> Option<String> {
    for resolver in lookup_servers {
        if let Some(name) =
            run_lookup_command("nslookup", &["-timeout=1", "-retry=1", ip, resolver])
                .and_then(|stdout| parse_nslookup_output(&stdout))
        {
            return Some(name);
        }
    }

    if !allow_system_fallback {
        return None;
    }

    run_lookup_command("nslookup", &["-timeout=1", "-retry=1", ip])
        .and_then(|stdout| parse_nslookup_output(&stdout))
}

fn preferred_lookup_servers(
    runtime: Option<&HookRuntime>,
    aggregate: &std::collections::BTreeMap<String, u64>,
) -> Vec<String> {
    if let Some(runtime) = runtime {
        if !runtime.vpn_dns_servers().is_empty() {
            return runtime
                .vpn_dns_servers()
                .iter()
                .take(DNS_PTR_MAX_LOOKUP_SERVERS)
                .cloned()
                .collect();
        }
    }

    aggregate
        .keys()
        .take(DNS_PTR_MAX_LOOKUP_SERVERS)
        .cloned()
        .collect()
}

fn normalize_dns_server(value: &str) -> String {
    value
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn run_lookup_command(name: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(name)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_millis(DNS_PTR_LOOKUP_CMD_TIMEOUT_MS);
    loop {
        match child.try_wait().ok()? {
            Some(_status) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
    }

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_nslookup_output(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some((_, rhs)) = trimmed.split_once("name =") {
            let value = normalize_dns_name(rhs);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn normalize_dns_name(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '(' || c == ')')
        .to_string()
}

fn fetch_dns_detection(
    client: &Client,
    session: &str,
    probe: u8,
) -> anyhow::Result<DnsDetectionResponse> {
    let https_url = format!("https://{}-{}.ipleak.net/dnsdetection/", session, probe);
    let http_url = format!("http://{}-{}.ipleak.net/dnsdetection/", session, probe);

    let mut errors = Vec::new();
    for url in [&https_url, &http_url] {
        let parsed = client
            .get(url)
            .send()
            .with_context(|| format!("request to {} failed", url))
            .and_then(|resp| {
                resp.error_for_status()
                    .with_context(|| format!("{} returned non-success status", url))
            })
            .and_then(|resp| {
                resp.json()
                    .with_context(|| format!("failed parsing DNS detection response from {}", url))
            });

        match parsed {
            Ok(response) => return Ok(response),
            Err(err) => errors.push(format!("{}: {}", url, err)),
        }
    }

    anyhow::bail!(
        "dns detection request failed for all endpoints: {}",
        errors.join(" | ")
    )
}

fn deserialize_dns_detection_ip<'de, D>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<String, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Object(map) => {
            let mut out = std::collections::BTreeMap::new();
            for (ip, raw_count) in map {
                let count = match raw_count {
                    serde_json::Value::Number(n) => n
                        .as_u64()
                        .ok_or_else(|| D::Error::custom("dns count must be a u64"))?,
                    serde_json::Value::String(s) => s.parse::<u64>().map_err(D::Error::custom)?,
                    _ => return Err(D::Error::custom("dns count must be number or string")),
                };
                out.insert(ip, count);
            }
            Ok(out)
        }
        serde_json::Value::Array(_) | serde_json::Value::Null => {
            Ok(std::collections::BTreeMap::new())
        }
        _ => Err(D::Error::custom(
            "dns ip payload must be object, array, or null",
        )),
    }
}

fn random_dns_detection_session(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .map(|c| c.to_ascii_lowercase())
        .take(len)
        .collect()
}

#[derive(Debug, Clone)]
struct IpInfoSummary {
    ip: String,
    country: Option<String>,
    city: Option<String>,
    org: Option<String>,
}

fn fetch_connectivity_ipinfo_pair(
    runtime: Option<&HookRuntime>,
) -> (Option<IpInfoSummary>, Option<IpInfoSummary>) {
    let runtime = runtime.cloned();
    run_hook_blocking(move || {
        run_with_http_client(
            Duration::from_secs(6),
            runtime.as_ref(),
            "connectivity metadata fetch",
            |client| {
                let ipv4 = fetch_ipinfo_summary_with_fallback(client, &IPINFO_IPV4_URLS).ok();
                let ipv6 = fetch_ipinfo_summary_with_fallback(client, &IPINFO_IPV6_URLS).ok();
                Ok((ipv4, ipv6))
            },
        )
    })
    .unwrap_or((None, None))
}

fn run_with_http_client<T, F>(
    timeout: Duration,
    runtime: Option<&HookRuntime>,
    label: &str,
    operation: F,
) -> anyhow::Result<T>
where
    F: Fn(&Client) -> anyhow::Result<T>,
{
    let preferred_client = build_http_client(timeout, runtime)
        .with_context(|| format!("failed to build HTTP client for {}", label))?;
    match operation(&preferred_client) {
        Ok(value) => Ok(value),
        Err(preferred_err) => {
            let allow_direct_fallback = runtime.and_then(HookRuntime::request_proxy_url).is_none();
            if !allow_direct_fallback {
                return Err(preferred_err);
            }

            if runtime.is_none() {
                return Err(preferred_err);
            }

            tracing::warn!(
                error = %preferred_err,
                operation = label,
                "hook_http_via_proxy_failed_fallback_direct"
            );
            let direct_client = build_http_client(timeout, None)
                .with_context(|| format!("failed to build direct HTTP client for {}", label))?;
            match operation(&direct_client) {
                Ok(value) => Ok(value),
                Err(direct_err) => anyhow::bail!(
                    "{} failed via proxy ({}) and direct ({})",
                    label,
                    preferred_err,
                    direct_err
                ),
            }
        }
    }
}

fn fetch_ipinfo_summary_with_fallback(
    client: &Client,
    urls: &[&str],
) -> anyhow::Result<IpInfoSummary> {
    let mut errors = Vec::new();
    for url in urls {
        match fetch_ipinfo_summary(client, url) {
            Ok(summary) => return Ok(summary),
            Err(err) => errors.push(format!("{}: {}", url, err)),
        }
    }

    anyhow::bail!(
        "ipinfo request failed for all endpoints: {}",
        errors.join(" | ")
    )
}

fn fetch_ipinfo_summary_optional(
    client: &Client,
    urls: &[&str],
    label: &str,
) -> (Option<IpInfoSummary>, Option<String>) {
    match fetch_ipinfo_summary_with_fallback(client, urls) {
        Ok(summary) => (Some(summary), None),
        Err(err) => (None, Some(format!("{}: {}", label, err))),
    }
}

fn build_http_client(timeout: Duration, runtime: Option<&HookRuntime>) -> anyhow::Result<Client> {
    let mut builder = Client::builder().timeout(timeout);
    if let Some(proxy_url) = runtime.and_then(HookRuntime::request_proxy_url) {
        let proxy = reqwest::Proxy::all(proxy_url)
            .with_context(|| format!("invalid proxy URL for hook runtime: {}", proxy_url))?;
        builder = builder.proxy(proxy);
    }
    builder.build().context("failed to build HTTP client")
}

fn summary_country(summary: Option<&IpInfoSummary>) -> &str {
    summary
        .and_then(|info| info.country.as_deref())
        .unwrap_or("unknown")
}

fn summary_city(summary: Option<&IpInfoSummary>) -> &str {
    summary
        .and_then(|info| info.city.as_deref())
        .unwrap_or("unknown")
}

fn summary_ip(summary: Option<&IpInfoSummary>) -> &str {
    summary.map(|info| info.ip.as_str()).unwrap_or("unknown")
}

fn summary_org(summary: Option<&IpInfoSummary>) -> &str {
    summary
        .and_then(|info| info.org.as_deref())
        .unwrap_or("unknown")
}

fn fetch_ipinfo_summary(client: &Client, url: &str) -> anyhow::Result<IpInfoSummary> {
    let body = client
        .get(url)
        .send()
        .with_context(|| format!("request to {} failed", url))?
        .error_for_status()
        .with_context(|| format!("{} returned non-success status", url))?
        .text()
        .with_context(|| format!("failed reading response body from {}", url))?;

    parse_ipinfo_body(&body, url)
}

fn parse_ipinfo_body(body: &str, url: &str) -> anyhow::Result<IpInfoSummary> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                let country = json
                    .get("country")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string);
                let city = json
                    .get("city")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string);
                let org = json
                    .get("org")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string);
                return Ok(IpInfoSummary {
                    ip: trimmed.to_string(),
                    country,
                    city,
                    org,
                });
            }
        }
    }

    let first_line = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_string();
    if first_line.is_empty() {
        anyhow::bail!("{} response did not contain a usable IP", url);
    }

    Ok(IpInfoSummary {
        ip: first_line,
        country: None,
        city: None,
        org: None,
    })
}

fn run_hook_blocking<T, F>(job: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    let handle = thread::Builder::new()
        .name("tunmux-hook-worker".to_string())
        .spawn(job)
        .context("failed to spawn hook worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(anyhow!("hook worker thread panicked")),
    }
}

fn run_command_checked(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(name)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail)
}

#[cfg(test)]
mod tests {
    use crate::config::Provider;
    use crate::wireguard::backend::WgBackend;
    use crate::wireguard::connection::ConnectionState;

    #[test]
    fn debug_env_contains_core_fields() {
        let state = ConnectionState {
            instance_name: "test-instance".to_string(),
            provider: "proton".to_string(),
            interface_name: "proton0".to_string(),
            backend: WgBackend::Kernel,
            server_endpoint: "1.2.3.4:51820".to_string(),
            server_display_name: "US#1".to_string(),
            original_gateway_ip: None,
            original_gateway_iface: None,
            original_resolv_conf: None,
            namespace_name: Some("tunmux_test".to_string()),
            proxy_pid: Some(1234),
            socks_port: Some(1080),
            http_port: Some(8118),
            dns_servers: vec!["10.2.0.1".to_string()],
            peer_public_key: None,
            local_public_key: None,
            virtual_ips: vec![],
            keepalive_secs: None,
        };

        let ifup = super::debug_ifup_env(Provider::Proton, &state);
        let ifdown = super::debug_ifdown_env(Provider::Proton, &state);

        assert!(ifup
            .iter()
            .any(|(k, v)| k == "TUNMUX_HOOK_EVENT" && v == "ifup"));
        assert!(ifdown
            .iter()
            .any(|(k, v)| k == "TUNMUX_HOOK_EVENT" && v == "ifdown"));
        assert!(ifup
            .iter()
            .any(|(k, v)| k == "TUNMUX_PROVIDER" && v == "proton"));
        assert!(ifup
            .iter()
            .any(|(k, v)| k == "TUNMUX_INSTANCE" && v == "test-instance"));
        assert!(ifup
            .iter()
            .any(|(k, v)| k == "TUNMUX_PROXY_PID" && v == "1234"));
        assert!(ifup
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == "http://127.0.0.1:8118"));
        assert!(ifup
            .iter()
            .any(|(k, v)| k == "ALL_PROXY" && v == "socks5h://127.0.0.1:1080"));
    }

    #[test]
    fn hook_runtime_prefers_http_proxy_for_requests() {
        let state = ConnectionState {
            instance_name: "test-instance".to_string(),
            provider: "proton".to_string(),
            interface_name: "proton0".to_string(),
            backend: WgBackend::Kernel,
            server_endpoint: "1.2.3.4:51820".to_string(),
            server_display_name: "US#1".to_string(),
            original_gateway_ip: None,
            original_gateway_iface: None,
            original_resolv_conf: None,
            namespace_name: None,
            proxy_pid: Some(1234),
            socks_port: Some(1080),
            http_port: Some(8118),
            dns_servers: vec!["10.2.0.1".to_string()],
            peer_public_key: None,
            local_public_key: None,
            virtual_ips: vec![],
            keepalive_secs: None,
        };

        let runtime = super::HookRuntime::from_state(&state);
        assert_eq!(runtime.request_proxy_url(), Some("http://127.0.0.1:8118"));
    }

    #[test]
    fn builtin_aliases_map_correctly() {
        assert!(matches!(
            super::builtin_from_entry("builtin:connectivity"),
            Some(super::BuiltinHook::Connectivity)
        ));
        assert!(matches!(
            super::builtin_from_entry("connectivity"),
            Some(super::BuiltinHook::Connectivity)
        ));
        assert!(matches!(
            super::builtin_from_entry("builtin:external-ip"),
            Some(super::BuiltinHook::ExternalIp)
        ));
        assert!(matches!(
            super::builtin_from_entry("external-ip"),
            Some(super::BuiltinHook::ExternalIp)
        ));
        assert!(matches!(
            super::builtin_from_entry("builtin:dns-detection"),
            Some(super::BuiltinHook::DnsDetection)
        ));
        assert!(matches!(
            super::builtin_from_entry("dns-detection"),
            Some(super::BuiltinHook::DnsDetection)
        ));
        assert!(super::builtin_from_entry("builtin:missing").is_none());
    }

    #[test]
    fn dns_detection_session_has_requested_length() {
        let value = super::random_dns_detection_session(40);
        assert_eq!(value.len(), 40);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn parse_ipinfo_json_extracts_location_fields() {
        let parsed = super::parse_ipinfo_body(
            r#"{"ip":"203.0.113.4","country":"US","city":"Austin","org":"AS64500 Example"}"#,
            "https://ipinfo.io",
        )
        .expect("ipinfo JSON should parse");

        assert_eq!(parsed.ip, "203.0.113.4");
        assert_eq!(parsed.country.as_deref(), Some("US"));
        assert_eq!(parsed.city.as_deref(), Some("Austin"));
        assert_eq!(parsed.org.as_deref(), Some("AS64500 Example"));
    }

    #[test]
    fn parse_ipinfo_text_fallback_keeps_ip() {
        let parsed = super::parse_ipinfo_body("198.51.100.10\n", "https://ipinfo.io")
            .expect("text fallback should parse");

        assert_eq!(parsed.ip, "198.51.100.10");
        assert!(parsed.country.is_none());
        assert!(parsed.city.is_none());
        assert!(parsed.org.is_none());
    }

    #[test]
    fn parse_nslookup_output_extracts_ptr_name() {
        let output = "Server: 1.1.1.1\nAddress: 1.1.1.1#53\n\n230.123.185.66.in-addr.arpa\tname = resolver1.example.net.\n";
        let parsed = super::parse_nslookup_output(output);
        assert_eq!(parsed.as_deref(), Some("resolver1.example.net"));
    }

    #[test]
    fn parse_dns_detection_ip_allows_empty_array() {
        let json = r#"{"session":"abc","ip":[]}"#;
        let parsed: super::DnsDetectionResponse =
            serde_json::from_str(json).expect("dns detection response should parse");
        assert_eq!(parsed.session, "abc");
        assert!(parsed.ip.is_empty());
    }

    #[test]
    fn parse_dns_detection_ip_object_counts() {
        let json = r#"{"session":"abc","ip":{"66.185.123.230":1,"2620:171:eb:f0::230":"2"}}"#;
        let parsed: super::DnsDetectionResponse =
            serde_json::from_str(json).expect("dns detection response should parse");
        assert_eq!(parsed.ip.get("66.185.123.230"), Some(&1));
        assert_eq!(parsed.ip.get("2620:171:eb:f0::230"), Some(&2));
    }
}

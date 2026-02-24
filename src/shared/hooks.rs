use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use reqwest::blocking::Client;

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
}

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
    let builtin = builtin_from_entry(entry)
        .ok_or_else(|| anyhow::anyhow!("unknown builtin hook: {}", entry))?;
    run_builtin_kind(builtin)
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
    for hook_entry in entries {
        if let Err(err) = run_hook_entry(&hook_entry, &env) {
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
        env.insert("TUNMUX_SOCKS_PORT".to_string(), socks_port.to_string());
    }
    if let Some(http_port) = state.http_port {
        env.insert("TUNMUX_HTTP_PORT".to_string(), http_port.to_string());
    }
    if let Some(proxy_pid) = state.proxy_pid {
        env.insert("TUNMUX_PROXY_PID".to_string(), proxy_pid.to_string());
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

fn run_hook_entry(entry: &str, env: &HashMap<String, String>) -> anyhow::Result<()> {
    let hook = entry.trim();
    if hook.is_empty() {
        return Ok(());
    }

    if let Some(builtin) = builtin_from_entry(hook) {
        return run_builtin_kind(builtin);
    }

    run_shell_hook(hook, env)
}

fn builtin_from_entry(entry: &str) -> Option<BuiltinHook> {
    match entry.trim() {
        "builtin:connectivity" | "connectivity" => Some(BuiltinHook::Connectivity),
        "builtin:external-ip" | "external-ip" => Some(BuiltinHook::ExternalIp),
        _ => None,
    }
}

fn run_builtin_kind(builtin: BuiltinHook) -> anyhow::Result<()> {
    match builtin {
        BuiltinHook::Connectivity => run_builtin_connectivity(),
        BuiltinHook::ExternalIp => run_builtin_external_ip(),
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

fn run_builtin_connectivity() -> anyhow::Result<()> {
    let ipv4 = ping_ipv4();
    let ipv6 = ping_ipv6();

    println!(
        "Hook connectivity: ipv4={} ipv6={}",
        if ipv4.is_ok() { "ok" } else { "failed" },
        if ipv6.is_ok() { "ok" } else { "failed" }
    );

    if let Err(err) = ipv4 {
        anyhow::bail!("ipv4 connectivity check failed: {}", err);
    }
    if let Err(err) = ipv6 {
        anyhow::bail!("ipv6 connectivity check failed: {}", err);
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

fn run_builtin_external_ip() -> anyhow::Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .context("failed to build HTTP client for external-ip check")?;

    let ipv4 = fetch_ipinfo_ip(&client, "https://ipinfo.io")
        .context("failed external IPv4 check via https://ipinfo.io")?;
    let ipv6 = fetch_ipinfo_ip(&client, "https://v6.ipinfo.io")
        .context("failed external IPv6 check via https://v6.ipinfo.io")?;

    println!("Hook external-ip: ipv4={} ipv6={}", ipv4, ipv6);
    Ok(())
}

fn fetch_ipinfo_ip(client: &Client, url: &str) -> anyhow::Result<String> {
    let body = client
        .get(url)
        .send()
        .with_context(|| format!("request to {} failed", url))?
        .error_for_status()
        .with_context(|| format!("{} returned non-success status", url))?
        .text()
        .with_context(|| format!("failed reading response body from {}", url))?;

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
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

    Ok(first_line)
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
        assert!(super::builtin_from_entry("builtin:missing").is_none());
    }
}

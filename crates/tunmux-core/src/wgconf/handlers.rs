use std::fs;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::config::{self, AppConfig, Provider};
use crate::shared::connection_ops::{self, ConnectOptions};
use crate::wireguard;

const PROVIDER: Provider = Provider::Wgconf;
const INTERFACE_NAME: &str = "wgconf0";
const PROFILE_DIR: &str = "profiles";

struct ConfigSource {
    display_name: String,
    instance_seed: String,
    config_text: String,
}

use crate::wireguard::config::{format_endpoint, WgConfig as RoutedConfig};

/// Parameters for `connect`, the non-clap counterpart of `tunmux connect wgconf`.
#[derive(Clone, Debug, Default)]
pub struct ConnectRequest {
    /// Config file to connect with; exclusive with `profile`.
    pub file: Option<String>,
    /// Saved profile name; exclusive with `file`.
    pub profile: Option<String>,
    /// Also save the config under this profile name.
    pub save_as: Option<String>,
    pub opts: ConnectOptions,
}

pub fn connect(args: ConnectRequest, config: &AppConfig) -> anyhow::Result<()> {
    let backend = connection_ops::resolve_connect_backend(
        args.opts.backend.as_deref(),
        &config.general.backend,
        args.opts.proxy,
        args.opts.local_proxy,
    )?;
    connection_ops::validate_disable_ipv6_direct_kernel(
        args.opts.disable_ipv6,
        args.opts.proxy,
        args.opts.local_proxy,
        backend,
    )?;
    if args.opts.mtu.is_some() && args.opts.local_proxy {
        anyhow::bail!("--mtu is not supported with --local-proxy");
    }
    let mut source = resolve_source(args.file.as_deref(), args.profile.as_deref())?;
    let parsed = wireguard::config::parse_config(&source.config_text)?;
    let mtu = wireguard::config::resolve_mtu(args.opts.mtu, parsed.mtu)?;
    if let Some(override_value) = args.opts.mtu {
        source.config_text = wireguard::config::with_mtu_override(
            &source.config_text,
            wireguard::config::Mtu::new(override_value)?,
        );
    }
    let mtu = mtu.map(wireguard::config::Mtu::get);

    if let Some(save_as) = args.save_as.as_deref() {
        save_profile_content(save_as, &source.config_text)?;
        crate::progress!("Saved profile {}", save_as);
    }

    let needs_routed_parse = args.opts.proxy
        || args.opts.local_proxy
        || backend == wireguard::backend::WgBackend::Kernel;
    let routed = if needs_routed_parse {
        Some(parse_routed_config(&source.config_text)?)
    } else {
        None
    };

    if args.opts.disable_ipv6 {
        let routed = routed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
        if has_ipv6_interface_address(&routed.addresses) {
            anyhow::bail!(
                "--disable-ipv6 can only be used when Interface.Address has no IPv6 entry"
            );
        }
    }

    if args.opts.proxy {
        let routed = routed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
        connect_proxy(
            &source,
            routed,
            mtu,
            args.opts.socks_port,
            args.opts.http_port,
            config,
        )?;
    } else if args.opts.local_proxy {
        let routed = routed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
        connect_local_proxy(
            &source,
            routed,
            args.opts.mtu,
            args.opts.socks_port,
            args.opts.http_port,
            config,
        )?;
    } else {
        connect_direct(
            &source,
            backend,
            routed.as_ref(),
            args.opts.disable_ipv6,
            mtu,
            config,
        )?;
    }

    Ok(())
}

fn connect_direct(
    source: &ConfigSource,
    backend: wireguard::backend::WgBackend,
    routed: Option<&RoutedConfig>,
    disable_ipv6: bool,
    mtu: Option<u16>,
    config: &AppConfig,
) -> anyhow::Result<()> {
    match backend {
        wireguard::backend::WgBackend::WgQuick | wireguard::backend::WgBackend::Userspace => {
            connection_ops::connect_direct_config(
                &source.config_text,
                backend,
                INTERFACE_NAME,
                PROVIDER,
                &source.display_name,
                config,
            )?;
        }
        wireguard::backend::WgBackend::Kernel => {
            let routed = routed.ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
            let endpoint_ip: IpAddr = routed
                .server_ip
                .parse()
                .with_context(|| format!("invalid endpoint IP {}", routed.server_ip))?;
            if endpoint_ip.is_ipv6() {
                anyhow::bail!(
                    "kernel direct mode currently supports IPv4 endpoints only (got {})",
                    routed.server_ip
                );
            }
            routed.with_params(mtu, |params| {
                connection_ops::connect_direct_wg(
                    params,
                    backend,
                    INTERFACE_NAME,
                    PROVIDER,
                    &source.display_name,
                    disable_ipv6,
                    config,
                )
            })?;
        }
        wireguard::backend::WgBackend::LocalProxy => {
            anyhow::bail!("use --local-proxy flag to start userspace WireGuard proxy mode");
        }
    }

    crate::progress!(
        "Connected to {} [backend: {}]",
        source.display_name,
        backend
    );
    Ok(())
}

fn connect_proxy(
    source: &ConfigSource,
    routed: &RoutedConfig,
    mtu: Option<u16>,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let instance = connection_ops::derive_instance_name(
        &source.instance_seed,
        "source",
        &source.display_name,
    )?;
    connection_ops::ensure_instance_available(&instance, "source", &source.display_name)?;

    let proxy_config = connection_ops::resolve_proxy_config(
        socks_port,
        http_port,
        config.general.proxy_access_log,
    )?;

    routed.with_params(mtu, |params| {
        let endpoint = format_endpoint(&routed.server_ip, routed.server_port);
        connection_ops::connect_proxy_via_netns(&connection_ops::ConnectContext {
            provider: PROVIDER,
            instance: &instance,
            display_name: &source.display_name,
            connect_endpoint: &endpoint,
            state_endpoint: &endpoint,
            dns_servers: routed.dns_servers.clone(),
            params,
            proxy_config: &proxy_config,
            config,
        })
    })
}

fn connect_local_proxy(
    source: &ConfigSource,
    routed: &RoutedConfig,
    mtu: Option<u16>,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let instance = connection_ops::derive_instance_name(
        &source.instance_seed,
        "source",
        &source.display_name,
    )?;
    connection_ops::ensure_instance_available(&instance, "source", &source.display_name)?;

    let proxy_config = connection_ops::resolve_proxy_config(
        socks_port,
        http_port,
        config.general.proxy_access_log,
    )?;

    routed.with_params(mtu, |params| {
        let endpoint = format_endpoint(&routed.server_ip, routed.server_port);
        connection_ops::connect_local_proxy_instance(&connection_ops::LocalProxyContext {
            provider: PROVIDER,
            instance: &instance,
            display_name: &source.display_name,
            connect_endpoint: &endpoint,
            state_endpoint: &endpoint,
            dns_servers: routed.dns_servers.clone(),
            virtual_ips: routed.addresses.clone(),
            peer_public_key: &routed.server_public_key,
            params,
            proxy_config: &proxy_config,
            config,
        })
    })
}

pub fn disconnect(instance: Option<String>, all: bool, config: &AppConfig) -> anyhow::Result<()> {
    connection_ops::disconnect_provider(PROVIDER, instance, all, config, false)
}

fn resolve_source(file: Option<&str>, profile: Option<&str>) -> anyhow::Result<ConfigSource> {
    match (file, profile) {
        (Some(path), None) => {
            let config_text = fs::read_to_string(path)
                .with_context(|| format!("failed to read WireGuard config file {}", path))?;
            let source_path = Path::new(path);
            let file_name = source_path
                .file_name()
                .and_then(|v| v.to_str())
                .filter(|v| !v.is_empty())
                .unwrap_or(path)
                .to_string();
            let instance_seed = source_path
                .file_stem()
                .and_then(|v| v.to_str())
                .filter(|v| !v.is_empty())
                .unwrap_or(&file_name)
                .to_string();
            Ok(ConfigSource {
                display_name: file_name,
                instance_seed,
                config_text,
            })
        }
        (None, Some(name)) => {
            let profile_name = validate_profile_name(name)?;
            let config_text = load_profile_content(&profile_name)?;
            Ok(ConfigSource {
                display_name: format!("profile:{}", profile_name),
                instance_seed: profile_name,
                config_text,
            })
        }
        (Some(_), Some(_)) => anyhow::bail!("use either --file or --profile, not both"),
        (None, None) => anyhow::bail!("one of --file or --profile is required"),
    }
}

fn parse_routed_config(config_text: &str) -> anyhow::Result<RoutedConfig> {
    let parsed = wireguard::config::parse_config(config_text)
        .context("invalid WireGuard configuration for kernel/proxy/local-proxy path")?;

    if parsed.private_key.trim().is_empty() {
        anyhow::bail!("Interface.PrivateKey must not be empty");
    }
    if parsed.addresses.is_empty() {
        anyhow::bail!("Interface.Address is required");
    }
    if parsed.dns_servers.is_empty() {
        anyhow::bail!(
            "Interface.DNS is required for kernel/proxy/local-proxy mode (direct wg-quick/userspace can use as-is config)"
        );
    }

    let addresses: Vec<String> = parsed
        .addresses
        .iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    if addresses.is_empty() {
        anyhow::bail!("Interface.Address is required");
    }

    let dns_servers: Vec<String> = parsed
        .dns_servers
        .iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    if dns_servers.is_empty() {
        anyhow::bail!(
            "Interface.DNS is required for kernel/proxy/local-proxy mode (direct wg-quick/userspace can use as-is config)"
        );
    }

    let (server_public_key, preshared_key, allowed_ips, server_ip, server_port) = {
        let peer = select_peer_with_endpoint(&parsed)?;
        let endpoint = peer
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("peer endpoint missing"))?;
        let (server_ip, server_port) = parse_endpoint(endpoint)?;

        (
            peer.public_key.clone(),
            peer.preshared_key.clone(),
            peer.allowed_ips.trim().to_string(),
            server_ip.to_string(),
            server_port,
        )
    };

    Ok(RoutedConfig {
        private_key: parsed.private_key.clone(),
        addresses,
        dns_servers,
        server_public_key,
        server_ip,
        server_port,
        preshared_key,
        allowed_ips,
    })
}

fn select_peer_with_endpoint(
    parsed: &wireguard::config::WgParsedConfig,
) -> anyhow::Result<&wireguard::config::WgParsedPeer> {
    parsed
        .peers
        .iter()
        .find(|peer| {
            !peer.public_key.trim().is_empty()
                && !peer.allowed_ips.trim().is_empty()
                && peer
                    .endpoint
                    .as_deref()
                    .is_some_and(|ep| !ep.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no usable peer found: require PublicKey, AllowedIPs, and a valid Endpoint"
            )
        })
}

fn parse_endpoint(value: &str) -> anyhow::Result<(IpAddr, u16)> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip(), addr.port()));
    }

    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint {}", value))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid endpoint port {}", port))?;

    let host = host.trim_matches(['[', ']']);
    let ip: IpAddr = host
        .parse()
        .ok()
        .or_else(|| {
            (host, port)
                .to_socket_addrs()
                .ok()?
                .next()
                .map(|addr| addr.ip())
        })
        .ok_or_else(|| anyhow::anyhow!("failed to resolve endpoint host {}", host))?;
    Ok((ip, port))
}

fn has_ipv6_interface_address(addresses: &[String]) -> bool {
    addresses.iter().any(|cidr| {
        let ip = cidr.split('/').next().unwrap_or_default().trim();
        ip.parse::<IpAddr>().is_ok_and(|addr| addr.is_ipv6())
    })
}

fn validate_profile_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("profile name cannot be empty");
    }
    if trimmed.len() > 64 {
        anyhow::bail!("profile name is too long (max 64 characters)");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!(
            "invalid profile name {:?}; use only lowercase letters, digits, '-', '_' or '.'",
            name
        );
    }
    Ok(trimmed.to_string())
}

fn provider_dir() -> PathBuf {
    config::config_dir(PROVIDER)
}

fn profile_dir_in(provider: &Path) -> PathBuf {
    provider.join(PROFILE_DIR)
}

fn ensure_profile_dirs_in(provider: &Path) -> anyhow::Result<()> {
    if !provider.exists() {
        fs::create_dir_all(provider).with_context(|| {
            format!("failed to create provider directory {}", provider.display())
        })?;
    }
    fs::set_permissions(provider, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set provider directory permissions {}",
            provider.display()
        )
    })?;

    let dir = profile_dir_in(provider);
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create profile directory {}", dir.display()))?;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set profile directory permissions {}",
            dir.display()
        )
    })?;
    Ok(())
}

fn profile_path_in(provider: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let valid = validate_profile_name(name)?;
    Ok(profile_dir_in(provider).join(format!("{}.conf", valid)))
}

pub fn save_profile_content(name: &str, content: &str) -> anyhow::Result<()> {
    save_profile_content_in(&provider_dir(), name, content)
}

fn save_profile_content_in(provider: &Path, name: &str, content: &str) -> anyhow::Result<()> {
    ensure_profile_dirs_in(provider)?;
    let path = profile_path_in(provider, name)?;
    crate::shared::persistence::write_private_atomic(&path, content.as_bytes())
        .with_context(|| format!("failed to write profile file {}", path.display()))?;
    Ok(())
}

fn load_profile_content(name: &str) -> anyhow::Result<String> {
    load_profile_content_in(&provider_dir(), name)
}

fn load_profile_content_in(provider: &Path, name: &str) -> anyhow::Result<String> {
    let path = profile_path_in(provider, name)?;
    fs::read_to_string(&path)
        .with_context(|| format!("profile {:?} not found at {}", name, path.display()))
}

pub fn list_profiles() -> anyhow::Result<Vec<String>> {
    list_profiles_in(&provider_dir())
}

/// Saved profile names.
pub fn profile_names() -> anyhow::Result<Vec<String>> {
    list_profiles()
}

/// Saved profiles with the peer endpoint, for the API.
pub fn profiles() -> anyhow::Result<Vec<crate::api::WgProfile>> {
    list_profiles()?
        .into_iter()
        .map(|name| {
            let text = load_profile_content(&name)?;
            let endpoint = wireguard::config::parse_config(&text)
                .ok()
                .and_then(|parsed| {
                    select_peer_with_endpoint(&parsed)
                        .ok()
                        .and_then(|peer| peer.endpoint.clone())
                });
            Ok(crate::api::WgProfile { name, endpoint })
        })
        .collect()
}

/// Save the config at `path` as profile `name` once it parses with a peer
/// endpoint; an existing profile of that name is not replaced.
pub fn import_profile(path: &Path, name: &str) -> anyhow::Result<()> {
    let name = validate_profile_name(name)?;
    anyhow::ensure!(
        !list_profiles()?.contains(&name),
        "a profile named {name} already exists"
    );
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = wireguard::config::parse_config(&text)
        .with_context(|| format!("{} is not a WireGuard config", path.display()))?;
    select_peer_with_endpoint(&parsed)?;
    save_profile_content(&name, &text)
}

pub fn delete_profile(name: &str) -> anyhow::Result<()> {
    remove_profile(name)
}

/// Saved profiles, offered as servers; connect takes the profile name.
pub fn server_list() -> anyhow::Result<Vec<crate::api::ServerInfo>> {
    Ok(list_profiles()?
        .into_iter()
        .map(|name| crate::api::ServerInfo {
            provider: PROVIDER,
            name,
            country_code: String::new(),
            city: String::new(),
            load: None,
            score: None,
            tags: Vec::new(),
        })
        .collect())
}

fn list_profiles_in(provider: &Path) -> anyhow::Result<Vec<String>> {
    let dir = profile_dir_in(provider);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("conf") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|v| v.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

pub fn remove_profile(name: &str) -> anyhow::Result<()> {
    remove_profile_in(&provider_dir(), name)
}

fn remove_profile_in(provider: &Path, name: &str) -> anyhow::Result<()> {
    let path = profile_path_in(provider, name)?;
    if !path.exists() {
        anyhow::bail!("profile {:?} does not exist", name);
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove profile {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        has_ipv6_interface_address, list_profiles_in, parse_endpoint, parse_routed_config,
        remove_profile_in, save_profile_content_in, validate_profile_name,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "tunmux-wgconf-test-{}-{}-{}",
            name,
            std::process::id(),
            now
        ))
    }

    #[test]
    fn profile_name_validation_rejects_invalid_values() {
        assert!(validate_profile_name("ok.name-1").is_ok());
        assert!(validate_profile_name("UPPER").is_err());
        assert!(validate_profile_name("../bad").is_err());
        assert!(validate_profile_name("bad/name").is_err());
        assert!(validate_profile_name("").is_err());
    }

    #[test]
    fn endpoint_parsing_supports_ipv4_and_bracketed_ipv6() {
        let (ip4, port4) = parse_endpoint("198.51.100.1:51820").expect("parse ipv4 endpoint");
        assert_eq!(ip4.to_string(), "198.51.100.1");
        assert_eq!(port4, 51820);

        let (ip6, port6) =
            parse_endpoint("[2001:db8::1]:51820").expect("parse bracketed ipv6 endpoint");
        assert_eq!(ip6.to_string(), "2001:db8::1");
        assert_eq!(port6, 51820);

        let (_host_ip, host_port) =
            parse_endpoint("localhost:51820").expect("parse hostname endpoint");
        assert_eq!(host_port, 51820);
    }

    #[test]
    fn routed_parse_requires_dns_and_valid_peer_endpoint() {
        let no_dns = "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = b\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\n";
        let err = parse_routed_config(no_dns)
            .err()
            .expect("dns should be required");
        assert!(err.to_string().contains("Interface.DNS"));

        let with_dns = "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = b\nAllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::1]:51820\n";
        let parsed = parse_routed_config(with_dns).expect("parse routed config");
        assert_eq!(parsed.server_ip, "2001:db8::1");
        assert_eq!(parsed.server_port, 51820);

        let with_dns_hostname = "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = b\nAllowedIPs = 0.0.0.0/0\nEndpoint = localhost:51820\n";
        let parsed = parse_routed_config(with_dns_hostname).expect("parse hostname endpoint");
        assert_eq!(parsed.server_port, 51820);
    }

    #[test]
    fn ipv6_address_detection_works() {
        assert!(!has_ipv6_interface_address(&["10.0.0.2/32".to_string()]));
        assert!(has_ipv6_interface_address(&[
            "10.0.0.2/32".to_string(),
            "fd7d:76ee:e68f:a993::2/128".to_string()
        ]));
    }

    #[test]
    fn profile_storage_permissions_and_listing() {
        let provider_dir = unique_test_dir("profile-storage").join("wgconf");
        std::fs::create_dir_all(&provider_dir).expect("create provider dir");

        save_profile_content_in(&provider_dir, "work", "[Interface]\nPrivateKey = a\n")
            .expect("save work profile");
        save_profile_content_in(&provider_dir, "home", "[Interface]\nPrivateKey = b\n")
            .expect("save home profile");

        let profiles_dir = provider_dir.join("profiles");
        let profile_file = profiles_dir.join("work.conf");

        assert_eq!(
            std::fs::metadata(&provider_dir)
                .expect("provider dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&profiles_dir)
                .expect("profiles dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&profile_file)
                .expect("profile file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let names = list_profiles_in(&provider_dir).expect("list profiles");
        assert_eq!(names, vec!["home".to_string(), "work".to_string()]);

        remove_profile_in(&provider_dir, "work").expect("remove profile");
        let names = list_profiles_in(&provider_dir).expect("list profiles after remove");
        assert_eq!(names, vec!["home".to_string()]);

        let _ = std::fs::remove_dir_all(
            provider_dir
                .parent()
                .expect("provider dir should have parent"),
        );
    }
}

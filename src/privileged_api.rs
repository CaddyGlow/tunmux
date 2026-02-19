use serde::{Deserialize, Serialize};

use std::net::IpAddr;
use std::path::{Component, Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WgQuickAction {
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillSignal {
    Term,
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrivilegedRequest {
    NamespaceCreate {
        name: String,
    },
    NamespaceDelete {
        name: String,
    },
    NamespaceExists {
        name: String,
    },

    InterfaceCreateWireguard {
        name: String,
    },
    InterfaceDelete {
        name: String,
    },
    InterfaceMoveToNetns {
        interface: String,
        namespace: String,
    },

    NetnsExec {
        namespace: String,
        args: Vec<String>,
    },

    HostIpAddrAdd {
        interface: String,
        cidr: String,
    },
    HostIpLinkSetUp {
        interface: String,
    },
    HostIpRouteAdd {
        destination: String,
        via: Option<String>,
        dev: String,
    },
    HostIpRouteDel {
        destination: String,
        via: Option<String>,
        dev: String,
    },

    WireguardSet {
        interface: String,
        private_key: String,
        peer_public_key: String,
        endpoint: String,
        allowed_ips: String,
    },
    WireguardSetPsk {
        interface: String,
        peer_public_key: String,
        psk: String,
    },

    WgQuickRun {
        action: WgQuickAction,
        interface: String,
        provider: String,
        config_content: String,
        #[serde(default)]
        prefer_userspace: bool,
    },

    EnsureDir {
        path: String,
        mode: u32,
    },
    WriteFile {
        path: String,
        contents: Vec<u8>,
        mode: u32,
    },
    RemoveDirAll {
        path: String,
    },

    KillPid {
        pid: u32,
        signal: KillSignal,
    },
    SpawnProxyDaemon {
        netns: String,
        socks_port: u16,
        http_port: u16,
        pid_file: String,
        log_file: String,
    },
    LeaseAcquire {
        token: String,
    },
    LeaseRelease {
        token: String,
    },
    ShutdownIfIdle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PrivilegedResponse {
    Unit,
    Bool(bool),
    Pid(u32),
    Error { code: String, message: String },
}

impl PrivilegedRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::NamespaceCreate { name }
            | Self::NamespaceDelete { name }
            | Self::NamespaceExists { name } => validate_namespace_name(name),
            Self::InterfaceCreateWireguard { name } | Self::InterfaceDelete { name } => {
                validate_interface_name(name)
            }
            Self::InterfaceMoveToNetns {
                interface,
                namespace,
            } => {
                validate_interface_name(interface)?;
                validate_namespace_name(namespace)?;
                Ok(())
            }
            Self::NetnsExec { namespace, args } => {
                validate_namespace_name(namespace)?;
                validate_netns_exec_args(args)
            }
            Self::HostIpAddrAdd { interface, cidr } => {
                validate_interface_name(interface)?;
                validate_cidr(cidr)
            }
            Self::HostIpLinkSetUp { interface } => validate_interface_name(interface),
            Self::HostIpRouteAdd {
                destination,
                via,
                dev,
            }
            | Self::HostIpRouteDel {
                destination,
                via,
                dev,
            } => {
                validate_interface_name(dev)?;
                validate_route_destination(destination)?;
                if let Some(gateway) = via {
                    validate_ipv4_like(gateway)?;
                }
                Ok(())
            }
            Self::WireguardSet {
                interface,
                private_key,
                peer_public_key,
                endpoint,
                allowed_ips,
            } => {
                validate_interface_name(interface)?;
                if private_key.is_empty() {
                    return Err("private_key cannot be empty".into());
                }
                if peer_public_key.is_empty() {
                    return Err("peer_public_key cannot be empty".into());
                }
                validate_host_endpoint(endpoint)?;
                validate_allowed_ips(allowed_ips)?;
                Ok(())
            }
            Self::WireguardSetPsk {
                interface,
                peer_public_key,
                psk,
            } => {
                validate_interface_name(interface)?;
                if peer_public_key.is_empty() {
                    return Err("peer_public_key cannot be empty".into());
                }
                if psk.is_empty() {
                    return Err("psk cannot be empty".into());
                }
                Ok(())
            }
            Self::WgQuickRun {
                interface,
                provider,
                ..
            } => {
                validate_interface_name(interface)?;
                validate_provider(provider)?;
                Ok(())
            }
            Self::EnsureDir { path, .. } => validate_ensure_dir_path(path),
            Self::WriteFile { path, .. } => validate_write_path(path),
            Self::RemoveDirAll { path } => validate_remove_dir_path(path),
            Self::KillPid { pid, .. } => {
                if *pid == 0 {
                    return Err("pid cannot be zero".into());
                }
                Ok(())
            }
            Self::SpawnProxyDaemon {
                netns,
                socks_port,
                http_port,
                pid_file,
                log_file,
            } => {
                validate_namespace_name(netns)?;
                if *socks_port == 0 || *http_port == 0 {
                    return Err("ports must be non-zero".into());
                }
                validate_write_path(pid_file)?;
                validate_write_path(log_file)?;
                Ok(())
            }
            Self::LeaseAcquire { token } | Self::LeaseRelease { token } => {
                validate_lease_token(token)
            }
            Self::ShutdownIfIdle => Ok(()),
        }
    }
}

pub fn validate_namespace_name(name: &str) -> Result<(), String> {
    if !name.starts_with("tunmux_") {
        return Err("namespace must start with tunmux_".into());
    }

    let suffix = &name["tunmux_".len()..];
    if suffix.is_empty() || suffix.len() > 32 {
        return Err("namespace suffix must be 1..=32 chars".into());
    }

    if !suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("namespace may only contain lowercase letters, digits, and '-'".into());
    }

    Ok(())
}

fn validate_interface_name(interface: &str) -> Result<(), String> {
    if interface == "proton0" || interface == "airvpn0" {
        return Ok(());
    }
    if !interface.starts_with("wg-") {
        return Err("interface must be proton0, airvpn0 or wg-*".into());
    }
    let suffix = &interface["wg-".len()..];
    if suffix.is_empty() || suffix.len() > 12 {
        return Err("wg-* interface suffix must be 1..=12 chars".into());
    }
    if !suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("wg-* interface name contains invalid characters".into());
    }
    Ok(())
}

fn validate_provider(provider: &str) -> Result<(), String> {
    if provider == "proton" || provider == "airvpn" {
        Ok(())
    } else {
        Err("provider must be proton or airvpn".into())
    }
}

fn validate_lease_token(token: &str) -> Result<(), String> {
    if token.is_empty() || token.len() > 64 {
        return Err("lease token must be 1..=64 chars".into());
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-' || c == '_')
    {
        return Err("lease token contains invalid characters".into());
    }
    Ok(())
}

fn validate_netns_exec_args(args: &[String]) -> Result<(), String> {
    let is_addr_add = |a: &[&str]| {
        a.len() == 6
            && a[0] == "ip"
            && a[1] == "addr"
            && a[2] == "add"
            && a[4] == "dev"
            && validate_interface_name(a[5]).is_ok()
            && validate_cidr(a[3]).is_ok()
    };
    let is_link_up = |a: &[&str]| {
        a.len() == 6
            && a[0] == "ip"
            && a[1] == "link"
            && a[2] == "set"
            && a[3] == "up"
            && a[4] == "dev"
            && validate_interface_name(a[5]).is_ok()
    };
    let is_route_default_v4 = |a: &[&str]| {
        a.len() == 6
            && a[0] == "ip"
            && a[1] == "route"
            && a[2] == "add"
            && a[3] == "default"
            && a[4] == "dev"
            && validate_interface_name(a[5]).is_ok()
    };
    let is_route_default_v6 = |a: &[&str]| {
        a.len() == 7
            && a[0] == "ip"
            && a[1] == "-6"
            && a[2] == "route"
            && a[3] == "add"
            && a[4] == "default"
            && a[5] == "dev"
            && validate_interface_name(a[6]).is_ok()
    };

    let args_strs: Vec<&str> = args.iter().map(String::as_str).collect();
    if is_addr_add(&args_strs)
        || is_link_up(&args_strs)
        || is_route_default_v4(&args_strs)
        || is_route_default_v6(&args_strs)
    {
        return Ok(());
    }
    Err("disallowed netns exec command".into())
}

fn validate_route_destination(destination: &str) -> Result<(), String> {
    if destination == "default" {
        return Ok(());
    }
    validate_cidr(destination)
}

fn validate_host_endpoint(endpoint: &str) -> Result<(), String> {
    let mut parts = endpoint.rsplitn(2, ':');
    let port = parts.next().ok_or("endpoint missing port")?;
    let host = parts.next().ok_or("endpoint missing host")?;
    if host.is_empty() || port.is_empty() {
        return Err("endpoint format invalid".into());
    }
    port.parse::<u16>()
        .map_err(|_| "invalid endpoint port".to_string())?;
    host.parse::<IpAddr>()
        .map_err(|_| "invalid endpoint host".to_string())?;
    Ok(())
}

fn validate_allowed_ips(allowed: &str) -> Result<(), String> {
    if allowed.is_empty() {
        return Err("allowed_ips cannot be empty".into());
    }
    for part in allowed.split(',') {
        validate_cidr(part.trim())?;
    }
    Ok(())
}

fn validate_ipv4_like(addr: &str) -> Result<(), String> {
    addr.parse::<IpAddr>()
        .map_err(|_| format!("invalid IP: {}", addr))
        .map(|_| ())
}

fn validate_cidr(cidr: &str) -> Result<(), String> {
    let mut split = cidr.split('/');
    let addr = split.next().ok_or("invalid cidr")?;
    let prefix = split.next().ok_or("invalid cidr (missing /)")?;
    if split.next().is_some() {
        return Err("invalid cidr (too many segments)".into());
    }
    let _ = addr
        .parse::<IpAddr>()
        .map_err(|_| "invalid cidr address".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| "invalid cidr prefix".to_string())?;
    if prefix > 128 {
        return Err("invalid cidr prefix".into());
    }
    Ok(())
}

fn validate_write_path(path: &str) -> Result<(), String> {
    validate_no_parent_component(path)?;

    if path == "/etc/resolv.conf" {
        return Ok(());
    }
    if is_managed_netns_resolv(path)? {
        return Ok(());
    }
    if path.starts_with("/var/lib/tunmux/") {
        return Ok(());
    }
    Err("path is not allowed for file write".into())
}

fn validate_ensure_dir_path(path: &str) -> Result<(), String> {
    validate_no_parent_component(path)?;
    if let Some(suffix) = path.strip_prefix("/etc/netns/") {
        validate_namespace_name(suffix)?;
        return Ok(());
    }
    if path.starts_with("/var/lib/tunmux/") {
        return Ok(());
    }
    Err("path is not allowed for directory creation".into())
}

fn validate_remove_dir_path(path: &str) -> Result<(), String> {
    validate_no_parent_component(path)?;
    if let Some(suffix) = path.strip_prefix("/etc/netns/") {
        if suffix.contains('/') || suffix.is_empty() {
            return Err("invalid namespace path".into());
        }
        validate_namespace_name(suffix)?;
        return Ok(());
    }
    Err("remove dir is allowed only for /etc/netns/<namespace>".into())
}

fn is_managed_netns_resolv(path: &str) -> Result<bool, String> {
    let prefix = "/etc/netns/";
    if !path.starts_with(prefix) {
        return Ok(false);
    }
    let suffix = &path[prefix.len()..];
    let (ns, file) = suffix.split_once('/').ok_or("invalid /etc/netns path")?;
    if file != "resolv.conf" {
        return Err("only /etc/netns/<ns>/resolv.conf is allowed".into());
    }
    validate_namespace_name(ns)?;
    Ok(true)
}

fn validate_no_parent_component(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }
    for c in path.components() {
        if matches!(c, Component::ParentDir | Component::CurDir) {
            return Err("path components cannot include .. or .".into());
        }
    }
    Ok(())
}

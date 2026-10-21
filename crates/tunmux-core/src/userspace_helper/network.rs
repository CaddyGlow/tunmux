use super::ParsedUserspaceConfig;
use anyhow::Context;
use nix::fcntl::{fcntl, FcntlArg, Flock, FlockArg, OFlag};
use nix::libc;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
#[cfg(target_os = "macos")]
use tracing::warn;
#[cfg(target_os = "linux")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct LinuxRoute {
    is_ipv6: bool,
    destination: String,
    via: Option<String>,
    dev: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MacosRoute {
    is_ipv6: bool,
    destination: String,
    interface: Option<String>,
    gateway: Option<String>,
}

#[cfg(unix)]
fn run_command(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
fn run_command_with_exists_ok(name: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("File exists") || stdout.contains("File exists") {
        return Ok(false);
    }
    let detail = stderr.trim();
    if detail.is_empty() {
        anyhow::bail!("{} {} failed", name, args.join(" "));
    }
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

fn run_command_capture_output(name: &str, args: &[&str]) -> anyhow::Result<Output> {
    let child = Command::new(name)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {name}"))?;
    let mut guard = ChildGuard(child);
    let child = &mut guard.0;
    let mut stdout = child.stdout.take().context("missing stdout")?;
    let mut stderr = child.stderr.take().context("missing stderr")?;
    fcntl(&stdout, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    fcntl(&stderr, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        drain(&mut stdout, &mut out)?;
        drain(&mut stderr, &mut err)?;
        if let Some(status) = child.try_wait()? {
            drain(&mut stdout, &mut out)?;
            drain(&mut stderr, &mut err)?;
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("command {name} timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn drain(reader: &mut impl Read, output: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut buf = [0; 4096];
    // Limit each polling turn so continuously writing children cannot defeat the deadline.
    for _ in 0..16 {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let count = n.min(65536usize.saturating_sub(output.len()));
                output.extend_from_slice(&buf[..count]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_network_linux(
    interface: &str,
    config: &ParsedUserspaceConfig,
    state: &mut Journal,
    budget: &SetupBudget<'_>,
) -> anyhow::Result<()> {
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));
    for address in &config.addresses {
        budget.check()?;
        run_command("ip", &["addr", "add", address, "dev", interface])?;
    }
    if let Some(mtu) = config.mtu {
        budget.check()?;
        run_command(
            "ip",
            &[
                "link",
                "set",
                "dev",
                interface,
                "mtu",
                &mtu.get().to_string(),
            ],
        )?;
    }
    budget.check()?;
    run_command("ip", &["link", "set", "up", "dev", interface])?;
    budget.check()?;
    let endpoint = match config.endpoint.ip() {
        IpAddr::V4(_) => {
            let default = get_linux_default_route_v4()?;
            Some(LinuxRoute {
                is_ipv6: false,
                destination: format!("{}/32", config.endpoint.ip()),
                via: Some(default.gateway),
                dev: Some(default.dev),
            })
        }
        IpAddr::V6(_) => get_linux_default_route_v6().map(|default| LinuxRoute {
            is_ipv6: true,
            destination: format!("{}/128", config.endpoint.ip()),
            via: Some(default.gateway),
            dev: Some(default.dev),
        }),
    };
    for route in
        endpoint
            .into_iter()
            .chain(linux_allowed_routes(interface, config, has_ipv6_address))
    {
        budget.check()?;
        if !linux_route_observation(&route)?.is_empty() {
            continue;
        }
        state.push(Action::LinuxRoute(route.clone()))?;
        budget.check()?;
        if !add_linux_route(&route)? {
            state.actions.pop();
            state.persist()?;
        }
    }
    if should_manage_global_resolv_conf() && !config.dns_servers.is_empty() {
        let original =
            std::fs::read_to_string("/etc/resolv.conf").context("cannot snapshot resolver")?;
        let intended = config
            .dns_servers
            .iter()
            .map(|dns| format!("nameserver {dns}\n"))
            .collect::<String>();
        state.push(Action::Resolver {
            path: PathBuf::from("/etc/resolv.conf"),
            original,
            intended: intended.clone(),
        })?;
        budget.check()?;
        std::fs::write("/etc/resolv.conf", intended).context("cannot set resolver")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_linux_route(route: &LinuxRoute) -> anyhow::Result<bool> {
    let mut args: Vec<String> = if route.is_ipv6 {
        vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            route.destination.clone(),
        ]
    } else {
        vec!["route".into(), "add".into(), route.destination.clone()]
    };
    if let Some(via) = &route.via {
        args.push("via".into());
        args.push(via.clone());
    }
    if let Some(dev) = &route.dev {
        args.push("dev".into());
        args.push(dev.clone());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command_with_exists_ok("ip", &arg_refs)
}

#[cfg(target_os = "linux")]
fn del_linux_route(route: &LinuxRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = if route.is_ipv6 {
        vec![
            "-6".into(),
            "route".into(),
            "del".into(),
            route.destination.clone(),
        ]
    } else {
        vec!["route".into(), "del".into(), route.destination.clone()]
    };
    if let Some(via) = &route.via {
        args.push("via".into());
        args.push(via.clone());
    }
    if let Some(dev) = &route.dev {
        args.push("dev".into());
        args.push(dev.clone());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command("ip", &arg_refs)
}

#[cfg(target_os = "linux")]
fn linux_allowed_routes(
    interface: &str,
    config: &ParsedUserspaceConfig,
    has_ipv6_address: bool,
) -> Vec<LinuxRoute> {
    let mut routes = Vec::new();
    for allowed in &config.allowed_ips {
        match allowed.as_str() {
            "0.0.0.0/0" => {
                routes.push(LinuxRoute {
                    is_ipv6: false,
                    destination: "0.0.0.0/1".to_string(),
                    via: None,
                    dev: Some(interface.to_string()),
                });
                routes.push(LinuxRoute {
                    is_ipv6: false,
                    destination: "128.0.0.0/1".to_string(),
                    via: None,
                    dev: Some(interface.to_string()),
                });
            }
            "::/0" => {
                if !has_ipv6_address {
                    continue;
                }
                routes.push(LinuxRoute {
                    is_ipv6: true,
                    destination: "::/1".to_string(),
                    via: None,
                    dev: Some(interface.to_string()),
                });
                routes.push(LinuxRoute {
                    is_ipv6: true,
                    destination: "8000::/1".to_string(),
                    via: None,
                    dev: Some(interface.to_string()),
                });
            }
            other => {
                let is_ipv6 = other.contains(':');
                if is_ipv6 && !has_ipv6_address {
                    continue;
                }
                routes.push(LinuxRoute {
                    is_ipv6,
                    destination: other.to_string(),
                    via: None,
                    dev: Some(interface.to_string()),
                });
            }
        }
    }
    routes
}

#[cfg(target_os = "linux")]
struct LinuxDefaultRoute {
    gateway: String,
    dev: String,
}

#[cfg(target_os = "linux")]
fn get_linux_default_route_v4() -> anyhow::Result<LinuxDefaultRoute> {
    let output = run_command_capture_output("ip", &["route", "show", "default"])
        .context("failed to run ip route show default")?;
    if !output.status.success() {
        anyhow::bail!("ip route show default failed");
    }
    parse_linux_default_route(std::str::from_utf8(&output.stdout).unwrap_or_default())
}

#[cfg(target_os = "linux")]
fn get_linux_default_route_v6() -> Option<LinuxDefaultRoute> {
    let output = run_command_capture_output("ip", &["-6", "route", "show", "default"]).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_linux_default_route(std::str::from_utf8(&output.stdout).ok()?).ok()
}

#[cfg(target_os = "linux")]
fn parse_linux_default_route(output: &str) -> anyhow::Result<LinuxDefaultRoute> {
    let line = output
        .lines()
        .find(|line| line.starts_with("default"))
        .ok_or_else(|| anyhow::anyhow!("no default route found"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();

    let via = fields
        .iter()
        .position(|value| *value == "via")
        .and_then(|index| fields.get(index + 1))
        .ok_or_else(|| anyhow::anyhow!("default route missing gateway"))?;
    let dev = fields
        .iter()
        .position(|value| *value == "dev")
        .and_then(|index| fields.get(index + 1))
        .ok_or_else(|| anyhow::anyhow!("default route missing interface"))?;

    Ok(LinuxDefaultRoute {
        gateway: (*via).to_string(),
        dev: (*dev).to_string(),
    })
}

#[cfg(target_os = "linux")]
fn should_manage_global_resolv_conf() -> bool {
    !is_systemd_resolved_managed_resolv_conf("/etc/resolv.conf")
}

#[cfg(target_os = "linux")]
fn is_systemd_resolved_managed_resolv_conf(path: &str) -> bool {
    match std::fs::canonicalize(path) {
        Ok(real_path) => real_path.starts_with("/run/systemd/resolve/"),
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn configure_network_macos(
    interface: &str,
    config: &ParsedUserspaceConfig,
    state: &mut Journal,
    budget: &SetupBudget<'_>,
) -> anyhow::Result<()> {
    let has_ipv4_address = config
        .addresses
        .iter()
        .any(|address| !address.contains(':'));
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));
    for address in &config.addresses {
        budget.check()?;
        let (ip, prefix) = parse_cidr(address)?;
        match ip {
            IpAddr::V4(addr) => {
                let ip_string = addr.to_string();
                budget.check()?;
                run_command(
                    "ifconfig",
                    &[interface, "inet", address, ip_string.as_str(), "alias"],
                )?;
            }
            IpAddr::V6(addr) => {
                let ip_string = addr.to_string();
                let prefix_string = prefix.to_string();
                budget.check()?;
                run_command(
                    "ifconfig",
                    &[
                        interface,
                        "inet6",
                        ip_string.as_str(),
                        "prefixlen",
                        prefix_string.as_str(),
                        "alias",
                    ],
                )?;
            }
        }
    }
    if let Some(mtu) = config.mtu {
        budget.check()?;
        run_command("ifconfig", &[interface, "mtu", &mtu.get().to_string()])?;
    }
    budget.check()?;
    run_command("ifconfig", &[interface, "up"])?;
    budget.check()?;
    if let Err(error) = run_command("ifconfig", &[interface, "-rxcsum", "-txcsum"]) {
        warn!(
            interface,
            error = %error,
            "userspace_helper_disable_checksum_offload_failed"
        );
    }

    budget.check()?;
    let endpoint_is_ipv6 = matches!(config.endpoint.ip(), IpAddr::V6(_));
    if !endpoint_is_ipv6 || has_ipv6_address {
        if let Some((default_gateway, default_interface)) =
            get_macos_default_route(endpoint_is_ipv6)?
        {
            let endpoint_route = MacosRoute {
                is_ipv6: endpoint_is_ipv6,
                destination: config.endpoint.ip().to_string(),
                interface: Some(default_interface),
                gateway: Some(default_gateway),
            };
            if !macos_route_present(&endpoint_route)? {
                state.push(Action::MacosRoute(endpoint_route.clone()))?;
                budget.check()?;
                if !add_macos_route(&endpoint_route)? {
                    state.actions.pop();
                    state.persist()?;
                }
            }
        }
    }

    let original = macos_allowed_routes(config, interface, has_ipv4_address, has_ipv6_address);
    let planned = if config.allow_lan {
        let policy = LanPolicy {
            interface: interface.into(),
            original,
            dns: config.dns_servers.clone(),
        };
        let planned = lan_routes(&policy)?;
        state.lan = Some(policy);
        state.persist()?;
        planned
    } else {
        original
    };
    for route in planned {
        budget.check()?;
        match macos_route_status(&route)? {
            Some(true) => continue,
            Some(false) if !config.allow_lan => continue,
            Some(false) => anyhow::bail!(
                "LAN policy route ownership conflict for {}",
                route.destination
            ),
            None => {}
        }
        state.push(Action::MacosRoute(route.clone()))?;
        budget.check()?;
        if !add_macos_route(&route)? {
            state.actions.pop();
            state.persist()?;
        }
    }

    if !config.dns_servers.is_empty() {
        budget.check()?;
        for service in list_macos_network_services()? {
            budget.check()?;
            let original = get_macos_dns_servers(&service)?;
            state.push(Action::MacosDns {
                service: service.clone(),
                original,
                intended: Some(config.dns_servers.clone()),
                search: false,
            })?;
            budget.check()?;
            set_macos_dns_servers(&service, &config.dns_servers)?;
            budget.check()?;
            let original = get_macos_search_domains(&service)?;
            state.push(Action::MacosDns {
                service: service.clone(),
                original,
                intended: None,
                search: true,
            })?;
            budget.check()?;
            set_macos_search_domains_empty(&service)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> anyhow::Result<Vec<String>> {
    let output = run_command_capture_output("networksetup", &["-listallnetworkservices"])?;
    if !output.status.success() {
        anyhow::bail!("networksetup -listallnetworkservices failed");
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("An asterisk") {
            continue;
        }
        let service = trimmed.strip_prefix('*').map(str::trim).unwrap_or(trimmed);
        if !service.is_empty() {
            services.push(service.to_string());
        }
    }

    Ok(services)
}

#[cfg(target_os = "macos")]
fn get_macos_dns_servers(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_macos_networksetup_values(service, "-getdnsservers", "DNS Servers")
}

#[cfg(target_os = "macos")]
fn get_macos_search_domains(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_macos_networksetup_values(service, "-getsearchdomains", "Search Domains")
}

#[cfg(target_os = "macos")]
fn get_macos_networksetup_values(
    service: &str,
    flag: &str,
    value_label: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    let output = run_command_capture_output("networksetup", &[flag, service])?;
    if !output.status.success() {
        anyhow::bail!("networksetup {} {} failed", flag, service);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let marker = format!("There aren't any {} set", value_label);
    if stdout.lines().any(|line| line.contains(&marker)) {
        return Ok(None);
    }

    let values: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if values.is_empty() || values == ["Empty".to_string()] {
        Ok(None)
    } else {
        Ok(Some(values))
    }
}

#[cfg(target_os = "macos")]
fn set_macos_dns_servers(service: &str, dns_servers: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + dns_servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(dns_servers.iter().map(String::as_str));
    run_command("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn set_macos_dns_servers_empty(service: &str) -> anyhow::Result<()> {
    run_command("networksetup", &["-setdnsservers", service, "Empty"])
}

#[cfg(target_os = "macos")]
fn set_macos_search_domains(service: &str, domains: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + domains.len());
    args.push("-setsearchdomains");
    args.push(service);
    args.extend(domains.iter().map(String::as_str));
    run_command("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn set_macos_search_domains_empty(service: &str) -> anyhow::Result<()> {
    run_command("networksetup", &["-setsearchdomains", service, "Empty"])
}

#[cfg(target_os = "macos")]
fn add_macos_route(route: &MacosRoute) -> anyhow::Result<bool> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "add".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(route.destination.clone());
    if let Some(gateway) = &route.gateway {
        args.push(gateway.clone());
    }
    if let Some(interface) = &route.interface {
        args.push(
            if route.gateway.is_some() {
                "-ifp"
            } else {
                "-interface"
            }
            .into(),
        );
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command_with_exists_ok("route", &refs)
}

#[cfg(target_os = "macos")]
fn del_macos_route(route: &MacosRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(route.destination.clone());
    if let Some(gateway) = &route.gateway {
        args.push(gateway.clone());
    }
    if let Some(interface) = &route.interface {
        args.push(
            if route.gateway.is_some() {
                "-ifp"
            } else {
                "-interface"
            }
            .into(),
        );
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command("route", &refs)
}

#[cfg(target_os = "macos")]
fn macos_allowed_routes(
    config: &ParsedUserspaceConfig,
    interface: &str,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();
    for allowed in &config.allowed_ips {
        match allowed.as_str() {
            "0.0.0.0/0" => {
                if !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "0.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "128.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            "::/0" => {
                if !has_ipv6_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "8000::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            other => {
                if other.contains(':') && !has_ipv6_address {
                    continue;
                }
                if !other.contains(':') && !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: other.contains(':'),
                    destination: other.to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
        }
    }
    routes
}

#[cfg(target_os = "macos")]
fn get_macos_default_route(is_ipv6: bool) -> anyhow::Result<Option<(String, String)>> {
    let mut args = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push("default");

    let output =
        run_command_capture_output("route", &args).context("failed to run route -n get default")?;
    if !output.status.success() {
        if is_ipv6 {
            return Ok(None);
        }
        anyhow::bail!("route -n get default failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(key).map(|s| s.trim().to_owned()))
    };
    match (field("gateway:"), field("interface:")) {
        (Some(gateway), Some(interface)) if !interface.starts_with("utun") => {
            Ok(Some((gateway, interface)))
        }
        _ if is_ipv6 => Ok(None),
        _ => anyhow::bail!("no settled physical default route"),
    }
}

#[cfg(target_os = "macos")]
fn parse_cidr(value: &str) -> anyhow::Result<(IpAddr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid cidr {}", value))?;
    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("invalid cidr IP {}", ip))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid cidr prefix {}", prefix))?;
    Ok((ip, prefix))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
enum Action {
    #[cfg(target_os = "linux")]
    LinuxRoute(LinuxRoute),
    #[cfg(any(test, target_os = "linux"))]
    Resolver {
        path: PathBuf,
        original: String,
        intended: String,
    },
    #[cfg(target_os = "macos")]
    MacosRoute(MacosRoute),
    #[cfg(target_os = "macos")]
    MacosDns {
        service: String,
        original: Option<Vec<String>>,
        intended: Option<Vec<String>>,
        search: bool,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct Journal {
    #[cfg(target_os = "macos")]
    #[serde(default)]
    lan: Option<LanPolicy>,
    version: u32,
    owner: String,
    actions: Vec<Action>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    pending_gateways: std::collections::HashMap<usize, String>,
}

pub(super) enum CleanupState {
    None,
    Active { journal: Journal },
}

fn journal_path(owner: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        !owner.is_empty()
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid recovery owner"
    );
    Ok(Path::new(super::SOCK_DIR).join(format!("{owner}.recovery.json")))
}

pub(super) type SessionLock = std::sync::Arc<Flock<std::fs::File>>;
pub(super) fn lock(owner: &str) -> anyhow::Result<SessionLock> {
    std::fs::create_dir_all(super::SOCK_DIR)?;
    let path = journal_path(owner)?.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map(std::sync::Arc::new)
        .map_err(|(_, error)| {
            anyhow::anyhow!("network session {owner} is already owned or cannot be locked: {error}")
        })
}

impl Journal {
    fn persist(&self) -> anyhow::Result<()> {
        crate::shared::persistence::write_private_atomic(&self.path, &serde_json::to_vec(self)?)?;
        Ok(())
    }
    fn push(&mut self, action: Action) -> anyhow::Result<()> {
        self.actions.push(action);
        if let Err(error) = self.persist() {
            self.actions.pop();
            return Err(error);
        }
        Ok(())
    }

    fn replace_action(&mut self, index: usize, action: Action) -> anyhow::Result<()> {
        let previous = std::mem::replace(&mut self.actions[index], action);
        if let Err(error) = self.persist() {
            // Never let a subsequent reconciliation tick apply an intent that
            // did not complete its checkpoint. Retrying must persist it again.
            self.actions[index] = previous;
            return Err(error);
        }
        Ok(())
    }
}

pub(super) fn recover_network_cancellable(
    owner: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<SessionLock> {
    let budget = SetupBudget {
        deadline: Instant::now() + Duration::from_secs(20),
        cancelled,
    };
    budget.check()?;
    let lock = lock(owner)?;
    ensure_stopped(owner)?;
    recover_locked_with(owner, &budget)?;
    Ok(lock)
}

pub(super) fn recover_locked(owner: &str) -> anyhow::Result<()> {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    recover_locked_with(
        owner,
        &SetupBudget {
            deadline: Instant::now() + Duration::from_secs(20),
            cancelled: &cancelled,
        },
    )
}

fn recover_locked_with(owner: &str, budget: &SetupBudget<'_>) -> anyhow::Result<()> {
    budget.check()?;
    let path = journal_path(owner)?;
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut journal: Journal =
        serde_json::from_slice(&data).context("invalid network recovery journal; preserving it")?;
    anyhow::ensure!(
        journal.version == 1 && journal.owner == owner,
        "unsupported or mismatched network journal"
    );
    journal.path = path;
    rollback_with(&mut journal, budget, |action| {
        restore_checked(action, Some(budget))
    })
}

struct SetupBudget<'a> {
    deadline: Instant,
    cancelled: &'a std::sync::atomic::AtomicBool,
}
impl SetupBudget<'_> {
    fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.cancelled.load(std::sync::atomic::Ordering::Acquire),
            "network operation cancelled"
        );
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "network operation deadline exceeded"
        );
        Ok(())
    }
}

pub(super) fn configure_network(
    interface: &str,
    config: &ParsedUserspaceConfig,
    owner: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<CleanupState> {
    let budget = SetupBudget {
        deadline: Instant::now() + Duration::from_secs(20),
        cancelled,
    };
    budget.check()?;
    let mut journal = Journal {
        #[cfg(target_os = "macos")]
        lan: None,
        version: 1,
        owner: owner.to_string(),
        actions: Vec::new(),
        path: journal_path(owner)?,
        pending_gateways: Default::default(),
    };
    journal.persist()?;
    #[cfg(target_os = "linux")]
    let result = configure_network_linux(interface, config, &mut journal, &budget);
    #[cfg(target_os = "macos")]
    let result = configure_network_macos(interface, config, &mut journal, &budget);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result: anyhow::Result<()> = {
        let _ = (interface, config);
        Ok(())
    };
    if let Err(error) = result.and_then(|()| budget.check()) {
        return match rollback(&mut journal) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!("network rollback incomplete: {cleanup}"))),
        };
    }
    Ok(CleanupState::Active { journal })
}

pub(super) fn cleanup_network(state: &CleanupState) -> anyhow::Result<()> {
    let CleanupState::Active { journal, .. } = state else {
        return Ok(());
    };
    let mut journal = Journal {
        #[cfg(target_os = "macos")]
        lan: journal.lan.clone(),
        version: journal.version,
        owner: journal.owner.clone(),
        actions: journal.actions.clone(),
        path: journal.path.clone(),
        pending_gateways: Default::default(),
    };
    rollback(&mut journal)
}

fn rollback(journal: &mut Journal) -> anyhow::Result<()> {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let budget = SetupBudget {
        deadline: Instant::now() + Duration::from_secs(20),
        cancelled: &cancelled,
    };
    rollback_with(journal, &budget, |action| {
        restore_checked(action, Some(&budget))
    })
}

// Keep effects injectable at the transactional boundary: checkpointing and retries
// follow the same production path even when a restoration command fails.
fn rollback_with(
    journal: &mut Journal,
    budget: &SetupBudget<'_>,
    mut restore_effect: impl FnMut(&Action) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for index in (0..journal.actions.len()).rev() {
        if let Err(error) = budget.check() {
            errors.push(error.to_string());
            break;
        }
        match restore_effect(&journal.actions[index]) {
            Ok(()) => {
                journal.actions.remove(index);
                if let Err(error) = journal.persist() {
                    errors.push(format!("failed to checkpoint restoration: {error}"));
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        match std::fs::remove_file(&journal.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    } else {
        anyhow::bail!("network recovery incomplete: {}", errors.join("; "))
    }
}

#[cfg(test)]
fn restore(action: &Action) -> anyhow::Result<()> {
    restore_checked(action, None)
}

fn restore_checked(action: &Action, budget: Option<&SetupBudget<'_>>) -> anyhow::Result<()> {
    let check = || budget.map_or(Ok(()), SetupBudget::check);
    check()?;
    match action {
        #[cfg(target_os = "linux")]
        Action::LinuxRoute(route) => {
            let current = linux_route_observation(route)?;
            if current.is_empty() {
                return Ok(());
            }
            anyhow::ensure!(
                linux_route_owned(route, &current),
                "route ownership conflict for {}",
                route.destination
            );
            check()?;
            ignore_missing_route(del_linux_route(route))
        }
        #[cfg(target_os = "macos")]
        Action::MacosRoute(route) => {
            match macos_route_status(route)? {
                None => return Ok(()),
                Some(false) => anyhow::bail!("route ownership conflict for {}", route.destination),
                Some(true) => {}
            }
            check()?;
            ignore_missing_route(del_macos_route(route))
        }
        #[cfg(any(test, target_os = "linux"))]
        Action::Resolver {
            path,
            original,
            intended,
        } => {
            let current = std::fs::read_to_string(path)?;
            if &current == original {
                return Ok(());
            }
            anyhow::ensure!(
                &current == intended,
                "resolver ownership conflict; preserving current DNS"
            );
            check()?;
            std::fs::write(path, original)?;
            Ok(())
        }
        #[cfg(target_os = "macos")]
        Action::MacosDns {
            service,
            original,
            intended,
            search,
        } => {
            let current = if *search {
                get_macos_search_domains(service)?
            } else {
                get_macos_dns_servers(service)?
            };
            if &current == original {
                return Ok(());
            }
            anyhow::ensure!(
                &current == intended,
                "DNS ownership conflict on {service}; preserving current settings"
            );
            check()?;
            match (search, original) {
                (true, Some(values)) => set_macos_search_domains(service, values),
                (true, None) => set_macos_search_domains_empty(service),
                (false, Some(values)) => set_macos_dns_servers(service, values),
                (false, None) => set_macos_dns_servers_empty(service),
            }
        }
    }
}

fn ignore_missing_route(result: anyhow::Result<()>) -> anyhow::Result<()> {
    match result {
        Err(e)
            if [
                "No such process",
                "not in table",
                "No such file",
                "not found",
            ]
            .iter()
            .any(|text| e.to_string().contains(text)) =>
        {
            Ok(())
        }
        other => other,
    }
}

#[cfg(target_os = "linux")]
fn linux_route_owned(route: &LinuxRoute, current: &[serde_json::Value]) -> bool {
    current.iter().all(|value| {
        value.get("gateway").and_then(serde_json::Value::as_str) == route.via.as_deref()
            && value.get("dev").and_then(serde_json::Value::as_str) == route.dev.as_deref()
    })
}

#[cfg(target_os = "linux")]
fn linux_route_observation(route: &LinuxRoute) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut args = vec!["-j"];
    if route.is_ipv6 {
        args.push("-6");
    }
    args.extend(["route", "show", "exact", &route.destination]);
    let output = run_command_capture_output("ip", &args)?;
    anyhow::ensure!(
        output.status.success(),
        "cannot inspect route {}",
        route.destination
    );
    serde_json::from_slice(&output.stdout).context("invalid route observation")
}

#[cfg(target_os = "macos")]
fn macos_route_present(route: &MacosRoute) -> anyhow::Result<bool> {
    Ok(macos_route_status(route)?.is_some())
}

#[cfg(target_os = "macos")]
fn macos_route_status(route: &MacosRoute) -> anyhow::Result<Option<bool>> {
    let output = run_command_capture_output(
        "netstat",
        &["-rn", "-f", if route.is_ipv6 { "inet6" } else { "inet" }],
    )?;
    anyhow::ensure!(output.status.success(), "cannot inspect macOS routes");
    let expected =
        normalized_macos_destination(&route.destination).context("invalid planned route")?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(destination) = fields.first() else {
            continue;
        };
        if normalized_macos_destination(destination) != Some(expected) {
            continue;
        }
        let owned = route
            .interface
            .as_ref()
            .is_none_or(|interface| fields.contains(&interface.as_str()))
            && route
                .gateway
                .as_ref()
                .is_none_or(|gateway| fields.get(1).is_some_and(|actual| *actual == gateway));
        return Ok(Some(owned));
    }
    Ok(None)
}

#[cfg(any(test, target_os = "macos"))]
fn normalized_macos_destination(value: &str) -> Option<(IpAddr, u8)> {
    let inferred;
    let (address, prefix) = if let Some(parts) = value.split_once('/') {
        parts
    } else {
        inferred = if value.contains(':') {
            "128".to_string()
        } else {
            (value.split('.').count() * 8).to_string()
        };
        (value, inferred.as_str())
    };
    let address = if !address.contains(':') && address != "default" {
        let mut parts = address.split('.').map(str::to_string).collect::<Vec<_>>();
        while parts.len() < 4 {
            parts.push("0".to_string());
        }
        parts.join(".")
    } else {
        address.to_string()
    };
    Some((address.parse().ok()?, prefix.parse().ok()?))
}

// A changed gateway must survive two polling observations before replacing
// an endpoint route. Pending observations are transient, never recovery intent.
fn gateway_settled(journal: &mut Journal, index: usize, observation: String) -> bool {
    let settled = journal.pending_gateways.get(&index) == Some(&observation);
    journal.pending_gateways.insert(index, observation);
    settled
}

pub(super) fn reconcile_network_cancellable(
    state: &mut CleanupState,
    cancelled: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<()> {
    let budget = SetupBudget {
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled,
    };
    budget.check()?;
    let CleanupState::Active { journal } = state else {
        return Ok(());
    };
    #[cfg(target_os = "macos")]
    reconcile_lan(journal, &budget)?;
    for index in 0..journal.actions.len() {
        budget.check()?;
        match journal.actions[index].clone() {
            #[cfg(target_os = "linux")]
            Action::LinuxRoute(mut route) => {
                if route.via.is_some() {
                    let observed = if route.is_ipv6 {
                        get_linux_default_route_v6().context("no settled IPv6 default gateway")
                    } else {
                        get_linux_default_route_v4()
                    };
                    let default = match observed {
                        Ok(default) => default,
                        Err(error) => {
                            journal.pending_gateways.remove(&index);
                            return Err(error);
                        }
                    };
                    if route.via.as_deref() != Some(default.gateway.as_str())
                        || route.dev.as_deref() != Some(default.dev.as_str())
                    {
                        if !gateway_settled(
                            journal,
                            index,
                            format!("{}@{}", default.gateway, default.dev),
                        ) {
                            continue;
                        }
                        budget.check()?;
                        restore_checked(&journal.actions[index], Some(&budget))?;
                        budget.check()?;
                        route.via = Some(default.gateway);
                        route.dev = Some(default.dev);
                        anyhow::ensure!(
                            linux_route_observation(&route)?.is_empty(),
                            "endpoint route ownership conflict after gateway change"
                        );
                        journal.replace_action(index, Action::LinuxRoute(route.clone()))?;
                    }
                    journal.pending_gateways.remove(&index);
                }
                budget.check()?;
                let current = linux_route_observation(&route)?;
                if current.is_empty() {
                    budget.check()?;
                    add_linux_route(&route)?;
                } else {
                    anyhow::ensure!(
                        linux_route_owned(&route, &current),
                        "route ownership conflict during reconciliation"
                    );
                }
            }
            #[cfg(target_os = "macos")]
            Action::MacosRoute(mut route) => {
                if route.gateway.is_some() {
                    let (gateway, interface) = match get_macos_default_route(route.is_ipv6) {
                        Ok(Some(default)) => default,
                        Ok(None) => {
                            journal.pending_gateways.remove(&index);
                            continue;
                        }
                        Err(error) => {
                            journal.pending_gateways.remove(&index);
                            return Err(error);
                        }
                    };
                    if route.gateway.as_deref() != Some(gateway.as_str())
                        || route.interface.as_deref() != Some(interface.as_str())
                    {
                        if !gateway_settled(journal, index, format!("{gateway}@{interface}")) {
                            continue;
                        }
                        budget.check()?;
                        restore_checked(&journal.actions[index], Some(&budget))?;
                        budget.check()?;
                        route.gateway = Some(gateway);
                        route.interface = Some(interface);
                        anyhow::ensure!(
                            !macos_route_present(&route)?,
                            "endpoint route ownership conflict after gateway change"
                        );
                        journal.replace_action(index, Action::MacosRoute(route.clone()))?;
                    }
                    journal.pending_gateways.remove(&index);
                }
                budget.check()?;
                match macos_route_status(&route)? {
                    None => {
                        budget.check()?;
                        add_macos_route(&route)?;
                    }
                    Some(true) => {}
                    Some(false) => anyhow::bail!("route ownership conflict during reconciliation"),
                }
            }
            #[cfg(any(test, target_os = "linux"))]
            Action::Resolver { path, intended, .. } => {
                anyhow::ensure!(
                    std::fs::read_to_string(path)? == intended,
                    "resolver ownership conflict during reconciliation"
                );
            }
            #[cfg(target_os = "macos")]
            Action::MacosDns {
                service,
                search,
                intended,
                ..
            } => {
                let current = if search {
                    get_macos_search_domains(&service)?
                } else {
                    get_macos_dns_servers(&service)?
                };
                anyhow::ensure!(
                    current == intended,
                    "DNS ownership conflict during reconciliation for {service}"
                );
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let dns = journal.actions.iter().find_map(|action| match action {
            Action::MacosDns {
                search: false,
                intended: Some(values),
                ..
            } => Some(values.clone()),
            _ => None,
        });
        if let Some(dns) = dns {
            budget.check()?;
            for service in list_macos_network_services()? {
                budget.check()?;
                for search in [false, true] {
                    budget.check()?;
                    if journal.actions.iter().any(|action| matches!(action, Action::MacosDns { service: existing, search: existing_search, .. } if existing == &service && *existing_search == search)) { continue; }
                    let original = if search {
                        get_macos_search_domains(&service)?
                    } else {
                        get_macos_dns_servers(&service)?
                    };
                    let intended = if search { None } else { Some(dns.clone()) };
                    journal.push(Action::MacosDns {
                        service: service.clone(),
                        original,
                        intended,
                        search,
                    })?;
                    if search {
                        budget.check()?;
                        set_macos_search_domains_empty(&service)?;
                    } else {
                        budget.check()?;
                        set_macos_dns_servers(&service, &dns)?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn ensure_stopped(owner: &str) -> anyhow::Result<()> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    let path = Path::new(super::SOCK_DIR).join(format!("{owner}.sock"));
    #[cfg(target_os = "macos")]
    let flags = SockFlag::empty();
    #[cfg(not(target_os = "macos"))]
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    let socket = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
    #[cfg(target_os = "macos")]
    {
        // macOS requires setting these properties after socket creation.
        use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
        fcntl(&socket, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&socket, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    }
    let address = UnixAddr::new(&path)?;
    match connect(socket.as_raw_fd(), &address) {
        Ok(()) => anyhow::bail!("control socket for {owner} is active; refusing network recovery"),
        Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED) => Ok(()),
        Err(error) => {
            Err(error).context("control socket ownership is unknown; refusing network recovery")
        }
    }
}

pub(super) fn recover_stopped_session(owner: &str) -> anyhow::Result<()> {
    let _lock = lock(owner)?;
    ensure_stopped(owner)?;
    recover_locked(owner)?;
    remove_stopped_endpoints(Path::new(super::SOCK_DIR), owner)
}

/// Call only after verifying the stopped owner while holding its session lock.
pub(super) fn remove_stopped_endpoints(directory: &Path, owner: &str) -> anyhow::Result<()> {
    for extension in ["sock", "stop"] {
        let path = directory.join(format!("{owner}.{extension}"));
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) fn has_pending_gateway(state: &CleanupState) -> bool {
    matches!(state, CleanupState::Active { journal } if !journal.pending_gateways.is_empty())
}

#[cfg(target_os = "macos")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct LanPolicy {
    interface: String,
    original: Vec<MacosRoute>,
    dns: Vec<String>,
}

#[cfg(target_os = "macos")]
fn physical_lans() -> anyhow::Result<Vec<String>> {
    // Enumerate hardware ports so virtual bridges and other VPN interfaces cannot become bypasses.
    let ports = run_command_capture_output("networksetup", &["-listallhardwareports"])?;
    anyhow::ensure!(
        ports.status.success(),
        "cannot enumerate physical network interfaces"
    );
    let devices: Vec<_> = String::from_utf8(ports.stdout)?
        .lines()
        .filter_map(|line| line.strip_prefix("Device: ").map(str::to_owned))
        .collect();
    let mut prefixes = Vec::new();
    for device in devices {
        if !device.starts_with("en") {
            continue;
        }
        let output = run_command_capture_output("ifconfig", &[&device])?;
        anyhow::ensure!(
            output.status.success(),
            "cannot inspect physical interface {device}"
        );
        let text = String::from_utf8(output.stdout)?;
        if !text.lines().any(|line| line.trim() == "status: active") {
            continue;
        }
        for line in text.lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.first() == Some(&"inet") && f.len() >= 4 && f[2] == "netmask" {
                let ip: std::net::Ipv4Addr = f[1].parse()?;
                if ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_unspecified()
                {
                    continue;
                }
                let mask = u32::from_str_radix(f[3].trim_start_matches("0x"), 16)?;
                let prefix = mask.leading_ones();
                anyhow::ensure!(
                    mask == if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    },
                    "noncontiguous interface mask"
                );
                if prefix > 0 && prefix < 32 {
                    prefixes.push(format!("{ip}/{prefix}"));
                }
            } else if f.first() == Some(&"inet6") && f.len() >= 4 && f[2] == "prefixlen" {
                let ip: std::net::Ipv6Addr = f[1].split('%').next().unwrap_or("").parse()?;
                let prefix: u8 = f[3].parse()?;
                if prefix > 0
                    && prefix < 128
                    && !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_unicast_link_local()
                {
                    prefixes.push(format!("{ip}/{prefix}"));
                }
            }
        }
    }
    Ok(prefixes)
}
#[cfg(target_os = "macos")]
fn lan_routes(policy: &LanPolicy) -> anyhow::Result<Vec<MacosRoute>> {
    let mut bases = Vec::new();
    for route in &policy.original {
        let (ip, prefix) =
            normalized_macos_destination(&route.destination).context("invalid VPN route")?;
        bases.push(format!("{ip}/{prefix}"));
    }
    let mut routes = crate::lan::vpn_routes(&bases, &physical_lans()?)?;
    // DNS hosts stay tunneled even when their address overlaps the LAN.
    for dns in &policy.dns {
        let ip: IpAddr = dns.parse()?;
        let host = format!("{ip}/{}", if ip.is_ipv6() { 128 } else { 32 });
        let target = crate::lan::Prefix::parse(&host)?;
        if bases
            .iter()
            .any(|base| crate::lan::Prefix::parse(base).is_ok_and(|base| base.contains(target)))
        {
            routes.push(host);
        }
    }
    routes.sort();
    routes.dedup();
    Ok(routes
        .into_iter()
        .map(|destination| MacosRoute {
            is_ipv6: destination.contains(':'),
            destination,
            interface: Some(policy.interface.clone()),
            gateway: None,
        })
        .collect())
}
#[cfg(target_os = "macos")]
fn reconcile_lan(journal: &mut Journal, budget: &SetupBudget<'_>) -> anyhow::Result<()> {
    let Some(policy) = journal.lan.clone() else {
        return Ok(());
    };
    budget.check()?;
    // Missing primary networks must not turn a transient observation into new routing intent.
    match get_macos_default_route(false) {
        Ok(Some(_)) => {}
        Ok(None) => {
            journal.pending_gateways.clear();
            return Ok(());
        }
        Err(error) => {
            journal.pending_gateways.clear();
            return Err(error);
        }
    }
    let desired = lan_routes(&policy)?;
    // Restore old intent before retiring it; a failed checkpoint leaves recoverable evidence.
    for index in (0..journal.actions.len()).rev() {
        if let Action::MacosRoute(route) = &journal.actions[index] {
            if route.gateway.is_none()
                && route.interface.as_ref() == Some(&policy.interface)
                && !desired.contains(route)
            {
                budget.check()?;
                restore_checked(&journal.actions[index], Some(budget))?;
                let previous = journal.actions.remove(index);
                if let Err(error) = journal.persist() {
                    journal.actions.insert(index, previous);
                    return Err(error);
                }
                journal.pending_gateways.clear();
            }
        }
    }
    for route in desired {
        budget.check()?;
        if journal
            .actions
            .iter()
            .any(|action| matches!(action,Action::MacosRoute(existing) if existing == &route))
        {
            continue;
        }
        match macos_route_status(&route)? {
            Some(true) => continue, // Existing interface routes remain borrowed, never owned cleanup intent.
            Some(false) => anyhow::bail!(
                "LAN route planning conflicts with existing route {}",
                route.destination
            ),
            None => {}
        }
        journal.push(Action::MacosRoute(route.clone()))?;
        budget.check()?;
        anyhow::ensure!(
            add_macos_route(&route)?,
            "LAN route appeared during reconciliation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn stopped_recovery_removes_crash_endpoints_and_preserves_receipts() {
        use std::os::unix::net::UnixListener;
        let directory =
            PathBuf::from("/tmp").join(format!("tmx-recovery-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        for endpoint in ["wg-test.sock", "wg-test.stop"] {
            let listener = UnixListener::bind(directory.join(endpoint)).unwrap();
            drop(listener); // A killed helper leaves these filesystem nodes behind.
        }
        for receipt in ["wg-test.session", "wg-test.recovery.lock", "other.sock"] {
            std::fs::write(directory.join(receipt), "preserved").unwrap();
        }
        remove_stopped_endpoints(&directory, "wg-test").unwrap();
        remove_stopped_endpoints(&directory, "wg-test").unwrap();
        assert!(!directory.join("wg-test.sock").exists());
        assert!(!directory.join("wg-test.stop").exists());
        for receipt in ["wg-test.session", "wg-test.recovery.lock", "other.sock"] {
            assert_eq!(
                std::fs::read_to_string(directory.join(receipt)).unwrap(),
                "preserved"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn planned_destinations(allowed_ips: &[&str], ipv6: bool) -> Vec<String> {
        let config = ParsedUserspaceConfig {
            allow_lan: false,
            private_key: [0; 32],
            mtu: None,
            addresses: vec!["10.0.0.2/32".into()],
            dns_servers: vec![],
            peer_public_key: [0; 32],
            peer_preshared_key: None,
            allowed_ips: allowed_ips.iter().map(|value| (*value).into()).collect(),
            endpoint: "192.0.2.1:51820".parse().unwrap(),
        };
        #[cfg(target_os = "macos")]
        let routes = macos_allowed_routes(&config, "vpn-test", true, ipv6);
        #[cfg(target_os = "linux")]
        let routes = linux_allowed_routes("vpn-test", &config, ipv6);
        routes.into_iter().map(|route| route.destination).collect()
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_lan_overlap_preserves_explicit_allowed_ips_without_bypasses() {
        let allowed = [
            "192.168.0.0/16",
            "192.168.1.0/24",
            "fd00::/8",
            "fd00:1::/64",
        ];
        assert_eq!(planned_destinations(&allowed, true), allowed);
        assert_eq!(planned_destinations(&allowed, false), &allowed[..2]);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_dual_stack_defaults_keep_existing_split_route_policy() {
        let allowed = ["0.0.0.0/0", "::/0"];
        assert_eq!(
            planned_destinations(&allowed, true),
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        );
        assert_eq!(
            planned_destinations(&allowed, false),
            ["0.0.0.0/1", "128.0.0.0/1"]
        );
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tunmux-network-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn journal(&self) -> Journal {
            Journal {
                #[cfg(target_os = "macos")]
                lan: None,
                version: 1,
                owner: "test".into(),
                path: self.0.join("recovery.json"),
                actions: vec![],
                pending_gateways: Default::default(),
            }
        }
        fn dns(&self, journal: &mut Journal, name: &str, current: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, current).unwrap();
            journal
                .push(Action::Resolver {
                    path: path.clone(),
                    original: "original".into(),
                    intended: "owned".into(),
                })
                .unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn test_failed_action_replacement_keeps_previous_intent_until_retry_is_durable() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let path = fixture.dns(&mut journal, "dns", "owned");
        let durable_path = journal.path.clone();
        let before = serde_json::to_vec(&journal.actions).unwrap();
        let replacement = Action::Resolver {
            path,
            original: "original".into(),
            intended: "new-owned".into(),
        };
        // A missing parent deterministically fails the checkpoint before rename.
        journal.path = fixture.0.join("missing-parent/recovery.json");
        assert!(journal.replace_action(0, replacement.clone()).is_err());
        assert_eq!(serde_json::to_vec(&journal.actions).unwrap(), before);
        let reloaded: Journal =
            serde_json::from_slice(&std::fs::read(&durable_path).unwrap()).unwrap();
        assert_eq!(serde_json::to_vec(&reloaded.actions).unwrap(), before);
        journal.path = durable_path;
        journal.replace_action(0, replacement).unwrap();
        let reloaded: Journal =
            serde_json::from_slice(&std::fs::read(&journal.path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_vec(&journal.actions).unwrap(),
            serde_json::to_vec(&reloaded.actions).unwrap()
        );
        assert_ne!(serde_json::to_vec(&journal.actions).unwrap(), before);
    }

    #[test]
    fn test_failed_push_does_not_leave_uncheckpointed_intent_in_memory() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        journal.persist().unwrap();
        let durable_path = journal.path.clone();
        journal.path = fixture.0.join("missing-parent/recovery.json");
        assert!(journal
            .push(Action::Resolver {
                path: fixture.0.join("dns"),
                original: "original".into(),
                intended: "owned".into(),
            })
            .is_err());
        assert!(journal.actions.is_empty());
        let reloaded: Journal =
            serde_json::from_slice(&std::fs::read(durable_path).unwrap()).unwrap();
        assert!(reloaded.actions.is_empty());
    }

    #[test]
    fn test_gateway_changes_require_two_matching_observations() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        assert!(!gateway_settled(&mut journal, 0, "gateway-a".into()));
        assert!(!gateway_settled(&mut journal, 0, "gateway-b".into()));
        assert!(gateway_settled(&mut journal, 0, "gateway-b".into()));
        // Losing the primary network invalidates the previous observation.
        journal.pending_gateways.remove(&0);
        assert!(!gateway_settled(&mut journal, 0, "gateway-b".into()));
        journal.persist().unwrap();
        let loaded: Journal =
            serde_json::from_slice(&std::fs::read(&journal.path).unwrap()).unwrap();
        assert!(loaded.pending_gateways.is_empty());
    }

    #[test]
    fn test_expired_recovery_leaves_journal_retryable() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        fixture.dns(&mut journal, "dns", "owned");
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let budget = SetupBudget {
            deadline: Instant::now(),
            cancelled: &cancelled,
        };
        let mut calls = 0;
        assert!(rollback_with(&mut journal, &budget, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
        assert_eq!(journal.actions.len(), 1);
        assert!(journal.path.exists());
    }

    #[test]
    fn test_cancelled_reconciliation_does_not_touch_journal_or_dns() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let path = fixture.dns(&mut journal, "dns", "owned");
        let before = std::fs::read(&journal.path).unwrap();
        let journal_path = journal.path.clone();
        let mut state = CleanupState::Active { journal };
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        assert!(reconcile_network_cancellable(&mut state, &cancelled).is_err());
        assert_eq!(std::fs::read(journal_path).unwrap(), before);
        assert_eq!(std::fs::read_to_string(path).unwrap(), "owned");
    }

    #[test]
    fn test_cancelled_recovery_preserves_pending_actions() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let path = fixture.dns(&mut journal, "dns", "owned");
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        let budget = SetupBudget {
            deadline: Instant::now() + Duration::from_secs(20),
            cancelled: &cancelled,
        };
        assert!(rollback_with(&mut journal, &budget, restore).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "owned");
        assert_eq!(journal.actions.len(), 1);
        assert!(journal.path.exists());
        // Cleanup must use an independent budget after cancellation.
        rollback(&mut journal).unwrap();
    }

    #[test]
    fn test_injected_restoration_failure_retains_only_pending_action_and_retries() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let first = fixture.dns(&mut journal, "first", "owned");
        let second = fixture.dns(&mut journal, "second", "owned");
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let budget = SetupBudget {
            deadline: Instant::now() + Duration::from_secs(20),
            cancelled: &cancelled,
        };
        let mut calls = 0;
        assert!(rollback_with(&mut journal, &budget, |action| {
            calls += 1;
            if calls == 1 {
                anyhow::bail!("injected effect failure")
            }
            restore(action)
        })
        .is_err());
        assert_eq!(calls, 2);
        assert_eq!(std::fs::read_to_string(first).unwrap(), "original");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "owned");
        let mut reloaded: Journal =
            serde_json::from_slice(&std::fs::read(&journal.path).unwrap()).unwrap();
        assert_eq!(reloaded.actions.len(), 1);
        reloaded.path = journal.path;
        rollback(&mut reloaded).unwrap();
        assert_eq!(std::fs::read_to_string(second).unwrap(), "original");
    }

    #[test]
    fn test_rollback_restores_owned_dns_and_is_repeatable() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let path = fixture.dns(&mut journal, "dns", "owned");
        rollback(&mut journal).unwrap();
        rollback(&mut journal).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
        assert!(!journal.path.exists());
    }
    #[test]
    fn test_rollback_retains_conflict_but_restores_independent_dns() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let owned = fixture.dns(&mut journal, "owned", "owned");
        let changed = fixture.dns(&mut journal, "changed", "user-modified");
        assert!(rollback(&mut journal)
            .unwrap_err()
            .to_string()
            .contains("ownership conflict"));
        assert_eq!(std::fs::read_to_string(owned).unwrap(), "original");
        assert_eq!(std::fs::read_to_string(changed).unwrap(), "user-modified");
        let saved: Journal =
            serde_json::from_slice(&std::fs::read(&journal.path).unwrap()).unwrap();
        assert_eq!(saved.actions.len(), 1);
    }
    #[test]
    fn test_crash_before_dns_mutation_recovers_without_changing_original() {
        let fixture = Fixture::new();
        let mut journal = fixture.journal();
        let path = fixture.dns(&mut journal, "dns", "original");
        let mut reloaded: Journal =
            serde_json::from_slice(&std::fs::read(&journal.path).unwrap()).unwrap();
        reloaded.path = journal.path;
        rollback(&mut reloaded).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
    }
    #[test]
    fn test_command_output_is_capped() {
        let output = run_command_capture_output("sh", &["-c", "head -c 131072 /dev/zero"]).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 65536);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn test_route_ownership_rejects_other_gateway_or_interface() {
        let route = LinuxRoute {
            is_ipv6: false,
            destination: "198.51.100.1/32".into(),
            via: Some("192.0.2.1".into()),
            dev: Some("eth0".into()),
        };
        let observed =
            |gateway, interface| vec![serde_json::json!({"gateway": gateway, "dev": interface})];
        assert!(linux_route_owned(&route, &observed("192.0.2.1", "eth0")));
        assert!(!linux_route_owned(&route, &observed("192.0.2.2", "eth0")));
        assert!(!linux_route_owned(&route, &observed("192.0.2.1", "eth1")));
    }
    #[test]
    fn test_macos_route_destination_fixtures() {
        assert_eq!(
            normalized_macos_destination("128/1"),
            normalized_macos_destination("128.0.0.0/1")
        );
        assert_eq!(
            normalized_macos_destination("192.0.2.1"),
            Some(("192.0.2.1".parse().unwrap(), 32))
        );
        assert_eq!(
            normalized_macos_destination("::/1"),
            Some(("::".parse().unwrap(), 1))
        );
        assert_eq!(normalized_macos_destination("default"), None);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn test_no_primary_network_observation_is_not_a_default_route() {
        assert!(parse_linux_default_route("192.0.2.0/24 dev eth0").is_err());
    }
    #[test]
    fn test_command_timeout_is_bounded() {
        let started = Instant::now();
        assert!(run_command_capture_output("sleep", &["10"])
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}

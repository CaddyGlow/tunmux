#[cfg(not(unix))]
pub fn maybe_run_from_env() -> bool {
    false
}

#[cfg(unix)]
use base64::Engine;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use daemonize::Daemonize;
#[cfg(unix)]
use gotatun::device::uapi::UapiServer;
#[cfg(unix)]
use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder, Peer};
#[cfg(unix)]
use gotatun::tun::tun_async_device::TunDevice;
#[cfg(unix)]
use gotatun::x25519::{PublicKey, StaticSecret};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(unix)]
const READY_OK: &[u8] = &[1];
#[cfg(unix)]
const READY_ERR: &[u8] = &[0];
#[cfg(unix)]
const SOCK_DIR: &str = "/var/run/wireguard";
#[cfg(unix)]
const HELPER_ENV: &str = "TUNMUX_GOTATUN_HELPER";
#[cfg(unix)]
const CONFIG_B64_ENV: &str = "TUNMUX_GOTATUN_CONFIG_B64";

#[cfg(unix)]
struct RunningDevice {
    interface_name: String,
    control_socket_path: PathBuf,
    device: Device<DefaultDeviceTransports>,
    cleanup: CleanupState,
}

#[cfg(unix)]
enum CleanupState {
    None,
    #[cfg(target_os = "linux")]
    Linux(LinuxCleanupState),
    #[cfg(target_os = "macos")]
    Macos(MacosCleanupState),
}

#[cfg(target_os = "linux")]
struct LinuxCleanupState {
    routes_added: Vec<LinuxRoute>,
    original_resolv_conf: Option<String>,
}

#[cfg(target_os = "linux")]
struct LinuxRoute {
    is_ipv6: bool,
    destination: String,
    via: Option<String>,
    dev: Option<String>,
}

#[cfg(target_os = "macos")]
struct MacosCleanupState {
    routes_added: Vec<MacosRoute>,
}

#[cfg(target_os = "macos")]
struct MacosRoute {
    is_ipv6: bool,
    destination: String,
    interface: Option<String>,
    gateway: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ParsedUserspaceConfig {
    private_key: [u8; 32],
    addresses: Vec<String>,
    dns_servers: Vec<String>,
    peer_public_key: [u8; 32],
    peer_preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<String>,
    endpoint: SocketAddr,
}

#[cfg(unix)]
pub fn maybe_run_from_env() -> bool {
    if std::env::var_os(HELPER_ENV).is_none() {
        return false;
    }

    let mut args = std::env::args();
    let _program = args.next();
    let interface = match args.next() {
        Some(value) => value,
        None => {
            eprintln!("tunmux gotatun helper: missing interface argument");
            std::process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("tunmux gotatun helper: unexpected extra arguments");
        std::process::exit(2);
    }

    if let Err(e) = daemonize_and_run(&interface) {
        eprintln!("tunmux gotatun helper failed: {e}");
        std::process::exit(1);
    }
    true
}

#[cfg(unix)]
fn daemonize_and_run(interface: &str) -> anyhow::Result<()> {
    let (child_tx, parent_rx) = UnixDatagram::pair().context("failed to create status socket")?;
    let daemonize = Daemonize::new().working_directory("/tmp");

    match daemonize.execute() {
        daemonize::Outcome::Parent(Err(e)) => {
            anyhow::bail!("failed to daemonize userspace helper: {}", e);
        }
        daemonize::Outcome::Parent(Ok(_)) => {
            let mut status = [0u8; 1];
            parent_rx
                .recv(&mut status)
                .context("failed to receive startup status from helper child")?;
            if status == READY_OK {
                return Ok(());
            }
            anyhow::bail!("userspace helper child reported startup failure");
        }
        daemonize::Outcome::Child(result) => {
            let signal_parent = |ok: bool| -> io::Result<()> {
                child_tx.send(if ok { READY_OK } else { READY_ERR })?;
                Ok(())
            };

            if let Err(e) = result {
                let _ = signal_parent(false);
                anyhow::bail!("failed to initialize userspace helper child: {}", e);
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to create tokio runtime for userspace helper")?;

            let running = match rt.block_on(start_device(interface)) {
                Ok(value) => value,
                Err(e) => {
                    let _ = signal_parent(false);
                    return Err(e);
                }
            };

            signal_parent(true).context("failed to notify parent about helper startup")?;
            rt.block_on(wait_for_shutdown(&running))?;
            cleanup_network(&running);
            rt.block_on(async {
                running.device.stop().await;
            });
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn start_device(interface: &str) -> anyhow::Result<RunningDevice> {
    let parsed_config = parse_config_from_env()?;
    let tun_name = helper_tun_name(interface);
    let tun = TunDevice::from_name(&tun_name)
        .map_err(|e| anyhow::anyhow!("failed to create TUN device {}: {}", interface, e))?;
    let interface_name = tun
        .name()
        .map_err(|e| anyhow::anyhow!("failed to resolve TUN interface name: {}", e))?;

    #[cfg(target_os = "macos")]
    if let Some(name_file) = std::env::var_os("WG_TUN_NAME_FILE") {
        tokio::fs::write(&name_file, &interface_name)
            .await
            .with_context(|| {
                format!(
                    "failed writing WG_TUN_NAME_FILE at {}",
                    PathBuf::from(name_file).display()
                )
            })?;
    }

    let uapi = UapiServer::default_unix_socket(interface, None, None)
        .map_err(|e| anyhow::anyhow!("failed to create UAPI socket for {}: {}", interface, e))?;

    let device = DeviceBuilder::new()
        .with_uapi(uapi)
        .with_default_udp()
        .with_ip(tun)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start gotatun device {}: {}", interface_name, e))?;

    if let Some(config) = parsed_config.as_ref() {
        if let Err(e) = apply_wireguard_config(&device, config).await {
            device.stop().await;
            let _ = std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
            return Err(e);
        }
    }

    let cleanup = if let Some(config) = parsed_config.as_ref() {
        match configure_network(&interface_name, config) {
            Ok(cleanup) => cleanup,
            Err(e) => {
                device.stop().await;
                let _ =
                    std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
                return Err(e);
            }
        }
    } else {
        CleanupState::None
    };

    let control_socket_path = PathBuf::from(SOCK_DIR).join(format!("{}.sock", interface));
    Ok(RunningDevice {
        interface_name,
        control_socket_path,
        device,
        cleanup,
    })
}

#[cfg(unix)]
async fn wait_for_shutdown(running: &RunningDevice) -> anyhow::Result<()> {
    let mut sigint = signal(SignalKind::interrupt()).context("failed to set SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to set SIGTERM handler")?;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = ticker.tick() => {
                if !running.control_socket_path.exists() {
                    break;
                }

                #[cfg(target_os = "linux")]
                {
                    let iface_path = Path::new("/sys/class/net").join(&running.interface_name);
                    if !iface_path.exists() {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn parse_config_from_env() -> anyhow::Result<Option<ParsedUserspaceConfig>> {
    let Some(encoded) = std::env::var_os(CONFIG_B64_ENV) else {
        return Ok(None);
    };
    let encoded = encoded
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", CONFIG_B64_ENV))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to decode userspace WireGuard config")?;
    let text = String::from_utf8(bytes).context("userspace WireGuard config is not UTF-8")?;
    parse_wg_quick_config(&text).map(Some)
}

#[cfg(unix)]
fn parse_wg_quick_config(config: &str) -> anyhow::Result<ParsedUserspaceConfig> {
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;
    let mut private_key = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut peer_public_key = None;
    let mut peer_preshared_key = None;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut endpoint = None;

    for raw_line in config.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = match &line[1..line.len() - 1] {
                "Interface" => Section::Interface,
                "Peer" => Section::Peer,
                _ => Section::None,
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if value.is_empty() {
            continue;
        }

        match section {
            Section::Interface => match key {
                "PrivateKey" => private_key = Some(decode_key32("PrivateKey", value)?),
                "Address" => addresses = split_csv(value),
                "DNS" => dns_servers = split_csv(value),
                _ => {}
            },
            Section::Peer => match key {
                "PublicKey" => peer_public_key = Some(decode_key32("PublicKey", value)?),
                "PresharedKey" => peer_preshared_key = Some(decode_key32("PresharedKey", value)?),
                "AllowedIPs" => allowed_ips = split_csv(value),
                "Endpoint" => endpoint = Some(parse_endpoint(value)?),
                _ => {}
            },
            Section::None => {}
        }
    }

    let private_key = private_key.ok_or_else(|| anyhow::anyhow!("missing Interface.PrivateKey"))?;
    if addresses.is_empty() {
        anyhow::bail!("missing Interface.Address");
    }
    let peer_public_key =
        peer_public_key.ok_or_else(|| anyhow::anyhow!("missing Peer.PublicKey"))?;
    if allowed_ips.is_empty() {
        anyhow::bail!("missing Peer.AllowedIPs");
    }
    let endpoint = endpoint.ok_or_else(|| anyhow::anyhow!("missing Peer.Endpoint"))?;

    Ok(ParsedUserspaceConfig {
        private_key,
        addresses,
        dns_servers,
        peer_public_key,
        peer_preshared_key,
        allowed_ips,
        endpoint,
    })
}

#[cfg(unix)]
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(unix)]
fn decode_key32(field: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("failed to decode {}", field))?;
    if decoded.len() != 32 {
        anyhow::bail!("{} must decode to 32 bytes", field);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[cfg(unix)]
fn parse_endpoint(value: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint {}", value))?;
    let ip: IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .with_context(|| format!("invalid endpoint IP {}", host))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid endpoint port {}", port))?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(unix)]
async fn apply_wireguard_config(
    device: &Device<DefaultDeviceTransports>,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<()> {
    let private_key = StaticSecret::from(config.private_key);
    let mut peer =
        Peer::new(PublicKey::from(config.peer_public_key)).with_endpoint(config.endpoint);
    peer.preshared_key = config.peer_preshared_key;

    for allowed in &config.allowed_ips {
        let network = allowed
            .parse()
            .with_context(|| format!("invalid AllowedIPs entry {}", allowed))?;
        peer.allowed_ips.push(network);
    }

    device
        .write(async move |device| {
            device.clear_peers();
            device.set_private_key(private_key).await;
            device.add_peer(peer);
        })
        .await
        .map_err(|e| anyhow::anyhow!("failed to configure gotatun device: {}", e))?;
    Ok(())
}

#[cfg(unix)]
fn helper_tun_name(interface: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        if interface == "utun" || interface.starts_with("utun") {
            return interface.to_string();
        }
        "utun".to_string()
    }

    #[cfg(not(target_os = "macos"))]
    {
        interface.to_string()
    }
}

#[cfg(unix)]
fn configure_network(
    interface: &str,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<CleanupState> {
    #[cfg(target_os = "linux")]
    {
        let cleanup = configure_network_linux(interface, config)?;
        Ok(CleanupState::Linux(cleanup))
    }

    #[cfg(target_os = "macos")]
    {
        let cleanup = configure_network_macos(interface, config)?;
        Ok(CleanupState::Macos(cleanup))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (interface, config);
        Ok(CleanupState::None)
    }
}

#[cfg(unix)]
fn cleanup_network(running: &RunningDevice) {
    match &running.cleanup {
        CleanupState::None => {}
        #[cfg(target_os = "linux")]
        CleanupState::Linux(state) => cleanup_network_linux(state),
        #[cfg(target_os = "macos")]
        CleanupState::Macos(state) => cleanup_network_macos(state),
    }
}

#[cfg(unix)]
fn run_command(name: &str, args: &[&str]) -> anyhow::Result<()> {
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
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
fn run_command_with_exists_ok(name: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = Command::new(name)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))?;
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

#[cfg(target_os = "linux")]
fn configure_network_linux(
    interface: &str,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<LinuxCleanupState> {
    let mut routes_added = Vec::new();
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));

    for address in &config.addresses {
        run_command("ip", &["addr", "add", address, "dev", interface])?;
    }
    run_command("ip", &["link", "set", "up", "dev", interface])?;

    let endpoint_route = match config.endpoint.ip() {
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

    if let Some(route) = endpoint_route {
        if add_linux_route(&route)? {
            routes_added.push(route);
        }
    }

    for route in linux_allowed_routes(interface, config, has_ipv6_address) {
        if add_linux_route(&route)? {
            routes_added.push(route);
        }
    }

    let original_resolv_conf = if should_manage_global_resolv_conf() {
        let original = std::fs::read_to_string("/etc/resolv.conf").ok();
        if !config.dns_servers.is_empty() {
            let contents: String = config
                .dns_servers
                .iter()
                .map(|dns| format!("nameserver {}\n", dns))
                .collect();
            std::fs::write("/etc/resolv.conf", contents)
                .context("failed to update /etc/resolv.conf for userspace tunnel")?;
        }
        original
    } else {
        None
    };

    Ok(LinuxCleanupState {
        routes_added,
        original_resolv_conf,
    })
}

#[cfg(target_os = "linux")]
fn cleanup_network_linux(state: &LinuxCleanupState) {
    for route in state.routes_added.iter().rev() {
        let _ = del_linux_route(route);
    }
    if let Some(original) = &state.original_resolv_conf {
        let _ = std::fs::write("/etc/resolv.conf", original);
    }
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
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("failed to run ip route show default")?;
    if !output.status.success() {
        anyhow::bail!("ip route show default failed");
    }
    parse_linux_default_route(std::str::from_utf8(&output.stdout).unwrap_or_default())
}

#[cfg(target_os = "linux")]
fn get_linux_default_route_v6() -> Option<LinuxDefaultRoute> {
    let output = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .ok()?;
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
) -> anyhow::Result<MacosCleanupState> {
    let mut routes_added = Vec::new();
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));
    for address in &config.addresses {
        let (ip, prefix) = parse_cidr(address)?;
        match ip {
            IpAddr::V4(addr) => {
                let ip_string = addr.to_string();
                run_command(
                    "ifconfig",
                    &[
                        interface,
                        "inet",
                        ip_string.as_str(),
                        ip_string.as_str(),
                        "alias",
                    ],
                )?;
            }
            IpAddr::V6(addr) => {
                let ip_string = addr.to_string();
                let prefix_string = prefix.to_string();
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
    run_command("ifconfig", &[interface, "up"])?;

    let endpoint_is_ipv6 = matches!(config.endpoint.ip(), IpAddr::V6(_));
    if !endpoint_is_ipv6 || has_ipv6_address {
        if let Some(default_gateway) = get_macos_default_gateway(endpoint_is_ipv6)? {
            let endpoint_route = MacosRoute {
                is_ipv6: endpoint_is_ipv6,
                destination: config.endpoint.ip().to_string(),
                interface: None,
                gateway: Some(default_gateway),
            };
            if add_macos_route(&endpoint_route)? {
                routes_added.push(endpoint_route);
            }
        }
    }

    for route in macos_allowed_routes(config, interface, has_ipv6_address) {
        if add_macos_route(&route)? {
            routes_added.push(route);
        }
    }

    Ok(MacosCleanupState { routes_added })
}

#[cfg(target_os = "macos")]
fn cleanup_network_macos(state: &MacosCleanupState) {
    for route in state.routes_added.iter().rev() {
        let _ = del_macos_route(route);
    }
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
        args.push("-interface".into());
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
        args.push("-interface".into());
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command("route", &refs)
}

#[cfg(target_os = "macos")]
fn macos_allowed_routes(
    config: &ParsedUserspaceConfig,
    interface: &str,
    has_ipv6_address: bool,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();
    for allowed in &config.allowed_ips {
        match allowed.as_str() {
            "0.0.0.0/0" => {
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
fn get_macos_default_gateway(is_ipv6: bool) -> anyhow::Result<Option<String>> {
    let mut args = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push("default");

    let output = Command::new("route")
        .args(args)
        .output()
        .context("failed to run route -n get default")?;
    if !output.status.success() {
        if is_ipv6 {
            return Ok(None);
        }
        anyhow::bail!("route -n get default failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("gateway:") {
            return Ok(Some(value.trim().to_string()));
        }
    }
    if is_ipv6 {
        Ok(None)
    } else {
        anyhow::bail!("default gateway not found")
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

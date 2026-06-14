#[cfg(not(unix))]
pub fn maybe_run_from_env() -> bool {
    false
}

#[cfg(unix)]
use base64::Engine;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "macos")]
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(all(unix, target_os = "linux"))]
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Output};
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
use tracing::{debug, info, warn};

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
const MTU_OVERRIDE_ENV: &str = "TUNMUX_GOTATUN_MTU_OVERRIDE";

#[cfg(unix)]
fn gotatun_pid_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.pid"))
}

#[cfg(unix)]
fn gotatun_name_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.name"))
}

#[cfg(unix)]
fn gotatun_cleanup_status_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.cleanup"))
}

#[cfg(unix)]
fn gotatun_log_path(interface: &str) -> PathBuf {
    // Shared with the privileged service (which clears and tails this file), so
    // both derive it from the same place. macOS: ~/Library/Logs/tunmux-<iface>.log;
    // Linux: /var/log/tunmux/<iface>.log.
    crate::config::gotatun_helper_log_path(interface)
}

#[cfg(unix)]
struct RunningDevice {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    interface_name: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    control_interface_name: String,
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
    /// Live routing state. Mutated by the network-change reconciler while the
    /// tunnel is up and read by teardown, hence the interior mutability.
    routing: std::sync::Mutex<MacosRoutingState>,
    /// Live DNS state. Like `routing`, the reconciler keeps this in sync with
    /// the active LAN while the tunnel is up and teardown reads it to restore.
    dns: std::sync::Mutex<MacosDnsState>,
    /// Immutable inputs the reconciler replays on every network change.
    reconcile: MacosReconcileInputs,
}

/// Routing state the reconciler keeps in sync with the live network.
#[cfg(target_os = "macos")]
struct MacosRoutingState {
    /// Routes this tunnel currently owns; the source of truth for teardown.
    routes_added: Vec<MacosRoute>,
    /// Last observed network environment. A change drives reconciliation.
    fingerprint: MacosNetworkFingerprint,
}

/// DNS state the reconciler keeps in sync with the active LAN.
#[cfg(target_os = "macos")]
struct MacosDnsState {
    /// Services we currently own, each carrying the original config to restore
    /// at teardown. Mutated as the reconciler takes/releases ownership.
    services: Vec<MacosDnsServiceState>,
    /// Last observed DNS-relevant environment. A change drives reconciliation.
    fingerprint: MacosDnsFingerprint,
}

/// Inputs captured at connect that the reconciler needs to recompute routing.
#[cfg(target_os = "macos")]
struct MacosReconcileInputs {
    interface: String,
    endpoint: IpAddr,
    endpoint_is_ipv6: bool,
    /// Whether the endpoint must be pinned out of the tunnel via the physical
    /// gateway. Only true when AllowedIPs would otherwise capture it (e.g. a
    /// full tunnel); split tunnels reach the endpoint over the default route,
    /// so an unpinned endpoint roams to a new network with no stale route.
    endpoint_needs_pin: bool,
    allowed_ips: Vec<String>,
    dns_servers: Vec<String>,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
}

/// A snapshot of the host network environment relevant to tunnel routing.
#[cfg(target_os = "macos")]
#[derive(Clone, Default, PartialEq)]
struct MacosNetworkFingerprint {
    /// Directly-connected subnets of physical interfaces (the LANs we must not
    /// hijack), sorted+deduped for stable comparison.
    local_subnets: Vec<(IpAddr, u8)>,
    /// Default gateway for the endpoint's address family (for the endpoint pin).
    endpoint_gateway: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, PartialEq)]
struct MacosRoute {
    is_ipv6: bool,
    destination: String,
    interface: Option<String>,
    gateway: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct MacosDnsServiceState {
    service: String,
    dns_servers: Option<Vec<String>>,
    search_domains: Option<Vec<String>>,
}

/// A snapshot of the host DNS-relevant environment. Equality drives the DNS
/// reconciler the same way `MacosNetworkFingerprint` drives the route one.
#[cfg(target_os = "macos")]
#[derive(Clone, Default, PartialEq)]
struct MacosDnsFingerprint {
    /// The service that currently owns global resolution (the primary service
    /// name), or `None` if it can't be determined.
    primary_service: Option<String>,
    /// All current service names, sorted+deduped — detects appear/disappear.
    services: Vec<String>,
    /// Per-service DNS as currently observed on the system, sorted by service.
    /// Detects DHCP clobber (our DNS silently replaced) without trusting our
    /// own cached view. `None` == "no DNS set" (networksetup "Empty"). Server
    /// lists are left in the order `networksetup` returns them (order is
    /// significant to macOS) so equality is stable across ticks.
    observed: Vec<(String, Option<Vec<String>>)>,
}

/// Which network services should carry the tunnel's DNS. `AllServices` matches
/// the historical connect-time behavior (now applied dynamically); `PrimaryOnly`
/// is the true analogue of the route LAN-exclusion — only the service that owns
/// global resolution gets tunnel DNS, so non-primary LANs keep their own.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsPolicy {
    #[allow(dead_code)]
    AllServices,
    PrimaryOnly,
}

/// Active DNS targeting policy. Switching this constant is the only change
/// needed to move between the phases described in `transparent_dns.md`.
#[cfg(target_os = "macos")]
const DNS_POLICY: DnsPolicy = DnsPolicy::PrimaryOnly;

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ParsedUserspaceConfig {
    private_key: [u8; 32],
    addresses: Vec<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dns_servers: Vec<String>,
    mtu: Option<u16>,
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

    // Logging is initialized to a per-interface file inside the daemonized child (see
    // daemonize_and_run); not here, because the helper detaches from its parent's stdio.

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
    let stdout = File::options()
        .write(true)
        .open("/dev/stdout")
        .context("failed to open /dev/stdout for helper logging")?;
    let stderr = File::options()
        .write(true)
        .open("/dev/stderr")
        .context("failed to open /dev/stderr for helper logging")?;
    let daemonize = Daemonize::new()
        .working_directory("/tmp")
        .stdout(stdout)
        .stderr(stderr);

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

            // Log to a per-interface file rather than inherited stdio. This stops the helper's
            // output from leaking into whichever terminal the privileged service was started in,
            // and lets the service tail this file to stream setup/teardown logs back to the
            // caller. Synchronous writer so the service reads complete lines without a flush race.
            // Ensure the runtime dir exists first (it is otherwise created later by start_device).
            let _ = std::fs::create_dir_all(SOCK_DIR);
            // Ensure the log's parent dir exists (on macOS this is ~/Library/Logs,
            // which normally exists; create_dir_all is cheap insurance).
            let log_path = gotatun_log_path(interface);
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = crate::logging::init_file_sync(&log_path.to_string_lossy(), false);

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

            let pid_path = gotatun_pid_path(interface);
            if let Err(error) = write_runtime_file(&pid_path, &std::process::id().to_string()) {
                cleanup_network(&running).ok();
                rt.block_on(async {
                    running.device.stop().await;
                });
                let _ = std::fs::remove_file(&running.control_socket_path);
                let _ = std::fs::remove_file(gotatun_name_path(interface));
                let _ = signal_parent(false);
                return Err(error.context("failed to write userspace helper pid file"));
            }

            if let Err(error) = signal_parent(true) {
                cleanup_network(&running).ok();
                rt.block_on(async {
                    running.device.stop().await;
                });
                let _ = std::fs::remove_file(&running.control_socket_path);
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(gotatun_name_path(interface));
                return Err(error).context("failed to notify parent about helper startup");
            }
            debug!(
                interface = running.control_interface_name,
                actual_interface = running.interface_name,
                pid = std::process::id(),
                "userspace_helper_ready"
            );
            let shutdown_started = std::time::Instant::now();
            let wait_result = rt.block_on(wait_for_shutdown(&running));
            debug!(
                interface = running.control_interface_name,
                elapsed_ms = shutdown_started.elapsed().as_millis(),
                result = ?wait_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_shutdown_triggered"
            );

            let cleanup_started = std::time::Instant::now();
            let cleanup_result = cleanup_network(&running);
            debug!(
                interface = running.control_interface_name,
                elapsed_ms = cleanup_started.elapsed().as_millis(),
                result = ?cleanup_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_network_cleanup_complete"
            );

            let control_socket_path = running.control_socket_path.clone();
            let stop_started = std::time::Instant::now();
            let stop_result = rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), running.device.stop())
                    .await
                    .map_err(|_| anyhow::anyhow!("gotatun device stop timed out after 5 seconds"))
            });
            debug!(
                interface,
                elapsed_ms = stop_started.elapsed().as_millis(),
                result = ?stop_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_device_stop_complete"
            );

            let mut errors = Vec::new();
            if let Err(error) = wait_result {
                errors.push(format!("shutdown wait failed: {error}"));
            }
            if let Err(error) = cleanup_result {
                errors.push(format!("network cleanup failed: {error}"));
            }
            if let Err(error) = stop_result {
                // Exiting the helper closes the tunnel fd even if gotatun's graceful
                // stop future stalls. The privileged caller verifies utun removal.
                warn!(
                    interface,
                    error = %error,
                    "userspace_helper_device_stop_forced_by_process_exit"
                );
            }
            let final_result = finish_cleanup(errors);

            let status = match &final_result {
                Ok(()) => "ok\n".to_string(),
                Err(error) => format!("error: {error}\n"),
            };
            write_runtime_file_atomic(&gotatun_cleanup_status_path(interface), &status)?;
            let _ = std::fs::remove_file(&control_socket_path);
            let _ = std::fs::remove_file(&pid_path);
            let _ = std::fs::remove_file(gotatun_name_path(interface));

            final_result?;
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
    write_runtime_file(&gotatun_name_path(interface), &interface_name)
        .context("failed to write userspace helper interface name")?;
    Ok(RunningDevice {
        interface_name,
        control_interface_name: interface.to_string(),
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
    #[cfg(target_os = "macos")]
    let diag_enabled = true;
    #[cfg(target_os = "macos")]
    let mut next_diag_at = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    let mut last_transfer: Option<(u64, u64)> = None;

    #[cfg(target_os = "macos")]
    info!(
        interface = running.control_interface_name,
        "userspace_helper_dataplane_probe_enabled"
    );

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                debug!(interface = running.control_interface_name, trigger = "sigint", "userspace_helper_shutdown_requested");
                break;
            },
            _ = sigterm.recv() => {
                debug!(interface = running.control_interface_name, trigger = "sigterm", "userspace_helper_shutdown_requested");
                break;
            },
            _ = ticker.tick() => {
                if !running.control_socket_path.exists() {
                    debug!(interface = running.control_interface_name, trigger = "control_socket_removed", "userspace_helper_shutdown_requested");
                    break;
                }

                #[cfg(target_os = "linux")]
                {
                    let iface_path = Path::new("/sys/class/net").join(&running.interface_name);
                    if !iface_path.exists() {
                        break;
                    }
                }

                #[cfg(target_os = "macos")]
                {
                    // Adapt routing to network changes (roam, suspend/resume,
                    // link up/down) live, without requiring a reconnect.
                    if let CleanupState::Macos(state) = &running.cleanup {
                        macos_reconcile_routes(state);
                        macos_reconcile_dns(state);
                    }

                    if diag_enabled && std::time::Instant::now() >= next_diag_at {
                        next_diag_at = std::time::Instant::now() + Duration::from_secs(5);
                        log_macos_dataplane_probe(
                            &running.control_interface_name,
                            &mut last_transfer,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
async fn log_macos_dataplane_probe(interface: &str, last_transfer: &mut Option<(u64, u64)>) {
    let ipv4_probe_sent = send_udp_probe(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)));
    let ipv6_probe_sent = send_udp_probe(SocketAddr::from((
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        53,
    )));

    match read_wg_transfer_bytes(interface).await {
        Ok(Some((rx_bytes, tx_bytes))) => {
            let (delta_rx_bytes, delta_tx_bytes) = last_transfer
                .map(|(prev_rx, prev_tx)| {
                    (
                        rx_bytes.saturating_sub(prev_rx),
                        tx_bytes.saturating_sub(prev_tx),
                    )
                })
                .unwrap_or((0, 0));
            *last_transfer = Some((rx_bytes, tx_bytes));
            info!(
                interface,
                ipv4_probe_sent,
                ipv6_probe_sent,
                rx_bytes,
                tx_bytes,
                delta_rx_bytes,
                delta_tx_bytes,
                "userspace_helper_dataplane_probe"
            );
        }
        Ok(None) => {
            info!(
                interface,
                ipv4_probe_sent, ipv6_probe_sent, "userspace_helper_dataplane_probe_no_transfer"
            );
        }
        Err(error) => {
            warn!(
                interface,
                ipv4_probe_sent,
                ipv6_probe_sent,
                error = %error,
                "userspace_helper_dataplane_probe_failed"
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn send_udp_probe(target: SocketAddr) -> bool {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return false;
    };
    socket.send_to(&[0], target).is_ok()
}

#[cfg(target_os = "macos")]
async fn read_wg_transfer_bytes(interface: &str) -> anyhow::Result<Option<(u64, u64)>> {
    // `wg show <iface> transfer` connects to gotatun's in-process UAPI socket, which can only
    // be serviced by the async UAPI task running on this same runtime. Running the command
    // inline would block the runtime thread and self-deadlock (the runtime can no longer poll
    // the task that `wg` is waiting on). Run it on a blocking thread, bounded by a timeout, so
    // the runtime stays free to answer the UAPI request and a stuck `wg` can never wedge us.
    let owned_interface = interface.to_string();
    let output = match tokio::time::timeout(
        Duration::from_secs(4),
        tokio::task::spawn_blocking(move || {
            Command::new("wg")
                .args(["show", &owned_interface, "transfer"])
                .output()
        }),
    )
    .await
    {
        Ok(join_result) => join_result
            .context("wg show transfer task panicked")?
            .context("failed to run wg show transfer")?,
        Err(_) => anyhow::bail!("wg show {} transfer timed out", interface),
    };
    if !output.status.success() {
        anyhow::bail!("wg show {} transfer failed", interface);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed_any = false;
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let Ok(rx) = fields[1].parse::<u64>() else {
            continue;
        };
        let Ok(tx) = fields[2].parse::<u64>() else {
            continue;
        };
        parsed_any = true;
        rx_total = rx_total.saturating_add(rx);
        tx_total = tx_total.saturating_add(tx);
    }

    if parsed_any {
        Ok(Some((rx_total, tx_total)))
    } else {
        Ok(None)
    }
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
    let mut config = parse_wg_quick_config(&text)?;
    if let Some(value) = std::env::var_os(MTU_OVERRIDE_ENV) {
        let value = value
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", MTU_OVERRIDE_ENV))?;
        apply_mtu_override(&mut config, value)?;
    }
    Ok(Some(config))
}

#[cfg(unix)]
fn apply_mtu_override(config: &mut ParsedUserspaceConfig, value: &str) -> anyhow::Result<()> {
    config.mtu = Some(crate::wireguard::config::parse_mtu(value)?);
    Ok(())
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
    let mut mtu = None;
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
                "MTU" => mtu = Some(crate::wireguard::config::parse_mtu(value)?),
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
        mtu,
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

#[cfg(all(test, unix))]
mod userspace_config_tests {
    use super::*;

    const CONFIG: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";

    #[test]
    fn userspace_config_parses_mtu() {
        let parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        assert_eq!(parsed.mtu, Some(1280));
    }

    #[test]
    fn userspace_config_rejects_invalid_mtu() {
        let config = CONFIG.replace("MTU = 1280", "MTU = 575");
        assert!(parse_wg_quick_config(&config).is_err());
    }

    #[test]
    fn explicit_mtu_overrides_config_mtu() {
        let mut parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        apply_mtu_override(&mut parsed, "1420").expect("apply override");
        assert_eq!(parsed.mtu, Some(1420));
    }
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
fn cleanup_network(running: &RunningDevice) -> anyhow::Result<()> {
    match &running.cleanup {
        CleanupState::None => Ok(()),
        #[cfg(target_os = "linux")]
        CleanupState::Linux(state) => cleanup_network_linux(state),
        #[cfg(target_os = "macos")]
        CleanupState::Macos(state) => cleanup_network_macos(state),
    }
}

#[cfg(unix)]
fn write_runtime_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_runtime_file_atomic(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    write_runtime_file(&temp_path, contents)?;
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
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

#[cfg(unix)]
fn run_command_capture_output(name: &str, args: &[&str]) -> anyhow::Result<Output> {
    debug!(command = %format_command_for_log(name, args), "userspace_helper_command");
    Command::new(name)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))
}

#[cfg(unix)]
fn format_command_for_log(name: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return name.to_string();
    }
    format!("{} {}", name, args.join(" "))
}

#[cfg(target_os = "linux")]
fn configure_network_linux(
    interface: &str,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<LinuxCleanupState> {
    let mut routes_added = Vec::new();
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));

    if let Some(mtu) = config.mtu {
        let mtu = mtu.to_string();
        run_command("ip", &["link", "set", "dev", interface, "mtu", &mtu])?;
    }
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
fn cleanup_network_linux(state: &LinuxCleanupState) -> anyhow::Result<()> {
    debug!(
        routes = state.routes_added.len(),
        restore_resolv_conf = state.original_resolv_conf.is_some(),
        "userspace_helper_network_cleanup_begin"
    );
    let mut errors = Vec::new();
    for route in state.routes_added.iter().rev() {
        if let Err(error) = del_linux_route(route) {
            errors.push(error.to_string());
        }
    }
    if let Some(original) = &state.original_resolv_conf {
        if let Err(error) = std::fs::write("/etc/resolv.conf", original) {
            errors.push(format!("restore /etc/resolv.conf failed: {error}"));
        }
    }
    finish_cleanup(errors)
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
    let has_ipv4_address = config
        .addresses
        .iter()
        .any(|address| !address.contains(':'));
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));
    let endpoint_is_ipv6 = matches!(config.endpoint.ip(), IpAddr::V6(_));
    let endpoint_family_supported = !endpoint_is_ipv6 || has_ipv6_address;
    // Decision (1): only pin the endpoint out of the tunnel when AllowedIPs
    // would otherwise capture it (full tunnel). A split tunnel reaches the
    // endpoint over the default route, so leaving it unpinned means roaming to
    // a new LAN "just works" with no stale gateway route to fix up.
    let endpoint_needs_pin = endpoint_family_supported
        && macos_allowed_ips_cover_endpoint(&config.allowed_ips, config.endpoint.ip());

    let inputs = MacosReconcileInputs {
        interface: interface.to_string(),
        endpoint: config.endpoint.ip(),
        endpoint_is_ipv6,
        endpoint_needs_pin,
        allowed_ips: config.allowed_ips.clone(),
        dns_servers: config.dns_servers.clone(),
        has_ipv4_address,
        has_ipv6_address,
    };

    let mut routes_added: Vec<MacosRoute> = Vec::new();
    let mut dns_services: Vec<MacosDnsServiceState> = Vec::new();
    let mut fingerprint = MacosNetworkFingerprint::default();
    let mut dns_fingerprint = MacosDnsFingerprint::default();

    let setup_result = (|| -> anyhow::Result<()> {
        if let Some(mtu) = config.mtu {
            let mtu = mtu.to_string();
            run_command("ifconfig", &[interface, "mtu", &mtu])?;
        }
        for address in &config.addresses {
            let (ip, prefix) = parse_cidr(address)?;
            match ip {
                IpAddr::V4(addr) => {
                    let ip_string = addr.to_string();
                    run_command(
                        "ifconfig",
                        &[interface, "inet", address, ip_string.as_str(), "alias"],
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
        if let Err(error) = run_command("ifconfig", &[interface, "-rxcsum", "-txcsum"]) {
            warn!(
                interface,
                error = %error,
                "userspace_helper_disable_checksum_offload_failed"
            );
        }

        // Compute the initial desired routes the same way the reconciler will,
        // so the LAN-exclusion is applied from the very first packet.
        fingerprint = macos_current_fingerprint(&inputs);
        for route in macos_desired_routes(&inputs, &fingerprint) {
            add_macos_route(&route)?;
            routes_added.push(route);
        }
        log_macos_routing_overview("connect", &inputs, &routes_added, &fingerprint);

        // Apply DNS the same way the reconciler will, then seed the DNS
        // fingerprint so the first reconcile tick is a no-op.
        dns_fingerprint = configure_macos_dns(config, &mut dns_services)?;
        Ok(())
    })();

    if let Err(setup_error) = setup_result {
        let mut errors = Vec::new();
        for route in routes_added.iter().rev() {
            if let Err(error) = del_macos_route(route) {
                errors.push(error.to_string());
            }
        }
        for service in dns_services.iter().rev() {
            if let Err(error) = restore_macos_dns_service(service) {
                errors.push(format!(
                    "restore DNS for {:?} failed: {error}",
                    service.service
                ));
            }
        }
        return if errors.is_empty() {
            Err(setup_error)
        } else {
            Err(anyhow::anyhow!(
                "setup failed: {}; rollback failed: {}",
                setup_error,
                errors.join("; ")
            ))
        };
    }

    Ok(MacosCleanupState {
        routing: std::sync::Mutex::new(MacosRoutingState {
            routes_added,
            fingerprint,
        }),
        dns: std::sync::Mutex::new(MacosDnsState {
            services: dns_services,
            fingerprint: dns_fingerprint,
        }),
        reconcile: inputs,
    })
}

#[cfg(target_os = "macos")]
fn cleanup_network_macos(state: &MacosCleanupState) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Restore routes then DNS, taking the `routing` and `dns` locks
    // independently (never both at once) to avoid any ordering hazard with the
    // reconciler.
    {
        let routing = state
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug!(
            routes = routing.routes_added.len(),
            "userspace_helper_network_cleanup_routes"
        );
        for route in routing.routes_added.iter().rev() {
            if let Err(error) = del_macos_route(route) {
                errors.push(error.to_string());
            }
        }
    }
    {
        let dns = state
            .dns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug!(
            dns_services = dns.services.len(),
            "userspace_helper_network_cleanup_dns"
        );
        for service in dns.services.iter().rev() {
            if let Err(error) = restore_macos_dns_service(service) {
                errors.push(format!(
                    "restore DNS for {:?} failed: {error}",
                    service.service
                ));
            }
        }
    }
    finish_cleanup(errors)
}

#[cfg(unix)]
fn finish_cleanup(errors: Vec<String>) -> anyhow::Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
    }
}

/// Apply the tunnel's DNS to the services selected by `DNS_POLICY`, saving each
/// touched service's original config into `saved` for later restore. Returns the
/// DNS fingerprint observed *after* applying, so the reconciler's first tick is a
/// no-op. Shares its per-service capture+apply path with the reconciler.
#[cfg(target_os = "macos")]
fn configure_macos_dns(
    config: &ParsedUserspaceConfig,
    saved: &mut Vec<MacosDnsServiceState>,
) -> anyhow::Result<MacosDnsFingerprint> {
    if config.dns_servers.is_empty() {
        return Ok(MacosDnsFingerprint::default());
    }

    let fingerprint = macos_current_dns_fingerprint();
    for service in dns_target_services(DNS_POLICY, &fingerprint) {
        if let Some(state) = capture_macos_dns_service(&service, &config.dns_servers)? {
            saved.push(state);
        }
        set_macos_dns_servers(&service, &config.dns_servers)?;
        set_macos_search_domains_empty(&service)?;
    }

    // Re-snapshot post-apply: the stored fingerprint must reflect the DNS we
    // just wrote so the first reconcile tick detects no change.
    Ok(macos_current_dns_fingerprint())
}

#[cfg(target_os = "macos")]
fn restore_macos_dns_service(state: &MacosDnsServiceState) -> anyhow::Result<()> {
    match &state.dns_servers {
        Some(servers) => set_macos_dns_servers(&state.service, servers)?,
        None => set_macos_dns_servers_empty(&state.service)?,
    }

    match &state.search_domains {
        Some(domains) => set_macos_search_domains(&state.service, domains)?,
        None => set_macos_search_domains_empty(&state.service)?,
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
        args.push("-interface".into());
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // Split routes (dev-bound, no explicit gateway) can linger on stale utun
    // devices; clear any existing entry first so this tunnel owns the route.
    if route.interface.is_some() && route.gateway.is_none() {
        let mut delete_args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
        delete_args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
        delete_args.push(route.destination.clone());
        let delete_refs: Vec<&str> = delete_args.iter().map(String::as_str).collect();
        let _ = run_command("route", &delete_refs);
    }

    run_command_with_exists_ok("route", &refs)
}

#[cfg(target_os = "macos")]
fn del_macos_route(route: &MacosRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(macos_route_target_kind(route).into());
    args.push(route.destination.clone());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command_capture_output("route", &refs)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("not in table") || stdout.contains("not in table") {
        return Ok(());
    }
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    anyhow::bail!("route {} failed: {}", refs.join(" "), detail)
}

#[cfg(target_os = "macos")]
fn macos_route_target_kind(route: &MacosRoute) -> &'static str {
    let host_prefix = if route.is_ipv6 { "/128" } else { "/32" };
    if route.gateway.is_some()
        || route.destination.ends_with(host_prefix)
        || !route.destination.contains('/')
    {
        "-host"
    } else {
        "-net"
    }
}

#[cfg(target_os = "macos")]
fn macos_allowed_routes(
    allowed_ips: &[String],
    interface: &str,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();
    for allowed in allowed_ips {
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

/// The routes this tunnel wants installed for the given network environment:
/// the (optional) endpoint pin plus the AllowedIPs routes, minus any subnet
/// we are currently directly attached to (so we never hijack our own LAN).
#[cfg(target_os = "macos")]
fn macos_desired_routes(
    inputs: &MacosReconcileInputs,
    fingerprint: &MacosNetworkFingerprint,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();

    if inputs.endpoint_needs_pin {
        if let Some(gateway) = &fingerprint.endpoint_gateway {
            routes.push(MacosRoute {
                is_ipv6: inputs.endpoint_is_ipv6,
                destination: inputs.endpoint.to_string(),
                interface: None,
                gateway: Some(gateway.clone()),
            });
        }
    }

    for route in macos_allowed_routes(
        &inputs.allowed_ips,
        &inputs.interface,
        inputs.has_ipv4_address,
        inputs.has_ipv6_address,
    ) {
        if let Some((subnet_ip, subnet_prefix)) =
            macos_route_excluded_by_local_subnet(&route, &fingerprint.local_subnets)
        {
            debug!(
                destination = %route.destination,
                local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
                "userspace_helper_route_excluded_local_lan"
            );
            continue;
        }
        routes.push(route);
    }

    routes
}

/// Returns the connected subnet that makes `route` local (so it must stay off
/// the tunnel), or `None` if the route should be installed normally.
#[cfg(target_os = "macos")]
fn macos_route_excluded_by_local_subnet(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
) -> Option<(IpAddr, u8)> {
    // Only tunnel-bound routes (interface, no gateway) can hijack a LAN.
    if route.interface.is_none() || route.gateway.is_some() {
        return None;
    }
    let (ip, prefix) = parse_cidr(&route.destination).ok()?;
    let destination = (macos_network_base(ip, prefix), prefix);
    local_subnets
        .iter()
        .find(|local| macos_subnet_contains(local, &destination))
        .copied()
}

/// True when `route` is equal to, or fully inside, the connected subnet `local`.
#[cfg(target_os = "macos")]
fn macos_subnet_contains(local: &(IpAddr, u8), route: &(IpAddr, u8)) -> bool {
    if route.1 < local.1 {
        return false;
    }
    match (local.0, route.0) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            macos_network_base(route.0, local.1) == macos_network_base(local.0, local.1)
        }
        _ => false,
    }
}

/// Mask `ip` down to its network base for the given prefix length.
#[cfg(target_os = "macos")]
fn macos_network_base(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = match prefix {
                0 => 0,
                p if p >= 32 => bits,
                p => bits & (u32::MAX << (32 - p)),
            };
            IpAddr::V4(Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = match prefix {
                0 => 0,
                p if p >= 128 => bits,
                p => bits & (u128::MAX << (128 - p)),
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

/// True when any AllowedIPs entry would route the endpoint into the tunnel.
#[cfg(target_os = "macos")]
fn macos_allowed_ips_cover_endpoint(allowed_ips: &[String], endpoint: IpAddr) -> bool {
    allowed_ips.iter().any(|allowed| {
        let Ok((net, prefix)) = parse_cidr(allowed) else {
            return false;
        };
        match (net, endpoint) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                macos_network_base(endpoint, prefix) == macos_network_base(net, prefix)
            }
            _ => false,
        }
    })
}

/// Snapshot the current network environment that drives tunnel routing.
#[cfg(target_os = "macos")]
fn macos_current_fingerprint(inputs: &MacosReconcileInputs) -> MacosNetworkFingerprint {
    let local_subnets = macos_local_connected_subnets(&inputs.interface);
    // Only the endpoint pin needs the gateway; skip the lookup otherwise so we
    // do not run `route get default` on every (no-op) reconcile tick.
    let endpoint_gateway = if inputs.endpoint_needs_pin {
        get_macos_default_gateway(inputs.endpoint_is_ipv6).unwrap_or(None)
    } else {
        None
    };
    MacosNetworkFingerprint {
        local_subnets,
        endpoint_gateway,
    }
}

/// Re-apply routing when the host network changed (roam, suspend/resume, link
/// up/down). Cheap and silent when nothing changed; expressive when it acts.
#[cfg(target_os = "macos")]
fn macos_reconcile_routes(state: &MacosCleanupState) {
    let inputs = &state.reconcile;
    let fingerprint = macos_current_fingerprint(inputs);

    let mut routing = state
        .routing
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if fingerprint == routing.fingerprint {
        return;
    }

    let previous = routing.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_gateway = ?previous.endpoint_gateway,
        new_gateway = ?fingerprint.endpoint_gateway,
        old_local_subnets = %format_subnets(&previous.local_subnets),
        new_local_subnets = %format_subnets(&fingerprint.local_subnets),
        "userspace_helper_network_change_detected"
    );

    let desired = macos_desired_routes(inputs, &fingerprint);
    let current = routing.routes_added.clone();
    let mut installed: Vec<MacosRoute> = Vec::new();
    let (mut added, mut removed, mut errors) = (0usize, 0usize, 0usize);

    // Remove routes that are no longer desired (e.g. a LAN we just left, or a
    // stale endpoint pin via the previous gateway).
    for route in &current {
        if !desired.contains(route) {
            match del_macos_route(route) {
                Ok(()) => removed += 1,
                Err(error) => {
                    errors += 1;
                    warn!(
                        destination = %route.destination,
                        error = %error,
                        "userspace_helper_reconcile_route_delete_failed"
                    );
                }
            }
        }
    }

    // Add newly desired routes; keep the ones already present.
    for route in desired {
        if current.contains(&route) {
            installed.push(route);
            continue;
        }
        match add_macos_route(&route) {
            Ok(_) => {
                added += 1;
                installed.push(route);
            }
            Err(error) => {
                errors += 1;
                warn!(
                    destination = %route.destination,
                    error = %error,
                    "userspace_helper_reconcile_route_add_failed"
                );
            }
        }
    }

    routing.routes_added = installed;
    routing.fingerprint = fingerprint.clone();

    info!(
        interface = inputs.interface,
        routes_added = added,
        routes_removed = removed,
        errors,
        "userspace_helper_reconcile_applied"
    );
    log_macos_routing_overview("reconcile", inputs, &routing.routes_added, &fingerprint);
}

/// The services that should carry tunnel DNS under `policy`. `PrimaryOnly`
/// targets just the service that owns global resolution; if that can't be
/// determined (or isn't a current service) it falls back to `AllServices` so we
/// never leave the primary resolver leaked (`transparent_dns.md` §6.3).
#[cfg(target_os = "macos")]
fn dns_target_services(policy: DnsPolicy, fp: &MacosDnsFingerprint) -> Vec<String> {
    match policy {
        DnsPolicy::AllServices => fp.services.clone(),
        DnsPolicy::PrimaryOnly => match &fp.primary_service {
            Some(primary) if fp.services.iter().any(|s| s == primary) => vec![primary.clone()],
            _ => fp.services.clone(),
        },
    }
}

/// The pure decision behind a DNS reconcile: given the tunnel's DNS, the freshly
/// observed environment, the services we currently own, and the services we want
/// to own, decide what to do. Kept free of I/O so it is unit-testable.
#[cfg(target_os = "macos")]
#[derive(Debug, Default, PartialEq)]
struct DnsActions {
    /// Targets we don't yet own and whose live DNS differs from the tunnel's:
    /// capture their original config, then assert tunnel DNS.
    capture: Vec<String>,
    /// Owned services no longer targeted but still present: restore originals.
    restore: Vec<String>,
    /// Owned services that have vanished: drop without restoring (gone already).
    drop: Vec<String>,
    /// Targets whose observed DNS has drifted from the tunnel's: (re-)assert.
    apply: Vec<String>,
}

#[cfg(target_os = "macos")]
fn plan_dns_actions(
    tunnel_dns: &[String],
    fp: &MacosDnsFingerprint,
    owned: &[String],
    targets: &[String],
) -> DnsActions {
    let shows_tunnel = |svc: &str| -> bool {
        fp.observed
            .iter()
            .find(|(s, _)| s == svc)
            .and_then(|(_, d)| d.as_deref())
            == Some(tunnel_dns)
    };

    let mut actions = DnsActions::default();

    for svc in targets {
        let matches_tunnel = shows_tunnel(svc);
        // Capture an original only when we are about to overwrite a value that
        // isn't already the tunnel's — never record our own DNS as "original".
        if !owned.iter().any(|s| s == svc) && !matches_tunnel {
            actions.capture.push(svc.clone());
        }
        if !matches_tunnel {
            actions.apply.push(svc.clone());
        }
    }

    for svc in owned {
        if targets.iter().any(|s| s == svc) {
            continue;
        }
        if fp.services.iter().any(|s| s == svc) {
            actions.restore.push(svc.clone());
        } else {
            actions.drop.push(svc.clone());
        }
    }

    actions
}

/// Snapshot the current DNS-relevant environment. Any sub-call that fails
/// degrades to empty/`None` rather than aborting the tick, mirroring
/// `macos_local_connected_subnets`.
#[cfg(target_os = "macos")]
fn macos_current_dns_fingerprint() -> MacosDnsFingerprint {
    let mut services = list_macos_network_services().unwrap_or_default();
    services.sort();
    services.dedup();

    let mut observed = Vec::with_capacity(services.len());
    for svc in &services {
        // None on error → treat as "unknown/unset"; never panic the tick.
        let dns = get_macos_dns_servers(svc).ok().flatten();
        observed.push((svc.clone(), dns));
    }

    MacosDnsFingerprint {
        primary_service: macos_primary_service(),
        services,
        observed,
    }
}

/// Read a service's current DNS + search domains and wrap them for later
/// restore. Returns `Ok(None)` when the service already shows the tunnel's DNS,
/// so we never capture our own values as "original" (`transparent_dns.md` §6.1).
#[cfg(target_os = "macos")]
fn capture_macos_dns_service(
    service: &str,
    tunnel_dns: &[String],
) -> anyhow::Result<Option<MacosDnsServiceState>> {
    let dns = get_macos_dns_servers(service)?;
    if dns.as_deref() == Some(tunnel_dns) {
        return Ok(None);
    }
    let search = get_macos_search_domains(service)?;
    Ok(Some(MacosDnsServiceState {
        service: service.to_string(),
        dns_servers: dns,
        search_domains: search,
    }))
}

/// Re-apply DNS when the host DNS environment changed (roam, DHCP renewal, a new
/// or vanished service, a primary-service change). Cheap and silent when nothing
/// changed; expressive when it acts. Mirrors `macos_reconcile_routes`.
#[cfg(target_os = "macos")]
fn macos_reconcile_dns(state: &MacosCleanupState) {
    let inputs = &state.reconcile;
    if inputs.dns_servers.is_empty() {
        return; // VPN promotes no DNS → nothing to own.
    }

    let fingerprint = macos_current_dns_fingerprint();

    let mut dns = state
        .dns
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if fingerprint == dns.fingerprint {
        return; // cheap identity check, same guard as routes.
    }

    let previous = dns.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_primary = ?previous.primary_service,
        new_primary = ?fingerprint.primary_service,
        old_services = previous.services.len(),
        new_services = fingerprint.services.len(),
        "userspace_helper_dns_change_detected"
    );

    let targets = dns_target_services(DNS_POLICY, &fingerprint);
    let owned: Vec<String> = dns.services.iter().map(|s| s.service.clone()).collect();
    let actions = plan_dns_actions(&inputs.dns_servers, &fingerprint, &owned, &targets);

    let (mut applied, mut captured, mut restored, mut dropped, mut errors) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    // (a) Capture originals for services we are about to own.
    for svc in &actions.capture {
        match capture_macos_dns_service(svc, &inputs.dns_servers) {
            Ok(Some(saved)) => {
                dns.services.push(saved);
                captured += 1;
            }
            Ok(None) => {} // already showing tunnel DNS; nothing to capture
            Err(_) => errors += 1,
        }
    }

    // (b) Release services we no longer target: restore the ones still present,
    // drop the ones whose host service has vanished.
    for svc in &actions.restore {
        let saved = dns.services.iter().find(|s| &s.service == svc).cloned();
        if let Some(saved) = saved {
            if restore_macos_dns_service(&saved).is_ok() {
                restored += 1;
            } else {
                errors += 1;
            }
        }
        dns.services.retain(|s| &s.service != svc);
    }
    for svc in &actions.drop {
        dropped += 1;
        dns.services.retain(|s| &s.service != svc);
    }

    // (c) (Re-)assert tunnel DNS on every target whose observed DNS has drifted.
    for svc in &actions.apply {
        if set_macos_dns_servers(svc, &inputs.dns_servers).is_ok()
            && set_macos_search_domains_empty(svc).is_ok()
        {
            applied += 1;
        } else {
            errors += 1;
        }
    }

    dns.fingerprint = fingerprint;
    info!(
        interface = inputs.interface,
        applied, captured, restored, dropped, errors, "userspace_helper_dns_reconcile_applied"
    );
}

/// The human-readable network service name that currently owns the default
/// route / global resolver, or `None`. `scutil` speaks BSD device names (en0)
/// and `networksetup` speaks service names ("Wi-Fi"); bridge them via the
/// service order, matching on device.
#[cfg(target_os = "macos")]
fn macos_primary_service() -> Option<String> {
    let primary_if = scutil_global_primary_interface()?;
    macos_service_name_for_device(&primary_if)
}

/// Ask `scutil` for the primary interface (BSD device, e.g. "en0").
#[cfg(target_os = "macos")]
fn scutil_global_primary_interface() -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(b"show State:/Network/Global/IPv4\n")
        .ok()?;
    // `wait_with_output` closes stdin first, so scutil sees EOF and exits.
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_scutil_primary_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `PrimaryInterface : en0` out of `scutil show State:/Network/Global/IPv4`.
#[cfg(target_os = "macos")]
fn parse_scutil_primary_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PrimaryInterface") {
            let value = rest.trim_start_matches([' ', ':']).trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Map a BSD device ("en0") to its `networksetup` service name ("Wi-Fi") via
/// `networksetup -listnetworkserviceorder`.
#[cfg(target_os = "macos")]
fn macos_service_name_for_device(device: &str) -> Option<String> {
    let output =
        run_command_capture_output("networksetup", &["-listnetworkserviceorder"]).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_service_name_for_device(&String::from_utf8_lossy(&output.stdout), device)
}

/// Parse `networksetup -listnetworkserviceorder` output, returning the service
/// name whose `(Hardware Port: …, Device: <device>)` line matches `device`.
/// Pseudo-services without a real device (e.g. VPNs) are skipped.
#[cfg(target_os = "macos")]
fn parse_service_name_for_device(text: &str, device: &str) -> Option<String> {
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(hw) = trimmed.strip_prefix("(Hardware Port:") {
            if parse_device_from_hw_line(hw).as_deref() == Some(device) {
                return current_name.clone();
            }
        } else if trimmed.starts_with('(') {
            // Service line: "(1) Wi-Fi" or "(*) Wi-Fi" (asterisk == disabled).
            if let Some((_, name)) = trimmed.split_once(')') {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract the BSD device from the tail of a `(Hardware Port: …, Device: enX)`
/// line (the part passed in is everything after "(Hardware Port:").
#[cfg(target_os = "macos")]
fn parse_device_from_hw_line(hw: &str) -> Option<String> {
    let idx = hw.find("Device:")?;
    let device = hw[idx + "Device:".len()..]
        .trim()
        .trim_end_matches(')')
        .trim();
    if device.is_empty() {
        None
    } else {
        Some(device.to_string())
    }
}

/// Emit a full route + DNS overview. Called once at connect and after every
/// reconcile action, so the log always shows the resulting tunnel state.
#[cfg(target_os = "macos")]
fn log_macos_routing_overview(
    reason: &str,
    inputs: &MacosReconcileInputs,
    routes: &[MacosRoute],
    fingerprint: &MacosNetworkFingerprint,
) {
    info!(
        reason,
        interface = inputs.interface,
        endpoint = %inputs.endpoint,
        endpoint_pinned = inputs.endpoint_needs_pin,
        endpoint_gateway = ?fingerprint.endpoint_gateway,
        local_subnets = %format_subnets(&fingerprint.local_subnets),
        tunnel_routes = %format_routes(routes),
        // The configured server list; live per-service DNS state is reported by
        // the DNS reconciler's own `userspace_helper_dns_*` events.
        dns_servers = %format_list(&inputs.dns_servers),
        dns_reconciled = true,
        "userspace_helper_routing_overview"
    );
}

/// Directly-connected subnets of up, non-loopback, non-point-to-point
/// interfaces (the physical LANs), excluding the tunnel itself.
#[cfg(target_os = "macos")]
fn macos_local_connected_subnets(tunnel_interface: &str) -> Vec<(IpAddr, u8)> {
    // Call ifconfig directly (not run_command_capture_output) to avoid emitting
    // a debug command log line on every reconcile tick.
    let output = match Command::new("ifconfig").output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut subnets = Vec::new();
    let mut interface_qualifies = false;
    for line in text.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Interface header: "en0: flags=8863<UP,BROADCAST,...> mtu 1500".
            interface_qualifies = false;
            if let Some((name, rest)) = line.split_once(':') {
                interface_qualifies = name.trim() != tunnel_interface
                    && rest.contains("UP")
                    && !rest.contains("LOOPBACK")
                    && !rest.contains("POINTOPOINT");
            }
            continue;
        }
        if !interface_qualifies {
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(subnet) = parse_ifconfig_inet4_subnet(rest) {
                subnets.push(subnet);
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(subnet) = parse_ifconfig_inet6_subnet(rest) {
                subnets.push(subnet);
            }
        }
    }
    subnets.sort();
    subnets.dedup();
    subnets
}

#[cfg(target_os = "macos")]
fn parse_ifconfig_inet4_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ip: Ipv4Addr = fields.first()?.parse().ok()?;
    let mask_index = fields.iter().position(|field| *field == "netmask")?;
    let prefix = parse_macos_hex_netmask(fields.get(mask_index + 1)?)?;
    Some((macos_network_base(IpAddr::V4(ip), prefix), prefix))
}

#[cfg(target_os = "macos")]
fn parse_ifconfig_inet6_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Strip any zone id, e.g. "fe80::1%en0".
    let address = fields.first()?.split('%').next()?;
    let ip: Ipv6Addr = address.parse().ok()?;
    // Skip link-local (fe80::/10) and loopback; they are not routable LANs.
    if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return None;
    }
    let prefix_index = fields.iter().position(|field| *field == "prefixlen")?;
    let prefix: u8 = fields.get(prefix_index + 1)?.parse().ok()?;
    Some((macos_network_base(IpAddr::V6(ip), prefix), prefix))
}

/// Convert a macOS hex netmask ("0xffffff00") to a prefix length.
#[cfg(target_os = "macos")]
fn parse_macos_hex_netmask(mask: &str) -> Option<u8> {
    let hex = mask
        .strip_prefix("0x")
        .or_else(|| mask.strip_prefix("0X"))?;
    Some(u32::from_str_radix(hex, 16).ok()?.count_ones() as u8)
}

#[cfg(target_os = "macos")]
fn format_subnets(subnets: &[(IpAddr, u8)]) -> String {
    if subnets.is_empty() {
        return "none".to_string();
    }
    subnets
        .iter()
        .map(|(ip, prefix)| format!("{ip}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(target_os = "macos")]
fn format_routes(routes: &[MacosRoute]) -> String {
    if routes.is_empty() {
        return "none".to_string();
    }
    routes
        .iter()
        .map(|route| match (&route.gateway, &route.interface) {
            (Some(gateway), _) => format!("{}->gw {}", route.destination, gateway),
            (None, Some(interface)) => format!("{}->{}", route.destination, interface),
            (None, None) => route.destination.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(target_os = "macos")]
fn format_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn subnet(value: &str) -> (IpAddr, u8) {
        let (ip, prefix) = parse_cidr(value).expect("valid cidr");
        (macos_network_base(ip, prefix), prefix)
    }

    #[test]
    fn macos_route_delete_uses_destination_kind_without_add_qualifiers() {
        let network = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&network), "-net");

        let endpoint = MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("55.56.57.1".to_string()),
        };
        assert_eq!(macos_route_target_kind(&endpoint), "-host");

        let host_cidr = MacosRoute {
            is_ipv6: true,
            destination: "2001:db8::1/128".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&host_cidr), "-host");
    }

    #[test]
    fn hex_netmask_converts_to_prefix() {
        assert_eq!(parse_macos_hex_netmask("0xffffff00"), Some(24));
        assert_eq!(parse_macos_hex_netmask("0xffff0000"), Some(16));
        assert_eq!(parse_macos_hex_netmask("0xffffffff"), Some(32));
        assert_eq!(parse_macos_hex_netmask("0x00000000"), Some(0));
        assert_eq!(parse_macos_hex_netmask("not-hex"), None);
    }

    #[test]
    fn endpoint_pinned_only_when_allowed_ips_cover_it() {
        let endpoint: IpAddr = "23.88.101.22".parse().unwrap();
        let split = vec!["100.64.0.0/24".to_string(), "55.56.57.0/24".to_string()];
        assert!(!macos_allowed_ips_cover_endpoint(&split, endpoint));
        let full = vec!["0.0.0.0/0".to_string()];
        assert!(macos_allowed_ips_cover_endpoint(&full, endpoint));
    }

    fn split_inputs() -> MacosReconcileInputs {
        MacosReconcileInputs {
            interface: "utun6".to_string(),
            endpoint: "23.88.101.22".parse().unwrap(),
            endpoint_is_ipv6: false,
            endpoint_needs_pin: false,
            allowed_ips: vec!["55.56.57.0/24".to_string(), "100.64.0.0/24".to_string()],
            dns_servers: vec!["100.64.1.1".to_string()],
            has_ipv4_address: true,
            has_ipv6_address: false,
        }
    }

    #[test]
    fn local_lan_is_excluded_but_returns_to_the_tunnel_on_a_different_lan() {
        let inputs = split_inputs();

        // Sitting in the home LAN: that subnet must NOT be routed into the tunnel.
        let home = MacosNetworkFingerprint {
            local_subnets: vec![subnet("55.56.57.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &home)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(!dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));

        // After roaming elsewhere, 55.56.57.0/24 is remote again and IS tunnelled.
        let elsewhere = MacosNetworkFingerprint {
            local_subnets: vec![subnet("10.20.30.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &elsewhere)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));
    }

    #[test]
    fn containment_matches_equal_and_more_specific_routes_only() {
        let local = subnet("55.56.57.0/24");

        let equal = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&equal, &[local]).is_some());

        let more_specific = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.128/25".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&more_specific, &[local]).is_some());

        // A broader supernet is not treated as local (we do not split routes).
        let broader = MacosRoute {
            is_ipv6: false,
            destination: "55.56.0.0/16".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&broader, &[local]).is_none());

        // Gatewayed (non-tunnel) routes are never excluded.
        let gatewayed = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: None,
            gateway: Some("10.0.0.1".to_string()),
        };
        assert!(macos_route_excluded_by_local_subnet(&gatewayed, &[local]).is_none());
    }

    // --- DNS reconciler ---

    fn dns_fp(
        primary: Option<&str>,
        observed: &[(&str, Option<&[&str]>)],
    ) -> MacosDnsFingerprint {
        let observed: Vec<(String, Option<Vec<String>>)> = observed
            .iter()
            .map(|(svc, dns)| {
                (
                    svc.to_string(),
                    dns.map(|servers| servers.iter().map(|s| s.to_string()).collect()),
                )
            })
            .collect();
        let mut services: Vec<String> = observed.iter().map(|(s, _)| s.clone()).collect();
        services.sort();
        services.dedup();
        MacosDnsFingerprint {
            primary_service: primary.map(str::to_string),
            services,
            observed,
        }
    }

    #[test]
    fn dns_target_services_honours_policy_and_falls_back() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[("Ethernet", Some(&["1.1.1.1"])), ("Wi-Fi", Some(&["1.1.1.1"]))],
        );

        // AllServices targets every service.
        assert_eq!(
            dns_target_services(DnsPolicy::AllServices, &fp),
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );

        // PrimaryOnly targets just the primary.
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &fp),
            vec!["Wi-Fi".to_string()]
        );

        // PrimaryOnly with no detectable primary falls back to all services.
        let no_primary = dns_fp(None, &[("Wi-Fi", None), ("Ethernet", None)]);
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &no_primary),
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );

        // PrimaryOnly whose primary isn't a current service also falls back.
        let stale_primary = dns_fp(Some("Bogus"), &[("Wi-Fi", None)]);
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &stale_primary),
            vec!["Wi-Fi".to_string()]
        );
    }

    fn tunnel() -> Vec<String> {
        vec!["100.64.0.1".to_string()]
    }

    #[test]
    fn plan_dns_new_primary_captures_and_restores_previous() {
        // Roamed Wi-Fi -> Ethernet under PrimaryOnly: own Wi-Fi, target Ethernet.
        let fp = dns_fp(
            Some("Ethernet"),
            &[
                ("Ethernet", Some(&["192.168.1.1"])), // native DHCP DNS
                ("Wi-Fi", Some(&["100.64.0.1"])),     // still has our tunnel DNS
            ],
        );
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Ethernet".to_string()]);
        assert_eq!(actions.apply, vec!["Ethernet".to_string()]);
        assert_eq!(actions.restore, vec!["Wi-Fi".to_string()]);
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_clobber_reapplies_without_recapturing() {
        // configd reverted our DNS on an owned, still-targeted service.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert!(actions.capture.is_empty()); // already owned → keep original
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_new_service_captured_under_all_services() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Wi-Fi", Some(&["100.64.0.1"])),  // owned, already tunnel
                ("Tether", Some(&["10.0.0.1"])),   // new service with native DNS
            ],
        );
        let targets = dns_target_services(DnsPolicy::AllServices, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Tether".to_string()]);
        assert_eq!(actions.apply, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_vanished_service_is_dropped_not_restored() {
        // We owned "Tether" but it's gone from the current services.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(
            &tunnel(),
            &fp,
            &["Wi-Fi".to_string(), "Tether".to_string()],
            &targets,
        );

        assert_eq!(actions.drop, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.capture.is_empty());
        assert!(actions.apply.is_empty());
    }

    #[test]
    fn plan_dns_steady_state_is_a_no_op() {
        // Primary already shows tunnel DNS and is owned → nothing to do.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);
        assert_eq!(actions, DnsActions::default());
    }

    #[test]
    fn plan_dns_partial_overlap_is_not_a_match() {
        // VPN [100.64.0.1, 8.8.8.8] vs observed [100.64.0.1] is not equal → apply.
        let tunnel = vec!["100.64.0.1".to_string(), "8.8.8.8".to_string()];
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel, &fp, &[], &targets);
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn parse_scutil_primary_interface_extracts_device() {
        let output = "\
<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 1A2B3C4D-0000-1111-2222-333344445555
  Router : 192.168.1.1
}
";
        assert_eq!(
            parse_scutil_primary_interface(output).as_deref(),
            Some("en0")
        );
        assert_eq!(parse_scutil_primary_interface("No such key").as_deref(), None);
    }

    #[test]
    fn parse_service_name_for_device_maps_devices_and_ignores_pseudo_services() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(*) VPN (Cisco IPSec)
(Hardware Port: VPN (Cisco IPSec), Device: )
";
        assert_eq!(
            parse_service_name_for_device(output, "en0").as_deref(),
            Some("Wi-Fi")
        );
        assert_eq!(
            parse_service_name_for_device(output, "bridge0").as_deref(),
            Some("Thunderbolt Bridge")
        );
        assert_eq!(
            parse_service_name_for_device(output, "en5").as_deref(),
            Some("USB 10/100/1000 LAN")
        );
        // Unknown device and the device-less VPN pseudo-service yield nothing.
        assert_eq!(parse_service_name_for_device(output, "en9"), None);
    }

    #[test]
    fn parse_device_from_hw_line_handles_present_and_empty() {
        assert_eq!(
            parse_device_from_hw_line(" Wi-Fi, Device: en0)").as_deref(),
            Some("en0")
        );
        assert_eq!(parse_device_from_hw_line(" VPN (Cisco IPSec), Device: )"), None);
        assert_eq!(parse_device_from_hw_line(" no device field here)"), None);
    }
}

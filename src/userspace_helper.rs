#[cfg(unix)]
mod network;
#[cfg(unix)]
use network::recover_network;
#[cfg(unix)]
mod worker;
#[cfg(unix)]
use worker::NetworkWorker;
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
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(all(unix, target_os = "linux"))]
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
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
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    interface_name: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    control_interface_name: String,
    control_socket_path: PathBuf,
    device: Device<DefaultDeviceTransports>,
    network: NetworkWorker,
    _session_lock: network::SessionLock,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ParsedUserspaceConfig {
    private_key: [u8; 32],
    mtu: Option<crate::wireguard::config::Mtu>,
    addresses: Vec<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
            drop(child_tx);
            let mut status = [0u8; 1];
            parent_rx.set_read_timeout(Some(Duration::from_secs(60)))?;
            parent_rx
                .recv(&mut status)
                .context("failed to receive startup status from helper child")?;
            if status == READY_OK {
                return Ok(());
            }
            anyhow::bail!("userspace helper child reported startup failure");
        }
        daemonize::Outcome::Child(result) => {
            drop(parent_rx);
            let signal_parent = |ok: bool| -> io::Result<()> {
                child_tx.send(if ok { READY_OK } else { READY_ERR })?;
                Ok(())
            };

            if let Err(e) = result {
                let _ = signal_parent(false);
                anyhow::bail!("failed to initialize userspace helper child: {}", e);
            }

            let _logging_guard = crate::logging::init_terminal(false)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to create tokio runtime for userspace helper")?;
            let mut session_ownership = None;
            let mut acknowledgment = None;
            let outcome = rt.block_on(async {
                let mut sigint = signal(SignalKind::interrupt()).context("failed to set SIGINT handler")?;
                let mut sigterm = signal(SignalKind::terminate()).context("failed to set SIGTERM handler")?;
                let session_lock = match recover_network(interface) {
                    Ok(lock) => lock,
                    Err(error) => { let _ = signal_parent(false); return Err(error); }
                };
                session_ownership = Some(session_lock.clone());
                let running = match start_device(interface, session_lock, &mut sigint, &mut sigterm).await {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = signal_parent(false);
                        return Err(error);
                    }
                };
                let stop_path = PathBuf::from(SOCK_DIR).join(format!("{interface}.stop"));
                let listener = tokio::net::UnixListener::bind(&stop_path);
                let outcome = match listener {
                    Ok(listener) => {
                        use std::os::unix::fs::PermissionsExt;
                        let setup = std::fs::set_permissions(
                            &stop_path,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .context("failed to protect helper stop socket")
                        .and_then(|()| {
                            signal_parent(true)
                                .context("failed to notify parent about helper startup")
                        });
                        match setup {
                            Ok(()) => match wait_for_shutdown(&running, &listener, &mut sigint, &mut sigterm).await {
                                Ok(stream) => {
                                    acknowledgment = stream;
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            },
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => {
                        Err(anyhow::Error::new(error).context("failed to bind helper stop socket"))
                    }
                };
                let cleanup = running.network.stop().await;
                let stop = stop_device(running.device).await;
                let errors: Vec<String> = [outcome, cleanup, stop].into_iter()
                    .filter_map(|result| result.err().map(|error| format!("{error:#}"))).collect();
                let result = if errors.is_empty() { Ok(()) } else {
                    tracing::error!(interface, errors = ?errors, "userspace_helper_teardown_failed");
                    Err(anyhow::anyhow!(errors.join("; ")))
                };
                if result.is_ok() {
                    let _ = std::fs::remove_file(&running.control_socket_path);
                }
                let _ = std::fs::remove_file(stop_path);
                result
            });
            // gotatun Drop can spawn async shutdown work; bound runtime shutdown too.
            rt.shutdown_timeout(Duration::from_secs(1));
            drop(session_ownership);
            if let Some(stream) = acknowledgment {
                use std::io::Write;
                let message = match &outcome {
                    Ok(()) => "ok\n".to_string(),
                    Err(error) => format!("error: {error:#}\n"),
                };
                if let Ok(mut stream) = stream.into_std() {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let _ = stream.write_all(message.as_bytes());
                }
            }
            outcome?;
        }
    }

    Ok(())
}

#[cfg(unix)]
#[tracing::instrument(
    skip_all,
    fields(interface, backend = "userspace", operation = "start")
)]
async fn start_device(
    interface: &str,
    session_lock: network::SessionLock,
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
) -> anyhow::Result<RunningDevice> {
    let stop_path = PathBuf::from(SOCK_DIR).join(format!("{interface}.stop"));
    match std::fs::remove_file(stop_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
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
        if let Err(e) = tokio::time::timeout(
            Duration::from_secs(5),
            apply_wireguard_config(&device, config),
        )
        .await
        .context("device configuration deadline exceeded")
        .and_then(|result| result)
        {
            let _ = stop_device(device).await;
            let _ = std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
            return Err(e);
        }
    }

    let network = match NetworkWorker::start(
        interface_name.clone(),
        parsed_config,
        interface.to_string(),
        session_lock.clone(),
        async {
            tokio::select! { _ = sigint.recv() => {}, _ = sigterm.recv() => {} }
        },
    )
    .await
    {
        Ok(worker) => worker,
        Err(error) => {
            let _ = stop_device(device).await;
            let _ = std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
            return Err(error);
        }
    };

    let control_socket_path = PathBuf::from(SOCK_DIR).join(format!("{}.sock", interface));
    Ok(RunningDevice {
        interface_name,
        control_interface_name: interface.to_string(),
        control_socket_path,
        device,
        network,
        _session_lock: session_lock,
    })
}

#[cfg(unix)]
#[tracing::instrument(
    skip_all,
    fields(backend = "userspace", operation = "stop", deadline_seconds = 5)
)]
async fn stop_device(device: Device<DefaultDeviceTransports>) -> anyhow::Result<()> {
    // stop consumes the device and waits on task joins. Retain the task until the
    // deadline, then abort it; runtime teardown drops remaining device tasks.
    finish_device_stop(tokio::spawn(device.stop()), Duration::from_secs(5)).await
}

#[cfg(unix)]
async fn finish_device_stop(
    mut task: tokio::task::JoinHandle<()>,
    deadline: Duration,
) -> anyhow::Result<()> {
    match tokio::time::timeout(deadline, &mut task).await {
        Ok(result) => result.context("device stop task failed"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("device stop exceeded 5 seconds; network restoration was attempted")
        }
    }
}

#[cfg(unix)]
#[tracing::instrument(skip_all, fields(interface = %running.interface_name, backend = "userspace", operation = "wait_for_shutdown"))]
async fn wait_for_shutdown(
    running: &RunningDevice,
    listener: &tokio::net::UnixListener,
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
) -> anyhow::Result<Option<tokio::net::UnixStream>> {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            biased;
            _ = sigint.recv() => return Ok(None),
            _ = sigterm.recv() => return Ok(None),
            result = listener.accept() => return result.map(|(stream, _)| Some(stream)).context("helper stop listener failed"),
            _ = ticker.tick() => {
                if !running.control_socket_path.exists() { return Ok(None); }
                #[cfg(target_os = "linux")]
                if !Path::new("/sys/class/net").join(&running.interface_name).exists() { return Ok(None); }
                let diagnostic = tokio::time::timeout(Duration::from_secs(1), running.device.peers());
                tokio::select! {
                    biased;
                    _ = sigint.recv() => return Ok(None),
                    _ = sigterm.recv() => return Ok(None),
                    result = listener.accept() => return result.map(|(stream, _)| Some(stream)).context("helper stop listener failed"),
                    result = diagnostic => match result {
                        Ok(peers) => {
                            let (rx_bytes, tx_bytes) = peers.iter().fold((0u64, 0u64), |(rx, tx), peer| {
                                (rx.saturating_add(peer.stats.rx_bytes as u64), tx.saturating_add(peer.stats.tx_bytes as u64))
                            });
                            tracing::debug!(interface = running.control_interface_name, rx_bytes, tx_bytes, "userspace_helper_statistics");
                        }
                        Err(_) => tracing::debug!(interface = running.control_interface_name, "userspace_helper_statistics_timeout"),
                    }
                }
            }
        }
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
    parse_wg_quick_config(&text).map(Some)
}

#[cfg(unix)]
fn parse_wg_quick_config(config: &str) -> anyhow::Result<ParsedUserspaceConfig> {
    let parsed = crate::wireguard::config::parse_config(config)?;
    if parsed.peers.len() != 1 {
        anyhow::bail!("userspace helper requires exactly one Peer section");
    }
    let peer = &parsed.peers[0];
    let endpoint = peer
        .endpoint
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing Peer.Endpoint"))?;
    Ok(ParsedUserspaceConfig {
        private_key: decode_key32("PrivateKey", &parsed.private_key)?,
        mtu: parsed.mtu,
        addresses: parsed.addresses,
        dns_servers: parsed.dns_servers,
        peer_public_key: decode_key32("PublicKey", &peer.public_key)?,
        peer_preshared_key: peer
            .preshared_key
            .as_deref()
            .map(|value| decode_key32("PresharedKey", value))
            .transpose()?,
        allowed_ips: split_csv(&peer.allowed_ips),
        endpoint: parse_endpoint(endpoint)?,
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

#[cfg(all(test, unix))]
mod mtu_tests {
    use super::*;

    #[test]
    fn test_helper_receives_validated_config_mtu() {
        let key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let config = format!("[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n");
        let parsed = parse_wg_quick_config(&config).unwrap();
        assert_eq!(parsed.mtu.unwrap().get(), 1280);
        let overridden = crate::wireguard::config::with_mtu_override(
            &config,
            crate::wireguard::config::Mtu::new(1420).unwrap(),
        );
        assert_eq!(
            parse_wg_quick_config(&overridden)
                .unwrap()
                .mtu
                .unwrap()
                .get(),
            1420
        );
        assert!(parse_wg_quick_config(&config.replace("1280", "575")).is_err());
    }
}

#[cfg(unix)]
pub fn recover_stopped(interface: &str) -> anyhow::Result<()> {
    network::recover_stopped_session(interface)
}

#[cfg(all(test, unix))]
mod lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn test_stalled_device_stop_is_cancelled_and_reaped() {
        struct Stopped(tokio::sync::oneshot::Sender<()>);
        impl Drop for Stopped {
            fn drop(&mut self) {
                let (replacement, _) = tokio::sync::oneshot::channel();
                let sender = std::mem::replace(&mut self.0, replacement);
                let _ = sender.send(());
            }
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _stopped = Stopped(sender);
            std::future::pending::<()>().await;
        });
        let result = finish_device_stop(task, Duration::from_millis(10)).await;
        assert!(result.is_err());
        receiver.await.unwrap();
    }
}

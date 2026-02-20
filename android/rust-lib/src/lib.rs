use base64::Engine;
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use gotatun::x25519::{PublicKey, StaticSecret};
use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde_json::{json, Value};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;
use tokio::task::AbortHandle;
use tunmux::airvpn::api::AirVpnClient;
use tunmux::airvpn::models::{AirManifest, AirServer, AirWgKey, AirWgMode};
use tunmux::airvpn::web::AirVpnWeb;
use tunmux::api;
use tunmux::crypto;
use tunmux::models::server::LogicalServer;
use tunmux::models::session::Session;
use tunmux::wireguard::proxy_tunnel::{run_local_proxy, LocalProxyConfig};

static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();
static LOGGER_INIT: OnceLock<()> = OnceLock::new();
static TUNNEL_STATE: Mutex<Option<TunnelHandle>> = Mutex::new(None);
static APP_STATE: Mutex<Option<AppState>> = Mutex::new(None);
static AIRVPN_STATE: Mutex<Option<AirVpnAndroidState>> = Mutex::new(None);
static PROTON_STATE: Mutex<Option<ProtonAndroidState>> = Mutex::new(None);
static LOCAL_PROXY_STATE: Mutex<Option<LocalProxyHandle>> = Mutex::new(None);

struct LocalProxyHandle {
    abort: AbortHandle,
    #[allow(dead_code)]
    socks_port: u16,
    #[allow(dead_code)]
    http_port: u16,
}

const UDP_RECV_BUFFER_SIZE: usize = 7 * 1024 * 1024;
const UDP_SEND_BUFFER_SIZE: usize = 7 * 1024 * 1024;
const AIRVPN_KEEPALIVE_SECS: u16 = 25;

type AndroidWgDevice = Device<(AndroidUdpFactory, TunDevice, TunDevice)>;

struct AppState {
    jvm: JavaVM,
    service_ref: GlobalRef,
    #[allow(dead_code)]
    files_dir: String,
}

struct TunnelHandle {
    tun_fd: RawFd,
    data_plane_ready: bool,
    wg_device: Option<AndroidWgDevice>,
    provider: String,
    backend: String,
    interface_name: String,
    selected_server: String,
    selected_key: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    peer_public_key: String,
    addresses: Vec<String>,
    dns_servers: Vec<String>,
    mtu: i32,
    keepalive_secs: Option<u16>,
    connected_since_epoch_secs: i64,
}

#[derive(Clone)]
struct AirVpnAndroidState {
    username: String,
    password: String,
    server_list_json: String,
    key_count: usize,
    servers: Vec<AirServer>,
    wg_mode: AirWgMode,
    wg_public_key: String,
    keys: Vec<AirWgKey>,
    selected_key_name: String,
}

#[derive(Clone)]
struct ProtonAndroidState {
    username: String,
    session: Session,
    server_list_json: String,
    servers: Vec<LogicalServer>,
}

struct LoginCredentials {
    username: String,
    password: String,
    totp: Option<String>,
    device: Option<String>,
}

#[derive(Clone)]
struct TunConfig {
    addresses: Vec<String>,
    routes: Vec<String>,
    dns_servers: Vec<String>,
    mtu: i32,
}

struct WireGuardRuntimeConfig {
    server_name: String,
    endpoint: SocketAddr,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<String>,
    keepalive_secs: Option<u16>,
}

#[derive(Clone)]
struct AndroidUdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
}

impl AndroidUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[derive(Clone, Copy)]
struct AndroidUdpFactory;

impl AndroidUdpFactory {
    fn create_socket(&self, addr: SocketAddr) -> io::Result<AndroidUdpSocket> {
        let domain = match addr {
            SocketAddr::V4(..) => socket2::Domain::IPV4,
            SocketAddr::V6(..) => socket2::Domain::IPV6,
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_recv_buffer_size(UDP_RECV_BUFFER_SIZE)?;
        socket.set_send_buffer_size(UDP_SEND_BUFFER_SIZE)?;
        socket.bind(&addr.into())?;

        protect_fd_from_app_state(socket.as_raw_fd()).map_err(io::Error::other)?;

        let std_socket: std::net::UdpSocket = socket.into();
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(AndroidUdpSocket {
            inner: Arc::new(socket),
        })
    }
}

impl UdpTransportFactory for AndroidUdpFactory {
    type Send = AndroidUdpSocket;
    type RecvV4 = AndroidUdpSocket;
    type RecvV6 = AndroidUdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::RecvV4), (Self::Send, Self::RecvV6))> {
        let mut port = params.port;
        let udp_v4 = self.create_socket((params.addr_v4, port).into())?;
        if port == 0 {
            port = udp_v4.local_addr()?.port();
        }

        let udp_v6 = self.create_socket((params.addr_v6, port).into())?;
        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
}

impl UdpSend for AndroidUdpSocket {
    type SendManyBuf = ();

    async fn send_to(
        &self,
        packet: gotatun::packet::Packet,
        destination: SocketAddr,
    ) -> io::Result<()> {
        self.inner.send_to(&packet, destination).await?;
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        AndroidUdpSocket::local_addr(self).map(Some)
    }
}

impl UdpRecv for AndroidUdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(
        &mut self,
        pool: &mut gotatun::packet::PacketBufPool,
    ) -> io::Result<(gotatun::packet::Packet, SocketAddr)> {
        let mut buf = pool.get();
        let (n, src) = self.inner.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, src))
    }
}

fn default_tun_config() -> TunConfig {
    TunConfig {
        addresses: vec!["10.64.0.2/32".to_string()],
        routes: vec!["0.0.0.0/0".to_string()],
        dns_servers: vec!["1.1.1.1".to_string()],
        mtu: 1500,
    }
}

fn ensure_logger() {
    LOGGER_INIT.get_or_init(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("tunmux"),
        );
    });
}

fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime init failed")
    })
}

fn close_raw_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn stop_tunnel_handle(handle: TunnelHandle) {
    if let Some(device) = handle.wg_device {
        get_runtime().block_on(async {
            device.stop().await;
        });
    }
    close_raw_fd(handle.tun_fd);
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeInitialize(
    mut env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    files_dir: JString,
) {
    ensure_logger();

    let jvm = env.get_java_vm().expect("failed to get JavaVM");
    let service_ref = env
        .new_global_ref(vpn_service)
        .expect("failed to create global ref");
    let files_dir: String = env
        .get_string(&files_dir)
        .expect("failed to get files_dir string")
        .into();

    let mut state = APP_STATE.lock().unwrap();
    *state = Some(AppState {
        jvm,
        service_ref,
        files_dir,
    });

    log::debug!("tunmux native initialized");
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeShutdown(
    _env: JNIEnv,
    _class: JClass,
) {
    ensure_logger();
    let previous_tunnel = {
        let mut tunnel = TUNNEL_STATE.lock().unwrap();
        tunnel.take()
    };
    if let Some(handle) = previous_tunnel {
        stop_tunnel_handle(handle);
    }
    let mut state = APP_STATE.lock().unwrap();
    *state = None;
    log::debug!("tunmux native shutdown");
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    provider: JString,
    server_json: JString,
) -> jboolean {
    ensure_logger();
    let provider: String = match env.get_string(&provider) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let provider_norm = provider.trim().to_ascii_lowercase();
    let server_json: String = match env.get_string(&server_json) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    log::info!("nativeConnect called; provider={}", provider_norm);
    let selected_server = extract_selected_server_label(&server_json);
    let (tun_config, wg_runtime_cfg, selected_key_name) = match provider_norm.as_str() {
        "airvpn" => {
            let state = AIRVPN_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => {
                    let key = match selected_airvpn_key(s) {
                        Ok(k) => k,
                        Err(e) => {
                            log::error!("nativeConnect: failed to resolve AirVPN key: {e}");
                            return JNI_FALSE;
                        }
                    };
                    let cfg = build_airvpn_tun_config(key);
                    let wg = match build_airvpn_runtime_config(s, key, &selected_server) {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!(
                                "nativeConnect: failed to build AirVPN WireGuard config: {e}"
                            );
                            return JNI_FALSE;
                        }
                    };
                    (cfg, wg, key.name.clone())
                }
                None => {
                    log::error!("nativeConnect: no AirVPN login state");
                    return JNI_FALSE;
                }
            }
        }
        "proton" => {
            let state = PROTON_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => {
                    let cfg = proton_tun_config();
                    let wg = match build_proton_runtime_config(s, &selected_server) {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!(
                                "nativeConnect: failed to build Proton WireGuard config: {e}"
                            );
                            return JNI_FALSE;
                        }
                    };
                    (cfg, wg, String::new())
                }
                None => {
                    log::error!("nativeConnect: no Proton login state");
                    return JNI_FALSE;
                }
            }
        }
        _ => {
            log::warn!(
                "nativeConnect: provider '{}' not implemented",
                provider_norm
            );
            return JNI_FALSE;
        }
    };

    let previous_tunnel = {
        let mut tunnel = TUNNEL_STATE.lock().unwrap();
        tunnel.take()
    };
    if let Some(handle) = previous_tunnel {
        stop_tunnel_handle(handle);
    }

    // Open the TUN fd by calling back into the VpnService
    let tun_fd = {
        let state = APP_STATE.lock().unwrap();
        let app_state = match state.as_ref() {
            Some(s) => s,
            None => {
                log::error!("nativeConnect: app state not initialized");
                return JNI_FALSE;
            }
        };
        open_tun_fd(&app_state.jvm, &app_state.service_ref, &tun_config)
    };

    let fd = match tun_fd {
        Ok(fd) if fd >= 0 => fd,
        Ok(_) | Err(_) => {
            log::error!("nativeConnect: failed to open TUN fd");
            return JNI_FALSE;
        }
    };

    let wg_device = match start_android_wireguard(fd, &wg_runtime_cfg) {
        Ok(device) => device,
        Err(e) => {
            log::error!("nativeConnect: failed to start WireGuard backend: {}", e);
            close_raw_fd(fd);
            return JNI_FALSE;
        }
    };

    let mut tunnel = TUNNEL_STATE.lock().unwrap();
    *tunnel = Some(TunnelHandle {
        tun_fd: fd,
        data_plane_ready: true,
        wg_device: Some(wg_device),
        provider: provider_norm,
        backend: "userspace".to_string(),
        interface_name: "tunmux0".to_string(),
        selected_server: wg_runtime_cfg.server_name,
        selected_key: selected_key_name,
        endpoint: wg_runtime_cfg.endpoint.to_string(),
        allowed_ips: wg_runtime_cfg.allowed_ips.clone(),
        peer_public_key: base64::engine::general_purpose::STANDARD
            .encode(wg_runtime_cfg.peer_public_key),
        addresses: tun_config.addresses,
        dns_servers: tun_config.dns_servers,
        mtu: tun_config.mtu,
        keepalive_secs: wg_runtime_cfg.keepalive_secs,
        connected_since_epoch_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    });

    log::info!(
        "nativeConnect: tunnel established with WireGuard backend, tun_fd={}",
        fd
    );
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
) {
    ensure_logger();
    let handle = {
        let mut tunnel = TUNNEL_STATE.lock().unwrap();
        tunnel.take()
    };
    if let Some(handle) = handle {
        stop_tunnel_handle(handle);
        log::info!("nativeDisconnect: tunnel closed");
    }
}

fn push_string_to_list(env: &mut JNIEnv, list: &JObject, value: &str) -> Result<(), String> {
    let jstr = env
        .new_string(value)
        .map_err(|e| format!("new_string failed: {e}"))?;
    let obj = JObject::from(jstr);
    env.call_method(
        list,
        "add",
        "(Ljava/lang/Object;)Z",
        &[jni::objects::JValueGen::Object(&obj)],
    )
    .map_err(|e| format!("ArrayList.add failed: {e}"))?;
    Ok(())
}

fn open_tun_fd(jvm: &JavaVM, service_ref: &GlobalRef, cfg: &TunConfig) -> Result<RawFd, String> {
    let mut env = jvm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread failed: {e}"))?;

    // Call TunmuxVpnService.openTun(addresses, routes, dns, mtu)
    let addresses = env
        .new_object("java/util/ArrayList", "()V", &[])
        .map_err(|e| format!("new ArrayList: {e}"))?;
    let routes = env
        .new_object("java/util/ArrayList", "()V", &[])
        .map_err(|e| format!("new ArrayList: {e}"))?;
    let dns = env
        .new_object("java/util/ArrayList", "()V", &[])
        .map_err(|e| format!("new ArrayList: {e}"))?;

    for addr in &cfg.addresses {
        push_string_to_list(&mut env, &addresses, addr)?;
    }
    for route in &cfg.routes {
        push_string_to_list(&mut env, &routes, route)?;
    }
    for dns_server in &cfg.dns_servers {
        push_string_to_list(&mut env, &dns, dns_server)?;
    }

    log::debug!(
        "open_tun_fd config: addresses={} routes={} dns={} mtu={}",
        cfg.addresses.len(),
        cfg.routes.len(),
        cfg.dns_servers.len(),
        cfg.mtu
    );

    let result = env
        .call_method(
            service_ref.as_obj(),
            "openTun",
            "(Ljava/util/List;Ljava/util/List;Ljava/util/List;I)I",
            &[
                (&addresses).into(),
                (&routes).into(),
                (&dns).into(),
                jni::objects::JValueGen::Int(cfg.mtu),
            ],
        )
        .map_err(|e| format!("openTun call failed: {e}"))?;

    match result {
        jni::objects::JValueGen::Int(fd) => Ok(fd as RawFd),
        _ => Err("openTun returned unexpected type".to_string()),
    }
}

// Provider operations (called from UI via RustBridge)

fn protect_fd_with_service(jvm: &JavaVM, service_ref: &GlobalRef, fd: RawFd) -> Result<(), String> {
    let mut env = jvm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread failed: {e}"))?;
    let result = env
        .call_method(
            service_ref.as_obj(),
            "bypass",
            "(I)Z",
            &[jni::objects::JValueGen::Int(fd)],
        )
        .map_err(|e| format!("bypass/protect call failed: {e}"))?;

    match result {
        jni::objects::JValueGen::Bool(v) if v != 0 => Ok(()),
        jni::objects::JValueGen::Bool(_) => Err(format!("VpnService.protect({fd}) returned false")),
        _ => Err("bypass returned unexpected type".to_string()),
    }
}

fn protect_fd_from_app_state(fd: RawFd) -> Result<(), String> {
    let state = APP_STATE.lock().unwrap();
    let app_state = state
        .as_ref()
        .ok_or_else(|| "app state not initialized for socket protect".to_string())?;
    protect_fd_with_service(&app_state.jvm, &app_state.service_ref, fd)
}

fn parse_login_credentials(credential: &str) -> Result<LoginCredentials, String> {
    let parsed: Value =
        serde_json::from_str(credential).map_err(|e| format!("invalid credential JSON: {e}"))?;

    let username = parsed
        .get("username")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing username".to_string())?
        .to_string();

    let password = parsed
        .get("password")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing password".to_string())?
        .to_string();

    let device = parsed
        .get("device")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    let totp = parsed
        .get("totp")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    Ok(LoginCredentials {
        username,
        password,
        totp,
        device,
    })
}

fn filter_proton_servers(max_tier: i32, mut servers: Vec<LogicalServer>) -> Vec<LogicalServer> {
    servers.retain(|s| s.is_enabled() && s.best_physical().is_some() && s.tier <= max_tier);
    servers.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    servers
}

fn build_proton_server_label(server: &LogicalServer) -> String {
    let location = server
        .city
        .as_deref()
        .filter(|v| !v.is_empty())
        .or_else(|| server.region.as_deref().filter(|v| !v.is_empty()))
        .unwrap_or("unknown");
    format!("{} [{}] {}", server.name, server.exit_country, location)
}

fn build_proton_server_list_json(servers: &[LogicalServer]) -> String {
    let mut labels: Vec<String> = servers.iter().map(build_proton_server_label).collect();
    labels.sort();
    serde_json::to_string(&labels).unwrap_or_else(|_| "[]".to_string())
}

fn proton_tun_config() -> TunConfig {
    TunConfig {
        addresses: vec!["10.2.0.2/32".to_string()],
        routes: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        dns_servers: vec!["10.2.0.1".to_string()],
        mtu: 1500,
    }
}

fn find_proton_server<'a>(
    state: &'a ProtonAndroidState,
    selected_server_label: &str,
) -> Option<&'a LogicalServer> {
    let trimmed = selected_server_label.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(found) = state
        .servers
        .iter()
        .find(|s| build_proton_server_label(s) == trimmed)
    {
        return Some(found);
    }

    if let Some(found) = state
        .servers
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(trimmed))
    {
        return Some(found);
    }

    let name_hint = trimmed.split(" [").next().unwrap_or("").trim();
    if name_hint.is_empty() {
        None
    } else {
        state
            .servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name_hint))
    }
}

fn format_airvpn_server_label(server: &AirServer) -> String {
    format!(
        "{} [{}] {}",
        server.name, server.country_code, server.location
    )
}

fn build_airvpn_server_list_json(manifest: &AirManifest) -> String {
    let mut entries: Vec<String> = manifest
        .servers
        .iter()
        .map(format_airvpn_server_label)
        .collect();
    entries.sort();
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

fn build_airvpn_tun_config(key: &AirWgKey) -> TunConfig {
    let mut cfg = default_tun_config();

    let mut addresses = Vec::new();
    if !key.wg_ipv4.is_empty() {
        addresses.push(key.wg_ipv4.clone());
    }
    if !key.wg_ipv6.is_empty() {
        addresses.push(key.wg_ipv6.clone());
    }
    if !addresses.is_empty() {
        cfg.addresses = addresses;
    }

    let has_v4 = !key.wg_ipv4.is_empty();
    let has_v6 = !key.wg_ipv6.is_empty();
    cfg.routes.clear();
    if has_v4 {
        cfg.routes.push("0.0.0.0/0".to_string());
    }
    if has_v6 {
        cfg.routes.push("::/0".to_string());
    }

    let mut dns_servers = Vec::new();
    if !key.wg_dns_ipv4.is_empty() {
        dns_servers.push(key.wg_dns_ipv4.clone());
    }
    if !key.wg_dns_ipv6.is_empty() {
        dns_servers.push(key.wg_dns_ipv6.clone());
    }
    if !dns_servers.is_empty() {
        cfg.dns_servers = dns_servers;
    }

    cfg
}

fn find_airvpn_key_by_name<'a>(state: &'a AirVpnAndroidState, name: &str) -> Option<&'a AirWgKey> {
    state
        .keys
        .iter()
        .find(|k| k.name.eq_ignore_ascii_case(name))
}

fn selected_airvpn_key(state: &AirVpnAndroidState) -> Result<&AirWgKey, String> {
    if state.keys.is_empty() {
        return Err("no WireGuard keys in AirVPN session".to_string());
    }

    if !state.selected_key_name.is_empty() {
        if let Some(key) = find_airvpn_key_by_name(state, &state.selected_key_name) {
            return Ok(key);
        }
    }

    state
        .keys
        .first()
        .ok_or_else(|| "no WireGuard keys in AirVPN session".to_string())
}

fn set_selected_airvpn_key(
    state: &mut AirVpnAndroidState,
    key_name: &str,
) -> Result<String, String> {
    let trimmed = key_name.trim();
    if trimmed.is_empty() {
        return Err("AirVPN key name cannot be empty".to_string());
    }

    let canonical = find_airvpn_key_by_name(state, trimmed)
        .map(|k| k.name.clone())
        .ok_or_else(|| format!("AirVPN key '{}' not found", trimmed))?;
    state.selected_key_name = canonical.clone();
    Ok(canonical)
}

fn refresh_airvpn_keys_in_state(state: &mut AirVpnAndroidState) -> Result<(), String> {
    let username = state.username.clone();
    let password = state.password.clone();

    let refreshed = get_runtime().block_on(async {
        let client = AirVpnClient::new()?;
        client.login(&username, &password).await
    });

    let session = refreshed.map_err(|e| format!("failed to refresh AirVPN keys: {e}"))?;
    state.wg_public_key = session.wg_public_key;
    state.key_count = session.keys.len();
    state.keys = session.keys;

    if state.keys.is_empty() {
        state.selected_key_name.clear();
        return Err("no WireGuard keys in refreshed AirVPN session".to_string());
    }

    if find_airvpn_key_by_name(state, &state.selected_key_name).is_none() {
        state.selected_key_name = state.keys[0].name.clone();
    }
    Ok(())
}

fn airvpn_credentials() -> Result<(String, String), String> {
    let state = AIRVPN_STATE.lock().unwrap();
    let current = state
        .as_ref()
        .ok_or_else(|| "AirVPN is not logged in".to_string())?;
    Ok((current.username.clone(), current.password.clone()))
}

fn extract_selected_server_label(server_json: &str) -> String {
    let trimmed = server_json.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        if let Some(s) = value.as_str() {
            return s.trim().to_string();
        }
        for key in ["server", "name", "label"] {
            if let Some(s) = value.get(key).and_then(Value::as_str) {
                return s.trim().to_string();
            }
        }
    }
    trimmed.to_string()
}

fn decode_key32(field: &str, value: &str) -> Result<[u8; 32], String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("failed to decode {field}: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn build_airvpn_runtime_config(
    state: &AirVpnAndroidState,
    key: &AirWgKey,
    selected_server_label: &str,
) -> Result<WireGuardRuntimeConfig, String> {
    let selected = if selected_server_label.is_empty() {
        None
    } else {
        state
            .servers
            .iter()
            .find(|s| format_airvpn_server_label(s) == selected_server_label)
            .or_else(|| {
                state
                    .servers
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(selected_server_label))
            })
    };
    let used_fallback = selected.is_none();
    let server = selected
        .or_else(|| state.servers.first())
        .ok_or_else(|| "no AirVPN servers available".to_string())?;
    if used_fallback && !selected_server_label.is_empty() {
        log::warn!(
            "nativeConnect: selected server '{}' not found, falling back to '{}'",
            selected_server_label,
            server.name
        );
    }

    let endpoint_ip = server
        .ips_entry
        .get(state.wg_mode.entry_index as usize)
        .or_else(|| server.ips_entry.first())
        .ok_or_else(|| "selected AirVPN server has no entry IPs".to_string())?;
    let endpoint_ip: IpAddr = endpoint_ip
        .parse()
        .map_err(|e| format!("invalid AirVPN endpoint IP '{}': {}", endpoint_ip, e))?;

    let private_key = decode_key32("wg_private_key", &key.wg_private_key)?;
    let peer_public_key = decode_key32("wg_public_key", &state.wg_public_key)?;
    let preshared_key = match key.wg_preshared.as_str() {
        psk if !psk.is_empty() => Some(decode_key32("wg_preshared", psk)?),
        _ => None,
    };

    Ok(WireGuardRuntimeConfig {
        server_name: server.name.clone(),
        endpoint: SocketAddr::new(endpoint_ip, state.wg_mode.port),
        private_key,
        peer_public_key,
        preshared_key,
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        keepalive_secs: Some(AIRVPN_KEEPALIVE_SECS),
    })
}

fn build_proton_runtime_config(
    state: &ProtonAndroidState,
    selected_server_label: &str,
) -> Result<WireGuardRuntimeConfig, String> {
    let selected = if selected_server_label.is_empty() {
        None
    } else {
        find_proton_server(state, selected_server_label)
    };
    let used_fallback = selected.is_none();
    let server = selected
        .or_else(|| state.servers.first())
        .ok_or_else(|| "no Proton servers available".to_string())?;
    if used_fallback && !selected_server_label.is_empty() {
        log::warn!(
            "nativeConnect: selected server '{}' not found, falling back to '{}'",
            selected_server_label,
            server.name
        );
    }

    let physical = server
        .best_physical()
        .ok_or_else(|| "selected Proton server has no WireGuard endpoint".to_string())?;
    let endpoint_ip: IpAddr = physical
        .entry_ip
        .parse()
        .map_err(|e| format!("invalid Proton endpoint IP '{}': {}", physical.entry_ip, e))?;
    let private_key = decode_key32("wg_private_key", &state.session.wg_private_key)?;
    let server_public_key = physical
        .x25519_public_key
        .as_deref()
        .ok_or_else(|| "selected Proton server is missing x25519 key".to_string())?;
    let peer_public_key = decode_key32("server_x25519_public_key", server_public_key)?;

    Ok(WireGuardRuntimeConfig {
        server_name: server.name.clone(),
        endpoint: SocketAddr::new(endpoint_ip, 51820),
        private_key,
        peer_public_key,
        preshared_key: None,
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        keepalive_secs: None,
    })
}

async fn login_proton(login_credentials: &LoginCredentials) -> Result<ProtonAndroidState, String> {
    let mut client = api::http::ProtonClient::new().map_err(|e| e.to_string())?;
    let auth = api::auth::login(
        &mut client,
        &login_credentials.username,
        &login_credentials.password,
    )
    .await
    .map_err(|e| e.to_string())?;

    if auth.two_factor.totp_required() {
        let code = login_credentials
            .totp
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        if code.is_empty() {
            return Err("2FA code required for this Proton account".to_string());
        }
        api::auth::submit_2fa(&client, code)
            .await
            .map_err(|e| e.to_string())?;
    }

    let vpn_info = api::vpn_info::fetch_vpn_info(&client)
        .await
        .map_err(|e| e.to_string())?;
    let keys = crypto::keys::VpnKeys::generate().map_err(|e| e.to_string())?;
    let cert = api::certificate::fetch_certificate(&client, &keys.ed25519_pk_pem())
        .await
        .map_err(|e| e.to_string())?;

    let session = Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        vpn_username: vpn_info.vpn.name,
        vpn_password: vpn_info.vpn.password,
        plan_name: vpn_info.vpn.plan_name,
        plan_title: vpn_info.vpn.plan_title,
        max_tier: vpn_info.vpn.max_tier,
        max_connections: vpn_info.vpn.max_connect,
        ed25519_private_key: keys.ed25519_sk_base64(),
        ed25519_public_key_pem: keys.ed25519_pk_pem(),
        wg_private_key: keys.wg_private_key(),
        wg_public_key: keys.wg_public_key(),
        fingerprint: keys.fingerprint(),
        certificate_pem: cert.certificate,
    };

    let servers_resp = api::servers::fetch_server_list(&client)
        .await
        .map_err(|e| e.to_string())?;
    let servers = filter_proton_servers(session.max_tier, servers_resp.logical_servers);
    if servers.is_empty() {
        return Err("no Proton WireGuard servers available for this account".to_string());
    }
    let server_list_json = build_proton_server_list_json(&servers);

    Ok(ProtonAndroidState {
        username: login_credentials.username.clone(),
        session,
        server_list_json,
        servers,
    })
}

fn start_android_wireguard(
    tun_fd: RawFd,
    cfg: &WireGuardRuntimeConfig,
) -> Result<AndroidWgDevice, String> {
    let mut peer = Peer::new(PublicKey::from(cfg.peer_public_key)).with_endpoint(cfg.endpoint);
    peer.preshared_key = cfg.preshared_key;
    peer.keepalive = cfg.keepalive_secs;
    for allowed in &cfg.allowed_ips {
        let network = allowed
            .parse()
            .map_err(|e| format!("invalid AllowedIPs entry '{}': {e}", allowed))?;
        peer.allowed_ips.push(network);
    }

    let udp_factory = AndroidUdpFactory;
    let runtime = get_runtime();

    // `tun::create_as_async` requires an entered Tokio runtime context.
    // Enter explicitly so this remains safe regardless of caller thread.
    let tun_device = {
        let _enter = runtime.enter();
        let mut tun_config = tun::Configuration::default();
        tun_config.raw_fd(tun_fd);
        tun_config.close_fd_on_drop(false);
        let tun = tun::create_as_async(&tun_config)
            .map_err(|e| format!("failed to wrap Android TUN fd: {e}"))?;
        TunDevice::from_tun_device(tun)
            .map_err(|e| format!("failed to create gotatun TUN device: {e}"))?
    };

    runtime.block_on(async move {
        let device = DeviceBuilder::new()
            .with_udp(udp_factory)
            .with_ip(tun_device)
            .build()
            .await
            .map_err(|e| format!("failed to start gotatun device: {e}"))?;
        device
            .set_private_key(StaticSecret::from(cfg.private_key))
            .await
            .map_err(|e| format!("failed to set WireGuard private key: {e}"))?;
        let added = device
            .add_peer(peer)
            .await
            .map_err(|e| format!("failed to add WireGuard peer: {e}"))?;
        if !added {
            return Err("WireGuard peer was not added".to_string());
        }
        Ok(device)
    })
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_login<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
    credential: JString,
) -> JString<'local> {
    ensure_logger();
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let _credential: String = env
        .get_string(&credential)
        .map(|s| s.into())
        .unwrap_or_default();

    let provider_norm = provider.trim().to_ascii_lowercase();
    log::debug!(
        "RustBridge.login: provider={} normalized={}",
        provider,
        provider_norm
    );

    let result = match provider_norm.as_str() {
        "airvpn" => match parse_login_credentials(&_credential) {
            Ok(login_credentials) => {
                let username = login_credentials.username;
                let password = login_credentials.password;
                let requested_device = login_credentials.device;
                let login_result = get_runtime().block_on(async {
                    let client = AirVpnClient::new()?;
                    let session = client.login(&username, &password).await?;
                    let manifest = client.fetch_manifest(&username, &password).await?;
                    let selected_key_name = if let Some(device_name) = requested_device.as_deref() {
                        session
                            .keys
                            .iter()
                            .find(|k| k.name.eq_ignore_ascii_case(device_name))
                            .map(|k| k.name.clone())
                            .ok_or_else(|| {
                                tunmux::error::AppError::Other(format!(
                                    "AirVPN key '{}' not found",
                                    device_name
                                ))
                            })?
                    } else {
                        session
                            .keys
                            .first()
                            .map(|k| k.name.clone())
                            .ok_or_else(|| {
                                tunmux::error::AppError::Other(
                                    "no WireGuard keys in AirVPN session".to_string(),
                                )
                            })?
                    };
                    let wg_mode = manifest.wg_modes.first().cloned().ok_or_else(|| {
                        tunmux::error::AppError::Other(
                            "no WireGuard modes in AirVPN manifest".to_string(),
                        )
                    })?;

                    Ok::<AirVpnAndroidState, tunmux::error::AppError>(AirVpnAndroidState {
                        username: username.clone(),
                        password: password.clone(),
                        server_list_json: build_airvpn_server_list_json(&manifest),
                        key_count: session.keys.len(),
                        servers: manifest.servers,
                        wg_mode,
                        wg_public_key: session.wg_public_key,
                        keys: session.keys,
                        selected_key_name,
                    })
                });

                match login_result {
                    Ok(login_data) => {
                        let keys = login_data.key_count;
                        let servers = login_data.servers.len();
                        let selected_key = login_data.selected_key_name.clone();
                        let mut state = AIRVPN_STATE.lock().unwrap();
                        *state = Some(login_data);
                        log::info!(
                            "RustBridge.login airvpn success: keys={} servers={} selected_key={}",
                            keys,
                            servers,
                            selected_key
                        );
                        json!({
                            "status": "ok",
                            "provider": "airvpn",
                            "keys": keys,
                            "servers": servers,
                            "selected_key": selected_key
                        })
                        .to_string()
                    }
                    Err(e) => {
                        log::error!("RustBridge.login airvpn failed: {}", e);
                        json!({
                            "status": "error",
                            "error": e.to_string()
                        })
                        .to_string()
                    }
                }
            }
            Err(msg) => {
                log::warn!("RustBridge.login airvpn bad credentials payload: {}", msg);
                json!({
                    "status": "error",
                    "error": msg
                })
                .to_string()
            }
        },
        "proton" => match parse_login_credentials(&_credential) {
            Ok(login_credentials) => {
                let login_result = get_runtime().block_on(login_proton(&login_credentials));
                match login_result {
                    Ok(login_data) => {
                        let servers = login_data.servers.len();
                        let username = login_data.username.clone();
                        let plan_title = login_data.session.plan_title.clone();
                        let max_tier = login_data.session.max_tier;
                        let max_connections = login_data.session.max_connections;
                        let mut state = PROTON_STATE.lock().unwrap();
                        *state = Some(login_data);
                        log::info!(
                            "RustBridge.login proton success: user={} servers={} tier={}",
                            username,
                            servers,
                            max_tier
                        );
                        json!({
                            "status": "ok",
                            "provider": "proton",
                            "username": username,
                            "plan_title": plan_title,
                            "max_tier": max_tier,
                            "max_connections": max_connections,
                            "servers": servers
                        })
                        .to_string()
                    }
                    Err(e) => {
                        log::error!("RustBridge.login proton failed: {}", e);
                        json!({
                            "status": "error",
                            "error": e
                        })
                        .to_string()
                    }
                }
            }
            Err(msg) => {
                log::warn!("RustBridge.login proton bad credentials payload: {}", msg);
                json!({
                    "status": "error",
                    "error": msg
                })
                .to_string()
            }
        },
        _ => {
            log::warn!(
                "RustBridge.login provider '{}' not implemented in JNI",
                provider_norm
            );
            json!({
                "status": "error",
                "error": format!("provider '{}' is not implemented on Android", provider_norm)
            })
            .to_string()
        }
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_logout(
    mut env: JNIEnv,
    _class: JClass,
    provider: JString,
) {
    ensure_logger();
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let provider_norm = provider.trim().to_ascii_lowercase();
    log::debug!("RustBridge.logout: provider={}", provider_norm);
    if provider_norm == "airvpn" {
        let mut state = AIRVPN_STATE.lock().unwrap();
        *state = None;
    } else if provider_norm == "proton" {
        let mut state = PROTON_STATE.lock().unwrap();
        *state = None;
    }
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_fetchServers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
) -> JString<'local> {
    ensure_logger();
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let provider_norm = provider.trim().to_ascii_lowercase();
    log::debug!("RustBridge.fetchServers: provider={}", provider_norm);

    let result = match provider_norm.as_str() {
        "airvpn" => {
            let state = AIRVPN_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => s.server_list_json.clone(),
                None => {
                    log::warn!("RustBridge.fetchServers airvpn without active session");
                    "[]".to_string()
                }
            }
        }
        "proton" => {
            let state = PROTON_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => s.server_list_json.clone(),
                None => {
                    log::warn!("RustBridge.fetchServers proton without active session");
                    "[]".to_string()
                }
            }
        }
        _ => "[]".to_string(),
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnListKeys<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JString<'local> {
    ensure_logger();
    let result = {
        let state = AIRVPN_STATE.lock().unwrap();
        if let Some(s) = state.as_ref() {
            let keys: Vec<Value> = s
                .keys
                .iter()
                .map(|k| {
                    json!({
                        "name": k.name,
                        "ipv4": k.wg_ipv4,
                        "ipv6": k.wg_ipv6
                    })
                })
                .collect();
            json!({
                "status": "ok",
                "selected": s.selected_key_name,
                "keys": keys
            })
            .to_string()
        } else {
            json!({
                "status": "error",
                "error": "AirVPN is not logged in"
            })
            .to_string()
        }
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnSelectKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    key_name: JString,
) -> JString<'local> {
    ensure_logger();
    let key_name: String = env
        .get_string(&key_name)
        .map(|s| s.into())
        .unwrap_or_default();

    let result = {
        let mut state = AIRVPN_STATE.lock().unwrap();
        if let Some(s) = state.as_mut() {
            match set_selected_airvpn_key(s, &key_name) {
                Ok(selected) => json!({
                    "status": "ok",
                    "selected": selected
                })
                .to_string(),
                Err(e) => json!({
                    "status": "error",
                    "error": e
                })
                .to_string(),
            }
        } else {
            json!({
                "status": "error",
                "error": "AirVPN is not logged in"
            })
            .to_string()
        }
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnListDevices<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JString<'local> {
    ensure_logger();
    let result = match airvpn_credentials() {
        Ok((username, password)) => {
            let devices_result: Result<_, String> = get_runtime().block_on(async {
                let web = AirVpnWeb::login_or_restore(&username, &password)
                    .await
                    .map_err(|e| e.to_string())?;
                let devices = web.list_devices().await.map_err(|e| e.to_string())?;
                web.save();
                Ok(devices)
            });

            match devices_result {
                Ok(devices) => {
                    let rows: Vec<Value> = devices
                        .iter()
                        .map(|d| {
                            json!({
                                "id": d.id,
                                "name": d.name,
                                "wg_public_key": d.wg_public_key,
                                "wg_ipv4": d.wg_ipv4,
                                "wg_ipv6": d.wg_ipv6
                            })
                        })
                        .collect();
                    json!({
                        "status": "ok",
                        "devices": rows
                    })
                    .to_string()
                }
                Err(e) => json!({
                    "status": "error",
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => json!({
            "status": "error",
            "error": e
        })
        .to_string(),
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnAddDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    name: JString,
) -> JString<'local> {
    ensure_logger();
    let name: String = env.get_string(&name).map(|s| s.into()).unwrap_or_default();
    let desired_name = name.trim().to_string();

    let result = match airvpn_credentials() {
        Ok((username, password)) => {
            let web_result: Result<_, String> = get_runtime().block_on(async {
                let web = AirVpnWeb::login_or_restore(&username, &password)
                    .await
                    .map_err(|e| e.to_string())?;
                let id = web.add_device().await.map_err(|e| e.to_string())?;
                if !desired_name.is_empty() {
                    web.rename_device(&id, &desired_name)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                let devices = web.list_devices().await.map_err(|e| e.to_string())?;
                web.save();
                let created_name = devices
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| d.name.clone())
                    .unwrap_or_else(|| desired_name.clone());
                Ok(created_name)
            });

            match web_result {
                Ok(created_name) => {
                    let mut state = AIRVPN_STATE.lock().unwrap();
                    if let Some(s) = state.as_mut() {
                        let update_result = refresh_airvpn_keys_in_state(s);
                        if let Err(e) = update_result {
                            json!({
                                "status": "error",
                                "error": e
                            })
                            .to_string()
                        } else {
                            if !created_name.is_empty() {
                                let _ = set_selected_airvpn_key(s, &created_name);
                            }
                            json!({
                                "status": "ok",
                                "created": created_name,
                                "selected": s.selected_key_name
                            })
                            .to_string()
                        }
                    } else {
                        json!({
                            "status": "error",
                            "error": "AirVPN is not logged in"
                        })
                        .to_string()
                    }
                }
                Err(e) => json!({
                    "status": "error",
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => json!({
            "status": "error",
            "error": e
        })
        .to_string(),
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnRenameDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    device: JString,
    name: JString,
) -> JString<'local> {
    ensure_logger();
    let old_name: String = env
        .get_string(&device)
        .map(|s| s.into())
        .unwrap_or_default();
    let new_name: String = env.get_string(&name).map(|s| s.into()).unwrap_or_default();

    if old_name.trim().is_empty() || new_name.trim().is_empty() {
        let err = json!({
            "status": "error",
            "error": "device and name are required"
        })
        .to_string();
        return env.new_string(err).expect("failed to create JString");
    }

    let result = match airvpn_credentials() {
        Ok((username, password)) => {
            let old_name_norm = old_name.trim().to_string();
            let new_name_norm = new_name.trim().to_string();

            let web_result: Result<_, String> = get_runtime().block_on(async {
                let web = AirVpnWeb::login_or_restore(&username, &password)
                    .await
                    .map_err(|e| e.to_string())?;
                let id = web
                    .lookup_device_id(&old_name_norm)
                    .await
                    .map_err(|e| e.to_string())?;
                web.rename_device(&id, &new_name_norm)
                    .await
                    .map_err(|e| e.to_string())?;
                web.save();
                Ok(())
            });

            match web_result {
                Ok(()) => {
                    let mut state = AIRVPN_STATE.lock().unwrap();
                    if let Some(s) = state.as_mut() {
                        let was_selected = s.selected_key_name.eq_ignore_ascii_case(&old_name_norm);
                        if let Err(e) = refresh_airvpn_keys_in_state(s) {
                            json!({
                                "status": "error",
                                "error": e
                            })
                            .to_string()
                        } else {
                            if was_selected {
                                let _ = set_selected_airvpn_key(s, &new_name_norm);
                            }
                            json!({
                                "status": "ok",
                                "selected": s.selected_key_name
                            })
                            .to_string()
                        }
                    } else {
                        json!({
                            "status": "error",
                            "error": "AirVPN is not logged in"
                        })
                        .to_string()
                    }
                }
                Err(e) => json!({
                    "status": "error",
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => json!({
            "status": "error",
            "error": e
        })
        .to_string(),
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_airvpnDeleteDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    device: JString,
) -> JString<'local> {
    ensure_logger();
    let device_name: String = env
        .get_string(&device)
        .map(|s| s.into())
        .unwrap_or_default();

    if device_name.trim().is_empty() {
        let err = json!({
            "status": "error",
            "error": "device is required"
        })
        .to_string();
        return env.new_string(err).expect("failed to create JString");
    }

    let result = match airvpn_credentials() {
        Ok((username, password)) => {
            let target = device_name.trim().to_string();
            let web_result: Result<_, String> = get_runtime().block_on(async {
                let web = AirVpnWeb::login_or_restore(&username, &password)
                    .await
                    .map_err(|e| e.to_string())?;
                let id = web
                    .lookup_device_id(&target)
                    .await
                    .map_err(|e| e.to_string())?;
                web.delete_device(&id).await.map_err(|e| e.to_string())?;
                web.save();
                Ok(())
            });

            match web_result {
                Ok(()) => {
                    let mut state = AIRVPN_STATE.lock().unwrap();
                    if let Some(s) = state.as_mut() {
                        if let Err(e) = refresh_airvpn_keys_in_state(s) {
                            json!({
                                "status": "error",
                                "error": e
                            })
                            .to_string()
                        } else {
                            json!({
                                "status": "ok",
                                "selected": s.selected_key_name
                            })
                            .to_string()
                        }
                    } else {
                        json!({
                            "status": "error",
                            "error": "AirVPN is not logged in"
                        })
                        .to_string()
                    }
                }
                Err(e) => json!({
                    "status": "error",
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => json!({
            "status": "error",
            "error": e
        })
        .to_string(),
    };

    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_getConnectionStatus<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JString<'local> {
    ensure_logger();
    let tunnel = TUNNEL_STATE.lock().unwrap();
    let status = if let Some(t) = tunnel.as_ref() {
        if t.data_plane_ready {
            let mut endpoint = t.endpoint.clone();
            let mut latest_handshake_age_secs: Option<u64> = None;
            let mut rx_bytes: Option<u64> = None;
            let mut tx_bytes: Option<u64> = None;

            if let Some(device) = t.wg_device.as_ref() {
                let peers =
                    get_runtime().block_on(async { device.read(async |d| d.peers().await).await });
                if let Some(peer_stats) = peers.into_iter().next() {
                    if let Some(peer_endpoint) = peer_stats.peer.endpoint {
                        endpoint = peer_endpoint.to_string();
                    }
                    latest_handshake_age_secs =
                        peer_stats.stats.last_handshake.map(|d| d.as_secs());
                    rx_bytes = Some(peer_stats.stats.rx_bytes as u64);
                    tx_bytes = Some(peer_stats.stats.tx_bytes as u64);
                }
            }

            json!({
                "state": "connected",
                "provider": t.provider,
                "backend": t.backend,
                "interface": t.interface_name,
                "server": t.selected_server,
                "selected_key": t.selected_key,
                "endpoint": endpoint,
                "peer_public_key": t.peer_public_key,
                "allowed_ips": t.allowed_ips,
                "addresses": t.addresses,
                "dns": t.dns_servers,
                "mtu": t.mtu,
                "keepalive_secs": t.keepalive_secs,
                "connected_since_epoch_secs": t.connected_since_epoch_secs,
                "latest_handshake_age_secs": latest_handshake_age_secs,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes
            })
            .to_string()
        } else {
            json!({
                "state": "degraded",
                "reason": "WireGuard data plane not ready"
            })
            .to_string()
        }
    } else {
        json!({
            "state": "disconnected"
        })
        .to_string()
    };
    env.new_string(status).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_createAccount<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
) -> JString<'local> {
    ensure_logger();
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let provider_norm = provider.trim().to_ascii_lowercase();

    let result = get_runtime().block_on(async {
        match provider_norm.as_str() {
            "mullvad" => create_account_mullvad().await,
            "ivpn" => create_account_ivpn().await,
            other => json!({
                "status": "error",
                "error": format!("create account not supported for '{}'", other)
            })
            .to_string(),
        }
    });

    env.new_string(result).expect("failed to create JString")
}

async fn create_account_mullvad() -> String {
    #[derive(serde::Deserialize)]
    struct Resp {
        number: String,
    }

    let client = match reqwest::Client::builder().user_agent("tunmux").build() {
        Ok(c) => c,
        Err(e) => return json!({"status": "error", "error": e.to_string()}).to_string(),
    };
    match client
        .post("https://api.mullvad.net/accounts/v1/accounts")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
            Ok(r) => json!({"status": "ok", "account_number": r.number}).to_string(),
            Err(e) => json!({"status": "error", "error": e.to_string()}).to_string(),
        },
        Ok(resp) => {
            let msg = resp.text().await.unwrap_or_default();
            json!({"status": "error", "error": msg}).to_string()
        }
        Err(e) => json!({"status": "error", "error": e.to_string()}).to_string(),
    }
}

async fn create_account_ivpn() -> String {
    #[derive(serde::Deserialize)]
    struct Account {
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        account: Account,
    }

    let client = match reqwest::Client::builder()
        .user_agent("tunmux")
        .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({"status": "error", "error": e.to_string()}).to_string(),
    };
    let body = serde_json::json!({"product": "IVPN Standard"});
    match client
        .post("https://www.ivpn.net/web/accounts/create")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
            Ok(r) => json!({"status": "ok", "account_id": r.account.id}).to_string(),
            Err(e) => json!({"status": "error", "error": e.to_string()}).to_string(),
        },
        Ok(resp) => {
            let msg = resp.text().await.unwrap_or_default();
            json!({"status": "error", "error": msg}).to_string()
        }
        Err(e) => json!({"status": "error", "error": e.to_string()}).to_string(),
    }
}

// ── Local proxy (no VpnService, no TUN) ───────────────────────────────────────

fn find_free_port(start: u16) -> Option<u16> {
    (start..=start + 100).find(|&p| std::net::TcpListener::bind(("127.0.0.1", p)).is_ok())
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_startLocalProxy<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
    server_json: JString,
    socks_port: jni::sys::jint,
    http_port: jni::sys::jint,
) -> JString<'local> {
    ensure_logger();

    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let server_json: String = env
        .get_string(&server_json)
        .map(|s| s.into())
        .unwrap_or_default();
    let provider_norm = provider.trim().to_ascii_lowercase();

    let cfg_result: Result<LocalProxyConfig, String> = (|| {
        if provider_norm != "airvpn" {
            return Err(format!(
                "local proxy not implemented for provider '{}'",
                provider_norm
            ));
        }
        let state = AIRVPN_STATE.lock().unwrap();
        let s = state
            .as_ref()
            .ok_or_else(|| "AirVPN is not logged in".to_string())?;
        let key = selected_airvpn_key(s)?;
        let wg_cfg =
            build_airvpn_runtime_config(s, key, &extract_selected_server_label(&server_json))?;

        let resolved_socks = if socks_port > 0 {
            socks_port as u16
        } else {
            find_free_port(1080).ok_or_else(|| "no free port for SOCKS5".to_string())?
        };
        let resolved_http = if http_port > 0 {
            http_port as u16
        } else {
            find_free_port(8118).ok_or_else(|| "no free port for HTTP proxy".to_string())?
        };

        let mut virtual_ips = Vec::new();
        if !key.wg_ipv4.is_empty() {
            virtual_ips.push(key.wg_ipv4.clone());
        }
        if !key.wg_ipv6.is_empty() {
            virtual_ips.push(key.wg_ipv6.clone());
        }

        Ok(LocalProxyConfig {
            private_key: wg_cfg.private_key,
            peer_public_key: wg_cfg.peer_public_key,
            preshared_key: wg_cfg.preshared_key,
            endpoint: wg_cfg.endpoint,
            virtual_ips,
            keepalive: wg_cfg.keepalive_secs,
            socks_port: resolved_socks,
            http_port: resolved_http,
        })
    })();

    let cfg = match cfg_result {
        Ok(c) => c,
        Err(e) => {
            log::error!("startLocalProxy: failed to build config: {}", e);
            let result = json!({"status": "error", "error": e}).to_string();
            return env.new_string(result).expect("failed to create JString");
        }
    };

    let actual_socks = cfg.socks_port;
    let actual_http = cfg.http_port;

    // Stop any existing local proxy task
    {
        let mut prev = LOCAL_PROXY_STATE.lock().unwrap();
        if let Some(h) = prev.take() {
            h.abort.abort();
        }
    }

    let runtime = get_runtime();
    let handle = runtime.spawn(async move {
        if let Err(e) = run_local_proxy(cfg).await {
            log::error!("local_proxy_exited; error={}", e);
        }
    });
    let abort = handle.abort_handle();

    {
        let mut state = LOCAL_PROXY_STATE.lock().unwrap();
        *state = Some(LocalProxyHandle {
            abort,
            socks_port: actual_socks,
            http_port: actual_http,
        });
    }

    log::info!(
        "startLocalProxy: socks={} http={}",
        actual_socks,
        actual_http
    );
    let result = json!({
        "status": "ok",
        "socks_port": actual_socks,
        "http_port": actual_http
    })
    .to_string();
    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_stopLocalProxy<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JString<'local> {
    ensure_logger();
    let mut state = LOCAL_PROXY_STATE.lock().unwrap();
    let stopped = if let Some(h) = state.take() {
        h.abort.abort();
        true
    } else {
        false
    };
    drop(state);
    log::info!("stopLocalProxy: stopped={}", stopped);
    let result = json!({"status": "ok", "stopped": stopped}).to_string();
    env.new_string(result).expect("failed to create JString")
}

use base64::Engine;
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use gotatun::x25519::{PublicKey, StaticSecret};
use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde_json::{json, Value};
use std::collections::HashMap;
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
use tunmux::ivpn::api as ivpn_api;
use tunmux::models::server::LogicalServer;
use tunmux::models::session::Session;
use tunmux::mullvad::api as mullvad_api;
use tunmux::wireguard::proxy_tunnel::{run_local_proxy, LocalProxyConfig};

static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();
static LOGGER_INIT: OnceLock<()> = OnceLock::new();
static TUNNEL_STATE: Mutex<Option<TunnelHandle>> = Mutex::new(None);
static APP_STATE: Mutex<Option<AppState>> = Mutex::new(None);
static AIRVPN_STATE: Mutex<Option<AirVpnAndroidState>> = Mutex::new(None);
static PROTON_STATE: Mutex<Option<ProtonAndroidState>> = Mutex::new(None);
static MULLVAD_STATE: Mutex<Option<MullvadAndroidState>> = Mutex::new(None);
static IVPN_STATE: Mutex<Option<IvpnAndroidState>> = Mutex::new(None);
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

struct ProtonAndroidState {
    username: String,
    session: Session,
    server_list_json: String,
    servers: Vec<LogicalServer>,
}

#[derive(Clone)]
struct MullvadAndroidState {
    account_number: String,
    access_token: String,
    device_id: String,
    wg_private_key: String,
    ipv4_address: String,
    ipv6_address: Option<String>,
    server_list_json: String,
    manifest: MullvadManifest,
}

#[derive(Clone)]
struct IvpnAndroidState {
    account_id: String,
    session_token: String,
    wg_private_key: String,
    wg_local_ip: String,
    server_list_json: String,
    manifest: IvpnManifest,
}

struct LoginCredentials {
    username: String,
    password: Option<String>,
    totp: Option<String>,
    device: Option<String>,
    api_key: Option<String>,
    api_uid: Option<String>,
    refresh_token: Option<String>,
    wg_private_key: Option<String>,
    wg_local_ip: Option<String>,
}

#[derive(Clone, serde::Deserialize)]
struct MullvadManifest {
    locations: HashMap<String, MullvadLocation>,
    wireguard: MullvadWireguard,
}

#[derive(Clone, serde::Deserialize)]
struct MullvadLocation {
    #[allow(dead_code)]
    country: String,
    city: String,
}

#[derive(Clone, serde::Deserialize)]
struct MullvadWireguard {
    relays: Vec<MullvadRelay>,
    port_ranges: Vec<(u16, u16)>,
    ipv4_gateway: String,
    #[serde(default)]
    ipv6_gateway: String,
}

#[derive(Clone, serde::Deserialize)]
struct MullvadRelay {
    hostname: String,
    location: String,
    active: bool,
    #[allow(dead_code)]
    provider: String,
    ipv4_addr_in: String,
    public_key: String,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnManifest {
    wireguard: Vec<IvpnWireGuardServer>,
    config: IvpnConfigInfo,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnWireGuardServer {
    gateway: String,
    country_code: String,
    #[allow(dead_code)]
    country: String,
    city: String,
    hosts: Vec<IvpnWireGuardHost>,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnWireGuardHost {
    hostname: String,
    dns_name: String,
    host: String,
    public_key: String,
    local_ip: String,
    #[serde(default)]
    load: f64,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnConfigInfo {
    ports: IvpnPortsInfo,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnPortsInfo {
    wireguard: Vec<IvpnPortInfo>,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnPortInfo {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    range: Option<IvpnPortRange>,
}

#[derive(Clone, serde::Deserialize)]
struct IvpnPortRange {
    min: u16,
    max: u16,
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
        "mullvad" => {
            let state = MULLVAD_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => {
                    let cfg = build_mullvad_tun_config(s);
                    let wg = match build_mullvad_runtime_config(s, &selected_server) {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!(
                                "nativeConnect: failed to build Mullvad WireGuard config: {e}"
                            );
                            return JNI_FALSE;
                        }
                    };
                    (cfg, wg, String::new())
                }
                None => {
                    log::error!("nativeConnect: no Mullvad login state");
                    return JNI_FALSE;
                }
            }
        }
        "ivpn" => {
            let state = IVPN_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => {
                    let (cfg, wg) = match build_ivpn_runtime_config(s, &selected_server) {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!(
                                "nativeConnect: failed to build IVPN WireGuard config: {e}"
                            );
                            return JNI_FALSE;
                        }
                    };
                    (cfg, wg, String::new())
                }
                None => {
                    log::error!("nativeConnect: no IVPN login state");
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
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

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

    let api_key = parsed
        .get("api_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    let api_uid = parsed
        .get("api_uid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    let refresh_token = parsed
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    let wg_private_key = parsed
        .get("wg_private_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    let wg_local_ip = parsed
        .get("wg_local_ip")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned);

    Ok(LoginCredentials {
        username,
        password,
        totp,
        device,
        api_key,
        api_uid,
        refresh_token,
        wg_private_key,
        wg_local_ip,
    })
}

fn parse_account_login_credential(credential: &str) -> Result<LoginCredentials, String> {
    parse_login_credentials(credential)
}

fn ensure_cidr(addr: &str, default_mask: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else {
        format!("{}{}", addr, default_mask)
    }
}

fn country_code_from_location(location: &str) -> String {
    location.split('-').next().unwrap_or("").to_uppercase()
}

fn choose_mullvad_port(ranges: &[(u16, u16)]) -> u16 {
    if ranges
        .iter()
        .any(|(start, end)| *start <= 51820 && 51820 <= *end)
    {
        return 51820;
    }
    if ranges
        .iter()
        .any(|(start, end)| *start <= 2049 && 2049 <= *end)
    {
        return 2049;
    }
    ranges.first().map(|(start, _)| *start).unwrap_or(51820)
}

fn format_mullvad_server_label(manifest: &MullvadManifest, relay: &MullvadRelay) -> String {
    let cc = country_code_from_location(&relay.location);
    let city = manifest
        .locations
        .get(&relay.location)
        .map(|l| l.city.as_str())
        .unwrap_or("unknown");
    format!("{} [{}] {}", relay.hostname, cc, city)
}

fn build_mullvad_server_list_json(manifest: &MullvadManifest) -> String {
    let mut labels: Vec<String> = manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .map(|r| format_mullvad_server_label(manifest, r))
        .collect();
    labels.sort();
    serde_json::to_string(&labels).unwrap_or_else(|_| "[]".to_string())
}

fn find_mullvad_relay<'a>(
    state: &'a MullvadAndroidState,
    selected_server_label: &str,
) -> Option<&'a MullvadRelay> {
    let trimmed = selected_server_label.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(found) = state
        .manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .find(|r| format_mullvad_server_label(&state.manifest, r) == trimmed)
    {
        return Some(found);
    }

    let name_hint = trimmed.split(" [").next().unwrap_or("").trim();
    if name_hint.is_empty() {
        None
    } else {
        state
            .manifest
            .wireguard
            .relays
            .iter()
            .filter(|r| r.active)
            .find(|r| r.hostname.eq_ignore_ascii_case(name_hint))
    }
}

fn build_mullvad_tun_config(state: &MullvadAndroidState) -> TunConfig {
    let mut cfg = default_tun_config();
    cfg.addresses = vec![ensure_cidr(&state.ipv4_address, "/32")];
    if let Some(ipv6) = &state.ipv6_address {
        if !ipv6.trim().is_empty() {
            cfg.addresses.push(ensure_cidr(ipv6.trim(), "/128"));
        }
    }

    cfg.routes = vec!["0.0.0.0/0".to_string()];
    if state.ipv6_address.is_some() {
        cfg.routes.push("::/0".to_string());
    }

    cfg.dns_servers.clear();
    if !state.manifest.wireguard.ipv4_gateway.is_empty() {
        cfg.dns_servers
            .push(state.manifest.wireguard.ipv4_gateway.clone());
    }
    if !state.manifest.wireguard.ipv6_gateway.is_empty() {
        cfg.dns_servers
            .push(state.manifest.wireguard.ipv6_gateway.clone());
    }
    if cfg.dns_servers.is_empty() {
        cfg.dns_servers = default_tun_config().dns_servers;
    }
    cfg
}

fn build_mullvad_runtime_config(
    state: &MullvadAndroidState,
    selected_server_label: &str,
) -> Result<WireGuardRuntimeConfig, String> {
    let selected = if selected_server_label.is_empty() {
        None
    } else {
        find_mullvad_relay(state, selected_server_label)
    };
    let used_fallback = selected.is_none();
    let mut active_relays: Vec<&MullvadRelay> = state
        .manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .collect();
    active_relays.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let relay = selected
        .or_else(|| active_relays.first().copied())
        .ok_or_else(|| "no Mullvad servers available".to_string())?;
    if used_fallback && !selected_server_label.is_empty() {
        log::warn!(
            "nativeConnect: selected server '{}' not found, falling back to '{}'",
            selected_server_label,
            relay.hostname
        );
    }

    let endpoint_ip: IpAddr = relay.ipv4_addr_in.parse().map_err(|e| {
        format!(
            "invalid Mullvad endpoint IP '{}': {}",
            relay.ipv4_addr_in, e
        )
    })?;
    let private_key = decode_key32("wg_private_key", &state.wg_private_key)?;
    let peer_public_key = decode_key32("server_public_key", &relay.public_key)?;

    Ok(WireGuardRuntimeConfig {
        server_name: relay.hostname.clone(),
        endpoint: SocketAddr::new(
            endpoint_ip,
            choose_mullvad_port(&state.manifest.wireguard.port_ranges),
        ),
        private_key,
        peer_public_key,
        preshared_key: None,
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        keepalive_secs: None,
    })
}

fn format_ivpn_server_label(server: &IvpnWireGuardServer, host: &IvpnWireGuardHost) -> String {
    format!(
        "{} [{}] {}",
        host.hostname, server.country_code, server.city
    )
}

fn choose_ivpn_port(ports: &[IvpnPortInfo]) -> u16 {
    for preferred in [2049u16, 51820u16, 443u16, 53u16] {
        if ports
            .iter()
            .any(|p| p.kind.eq_ignore_ascii_case("udp") && ivpn_port_matches(p, preferred))
        {
            return preferred;
        }
    }

    if let Some(port) = ports
        .iter()
        .find(|p| p.kind.eq_ignore_ascii_case("udp") && p.port.unwrap_or(0) > 0)
        .and_then(|p| p.port)
    {
        return port;
    }

    if let Some(min) = ports
        .iter()
        .find(|p| p.kind.eq_ignore_ascii_case("udp") && p.range.is_some())
        .and_then(|p| p.range.as_ref().map(|r| r.min))
    {
        return min;
    }

    2049
}

fn ivpn_port_matches(port: &IvpnPortInfo, value: u16) -> bool {
    if let Some(p) = port.port {
        return p == value;
    }
    if let Some(range) = &port.range {
        return range.min <= value && value <= range.max;
    }
    false
}

fn build_ivpn_server_list_json(manifest: &IvpnManifest) -> String {
    let mut rows: Vec<(String, f64)> = Vec::new();
    for server in &manifest.wireguard {
        for host in &server.hosts {
            rows.push((format_ivpn_server_label(server, host), host.load));
        }
    }
    rows.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let labels: Vec<String> = rows.into_iter().map(|(label, _)| label).collect();
    serde_json::to_string(&labels).unwrap_or_else(|_| "[]".to_string())
}

fn find_ivpn_host<'a>(
    state: &'a IvpnAndroidState,
    selected_server_label: &str,
) -> Option<(&'a IvpnWireGuardServer, &'a IvpnWireGuardHost)> {
    let trimmed = selected_server_label.trim();
    if trimmed.is_empty() {
        return None;
    }

    for server in &state.manifest.wireguard {
        for host in &server.hosts {
            if format_ivpn_server_label(server, host) == trimmed {
                return Some((server, host));
            }
            if host.hostname.eq_ignore_ascii_case(trimmed)
                || host.dns_name.eq_ignore_ascii_case(trimmed)
            {
                return Some((server, host));
            }
        }
        if server.gateway.eq_ignore_ascii_case(trimmed) {
            let best = server.hosts.iter().min_by(|a, b| {
                a.load
                    .partial_cmp(&b.load)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            if let Some(host) = best {
                return Some((server, host));
            }
        }
    }

    let name_hint = trimmed.split(" [").next().unwrap_or("").trim();
    if name_hint.is_empty() {
        None
    } else {
        for server in &state.manifest.wireguard {
            if let Some(host) = server.hosts.iter().find(|h| {
                h.hostname.eq_ignore_ascii_case(name_hint)
                    || h.dns_name.eq_ignore_ascii_case(name_hint)
            }) {
                return Some((server, host));
            }
        }
        None
    }
}

fn build_ivpn_runtime_config(
    state: &IvpnAndroidState,
    selected_server_label: &str,
) -> Result<(TunConfig, WireGuardRuntimeConfig), String> {
    let selected = if selected_server_label.is_empty() {
        None
    } else {
        find_ivpn_host(state, selected_server_label)
    };
    let used_fallback = selected.is_none();

    let mut rows: Vec<(&IvpnWireGuardServer, &IvpnWireGuardHost)> = Vec::new();
    for server in &state.manifest.wireguard {
        for host in &server.hosts {
            rows.push((server, host));
        }
    }
    rows.sort_by(|a, b| {
        a.1.load
            .partial_cmp(&b.1.load)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let (server, host) = selected
        .or_else(|| rows.first().copied())
        .ok_or_else(|| "no IVPN servers available".to_string())?;
    if used_fallback && !selected_server_label.is_empty() {
        log::warn!(
            "nativeConnect: selected server '{}' not found, falling back to '{}'",
            selected_server_label,
            host.hostname
        );
    }

    let local_ip_no_mask = state
        .wg_local_ip
        .split('/')
        .next()
        .unwrap_or(&state.wg_local_ip)
        .to_string();
    let dns_ip = host
        .local_ip
        .split('/')
        .next()
        .unwrap_or("10.0.0.1")
        .to_string();
    let tun_config = TunConfig {
        addresses: vec![ensure_cidr(&local_ip_no_mask, "/32")],
        routes: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        dns_servers: vec![dns_ip],
        mtu: 1500,
    };

    let endpoint_ip: IpAddr = host
        .host
        .parse()
        .map_err(|e| format!("invalid IVPN endpoint IP '{}': {}", host.host, e))?;
    let private_key = decode_key32("wg_private_key", &state.wg_private_key)?;
    let peer_public_key = decode_key32("server_public_key", &host.public_key)?;

    let cfg = WireGuardRuntimeConfig {
        server_name: format!("{} ({})", host.hostname, server.country_code),
        endpoint: SocketAddr::new(
            endpoint_ip,
            choose_ivpn_port(&state.manifest.config.ports.wireguard),
        ),
        private_key,
        peer_public_key,
        preshared_key: None,
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        keepalive_secs: None,
    };
    Ok((tun_config, cfg))
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

async fn login_proton_with_password(
    username: &str,
    password: &str,
    totp: Option<&str>,
) -> Result<ProtonAndroidState, String> {
    let mut client = api::http::ProtonClient::new().map_err(|e| e.to_string())?;
    let auth = api::auth::login(&mut client, username, password)
        .await
        .map_err(|e| e.to_string())?;

    if auth.two_factor.totp_required() {
        let code = totp.map(str::trim).unwrap_or("");
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
        username: username.to_string(),
        session,
        server_list_json,
        servers,
    })
}

async fn login_proton_with_api_key(
    username: &str,
    uid: &str,
    access_token: &str,
    refresh_token: Option<&str>,
) -> Result<ProtonAndroidState, String> {
    let client =
        api::http::ProtonClient::authenticated(uid, access_token).map_err(|e| e.to_string())?;
    let vpn_info = api::vpn_info::fetch_vpn_info(&client)
        .await
        .map_err(|e| e.to_string())?;
    let keys = crypto::keys::VpnKeys::generate().map_err(|e| e.to_string())?;
    let cert = api::certificate::fetch_certificate(&client, &keys.ed25519_pk_pem())
        .await
        .map_err(|e| e.to_string())?;
    let session = Session {
        uid: uid.to_string(),
        access_token: access_token.to_string(),
        refresh_token: refresh_token.unwrap_or("").to_string(),
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
        username: username.to_string(),
        session,
        server_list_json,
        servers,
    })
}

async fn login_mullvad(
    account_number: &str,
    api_key: Option<&str>,
) -> Result<MullvadAndroidState, String> {
    let data = if let Some(token) = api_key.filter(|v| !v.trim().is_empty()) {
        match mullvad_api::login_with_access_token(account_number, token).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "Mullvad api_key login failed; falling back to account auth: {}",
                    e
                );
                mullvad_api::login(account_number)
                    .await
                    .map_err(|e| e.to_string())?
            }
        }
    } else {
        mullvad_api::login(account_number)
            .await
            .map_err(|e| e.to_string())?
    };
    let manifest_json = serde_json::to_value(&data.manifest).map_err(|e| e.to_string())?;
    let manifest: MullvadManifest =
        serde_json::from_value(manifest_json).map_err(|e| e.to_string())?;
    let server_list_json = build_mullvad_server_list_json(&manifest);
    if server_list_json == "[]" {
        return Err("no Mullvad WireGuard servers available".to_string());
    }

    Ok(MullvadAndroidState {
        account_number: data.account_number,
        access_token: data.access_token,
        device_id: data.device_id,
        wg_private_key: data.wg_private_key,
        ipv4_address: data.ipv4_address,
        ipv6_address: data.ipv6_address,
        server_list_json,
        manifest,
    })
}

async fn login_ivpn(
    account_id: &str,
    totp: Option<&str>,
    api_key: Option<&str>,
    wg_private_key: Option<&str>,
    wg_local_ip: Option<&str>,
) -> Result<IvpnAndroidState, String> {
    let data = if let (Some(token), Some(private_key), Some(local_ip)) = (
        api_key.filter(|v| !v.trim().is_empty()),
        wg_private_key.filter(|v| !v.trim().is_empty()),
        wg_local_ip.filter(|v| !v.trim().is_empty()),
    ) {
        match ivpn_api::restore_session(account_id, token, private_key, local_ip).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "IVPN api_key restore failed; falling back to account auth: {}",
                    e
                );
                ivpn_api::login(account_id, totp)
                    .await
                    .map_err(|e| e.to_string())?
            }
        }
    } else {
        ivpn_api::login(account_id, totp)
            .await
            .map_err(|e| e.to_string())?
    };
    let manifest_json = serde_json::to_value(&data.manifest).map_err(|e| e.to_string())?;
    let manifest: IvpnManifest =
        serde_json::from_value(manifest_json).map_err(|e| e.to_string())?;
    let server_list_json = build_ivpn_server_list_json(&manifest);
    if server_list_json == "[]" {
        return Err("no IVPN WireGuard servers available".to_string());
    }

    Ok(IvpnAndroidState {
        account_id: data.account_id,
        session_token: data.session_token,
        wg_private_key: data.wg_private_key,
        wg_local_ip: data.wg_local_ip,
        server_list_json,
        manifest,
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
                let password = match login_credentials.password {
                    Some(v) => v,
                    None => {
                        return env
                            .new_string(
                                json!({
                                    "status": "error",
                                    "error": "missing password"
                                })
                                .to_string(),
                            )
                            .expect("failed to create JString");
                    }
                };
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
                let login_result = get_runtime().block_on(async {
                    if let (Some(api_uid), Some(api_key)) = (
                        login_credentials.api_uid.as_deref(),
                        login_credentials.api_key.as_deref(),
                    ) {
                        match login_proton_with_api_key(
                            &login_credentials.username,
                            api_uid,
                            api_key,
                            login_credentials.refresh_token.as_deref(),
                        )
                        .await
                        {
                            Ok(v) => Ok(v),
                            Err(e) => {
                                log::warn!("Proton api_key login failed; falling back to password login: {}", e);
                                let password = login_credentials.password.as_deref().unwrap_or("").trim();
                                if password.is_empty() {
                                    Err(e)
                                } else {
                                    login_proton_with_password(
                                        &login_credentials.username,
                                        password,
                                        login_credentials.totp.as_deref(),
                                    )
                                    .await
                                }
                            }
                        }
                    } else {
                        let password = login_credentials.password.as_deref().unwrap_or("").trim();
                        if password.is_empty() {
                            Err("missing password".to_string())
                        } else {
                            login_proton_with_password(
                                &login_credentials.username,
                                password,
                                login_credentials.totp.as_deref(),
                            )
                            .await
                        }
                    }
                });
                match login_result {
                    Ok(login_data) => {
                        let servers = login_data.servers.len();
                        let username = login_data.username.clone();
                        let plan_title = login_data.session.plan_title.clone();
                        let max_tier = login_data.session.max_tier;
                        let max_connections = login_data.session.max_connections;
                        let api_key = login_data.session.access_token.clone();
                        let api_uid = login_data.session.uid.clone();
                        let refresh_token = login_data.session.refresh_token.clone();
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
                            "servers": servers,
                            "api_key": api_key,
                            "api_uid": api_uid,
                            "refresh_token": refresh_token
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
        "mullvad" => match parse_account_login_credential(&_credential) {
            Ok(login_credentials) => {
                let account_number = login_credentials.username;
                let login_result = get_runtime().block_on(login_mullvad(
                    &account_number,
                    login_credentials.api_key.as_deref(),
                ));
                match login_result {
                    Ok(login_data) => {
                        let servers = login_data
                            .manifest
                            .wireguard
                            .relays
                            .iter()
                            .filter(|r| r.active)
                            .count();
                        let account = login_data.account_number.clone();
                        let api_key = login_data.access_token.clone();
                        let mut state = MULLVAD_STATE.lock().unwrap();
                        *state = Some(login_data);
                        log::info!(
                            "RustBridge.login mullvad success: account={} servers={}",
                            account,
                            servers
                        );
                        json!({
                            "status": "ok",
                            "provider": "mullvad",
                            "account": account,
                            "servers": servers,
                            "api_key": api_key
                        })
                        .to_string()
                    }
                    Err(e) => {
                        log::error!("RustBridge.login mullvad failed: {}", e);
                        json!({
                            "status": "error",
                            "error": e
                        })
                        .to_string()
                    }
                }
            }
            Err(msg) => {
                log::warn!("RustBridge.login mullvad bad credentials payload: {}", msg);
                json!({
                    "status": "error",
                    "error": msg
                })
                .to_string()
            }
        },
        "ivpn" => match parse_account_login_credential(&_credential) {
            Ok(login_credentials) => {
                let account_id = login_credentials.username;
                let login_result = get_runtime().block_on(login_ivpn(
                    &account_id,
                    login_credentials.totp.as_deref(),
                    login_credentials.api_key.as_deref(),
                    login_credentials.wg_private_key.as_deref(),
                    login_credentials.wg_local_ip.as_deref(),
                ));
                match login_result {
                    Ok(login_data) => {
                        let mut servers = 0usize;
                        for server in &login_data.manifest.wireguard {
                            servers += server.hosts.len();
                        }
                        let account = login_data.account_id.clone();
                        let api_key = login_data.session_token.clone();
                        let wg_private_key = login_data.wg_private_key.clone();
                        let wg_local_ip = login_data.wg_local_ip.clone();
                        let mut state = IVPN_STATE.lock().unwrap();
                        *state = Some(login_data);
                        log::info!(
                            "RustBridge.login ivpn success: account={} servers={}",
                            account,
                            servers
                        );
                        json!({
                            "status": "ok",
                            "provider": "ivpn",
                            "account": account,
                            "servers": servers,
                            "api_key": api_key,
                            "wg_private_key": wg_private_key,
                            "wg_local_ip": wg_local_ip
                        })
                        .to_string()
                    }
                    Err(e) => {
                        log::error!("RustBridge.login ivpn failed: {}", e);
                        json!({
                            "status": "error",
                            "error": e
                        })
                        .to_string()
                    }
                }
            }
            Err(msg) => {
                log::warn!("RustBridge.login ivpn bad credentials payload: {}", msg);
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
    } else if provider_norm == "mullvad" {
        let previous = {
            let mut state = MULLVAD_STATE.lock().unwrap();
            state.take()
        };
        if let Some(s) = previous {
            let _ =
                get_runtime().block_on(mullvad_api::delete_device(&s.account_number, &s.device_id));
        }
    } else if provider_norm == "ivpn" {
        let previous = {
            let mut state = IVPN_STATE.lock().unwrap();
            state.take()
        };
        if let Some(s) = previous {
            let _ = get_runtime().block_on(ivpn_api::delete_session(&s.session_token));
        }
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
        "mullvad" => {
            let state = MULLVAD_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => s.server_list_json.clone(),
                None => {
                    log::warn!("RustBridge.fetchServers mullvad without active session");
                    "[]".to_string()
                }
            }
        }
        "ivpn" => {
            let state = IVPN_STATE.lock().unwrap();
            match state.as_ref() {
                Some(s) => s.server_list_json.clone(),
                None => {
                    log::warn!("RustBridge.fetchServers ivpn without active session");
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

use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use std::os::unix::io::RawFd;
use std::sync::{Mutex, OnceLock};
use tokio::runtime::Runtime;

static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TUNNEL_STATE: Mutex<Option<TunnelHandle>> = Mutex::new(None);
static APP_STATE: Mutex<Option<AppState>> = Mutex::new(None);

struct AppState {
    jvm: JavaVM,
    service_ref: GlobalRef,
    #[allow(dead_code)]
    files_dir: String,
}

struct TunnelHandle {
    tun_fd: RawFd,
}

fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime init failed")
    })
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeInitialize(
    mut env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    files_dir: JString,
) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("tunmux"),
    );

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

    log::info!("tunmux native initialized");
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeShutdown(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut tunnel = TUNNEL_STATE.lock().unwrap();
    *tunnel = None;
    let mut state = APP_STATE.lock().unwrap();
    *state = None;
    log::info!("tunmux native shutdown");
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    provider: JString,
    server_json: JString,
) -> jboolean {
    let provider: String = match env.get_string(&provider) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let _server_json: String = match env.get_string(&server_json) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    log::info!("nativeConnect called; provider={}", provider);

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
        open_tun_fd(&app_state.jvm, &app_state.service_ref)
    };

    let fd = match tun_fd {
        Ok(fd) if fd >= 0 => fd,
        Ok(_) | Err(_) => {
            log::error!("nativeConnect: failed to open TUN fd");
            return JNI_FALSE;
        }
    };

    let mut tunnel = TUNNEL_STATE.lock().unwrap();
    *tunnel = Some(TunnelHandle { tun_fd: fd });

    log::info!("nativeConnect: tunnel established, tun_fd={}", fd);
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_TunmuxVpnService_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut tunnel = TUNNEL_STATE.lock().unwrap();
    if let Some(handle) = tunnel.take() {
        // Close the TUN fd
        unsafe {
            libc::close(handle.tun_fd);
        }
        log::info!("nativeDisconnect: tunnel closed");
    }
}

fn open_tun_fd(jvm: &JavaVM, service_ref: &GlobalRef) -> Result<RawFd, String> {
    let mut env = jvm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread failed: {e}"))?;

    // addresses, routes, dns, mtu -- use defaults for now
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

    let result = env
        .call_method(
            service_ref.as_obj(),
            "openTun",
            "(Ljava/util/List;Ljava/util/List;Ljava/util/List;I)I",
            &[
                (&addresses).into(),
                (&routes).into(),
                (&dns).into(),
                jni::objects::JValueGen::Int(1500),
            ],
        )
        .map_err(|e| format!("openTun call failed: {e}"))?;

    match result {
        jni::objects::JValueGen::Int(fd) => Ok(fd as RawFd),
        _ => Err("openTun returned unexpected type".to_string()),
    }
}

// Provider operations (called from UI via RustBridge)

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_login<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
    credential: JString,
) -> JString<'local> {
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    let _credential: String = env
        .get_string(&credential)
        .map(|s| s.into())
        .unwrap_or_default();

    log::info!("RustBridge.login: provider={}", provider);

    let result = r#"{"status":"ok"}"#;
    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_logout(
    mut env: JNIEnv,
    _class: JClass,
    provider: JString,
) {
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    log::info!("RustBridge.logout: provider={}", provider);
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_fetchServers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    provider: JString,
) -> JString<'local> {
    let provider: String = env
        .get_string(&provider)
        .map(|s| s.into())
        .unwrap_or_default();
    log::info!("RustBridge.fetchServers: provider={}", provider);

    let result = "[]";
    env.new_string(result).expect("failed to create JString")
}

#[no_mangle]
pub extern "system" fn Java_net_tunmux_RustBridge_getConnectionStatus<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JString<'local> {
    let tunnel = TUNNEL_STATE.lock().unwrap();
    let status = if tunnel.is_some() {
        r#"{"state":"connected"}"#
    } else {
        r#"{"state":"disconnected"}"#
    };
    env.new_string(status).expect("failed to create JString")
}

// Suppress unused warning for get_runtime -- it will be used when actual
// async provider calls are wired up.
#[allow(dead_code)]
fn _use_runtime() {
    let _ = get_runtime();
}

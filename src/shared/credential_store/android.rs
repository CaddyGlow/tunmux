use crate::config::Provider;
use crate::error::Result;

const BACKEND: &str = "android_keystore";

#[cfg(target_os = "android")]
type SaveCallback = dyn Fn(Provider, &str) -> std::result::Result<(), String> + Send + Sync;
#[cfg(target_os = "android")]
type LoadCallback = dyn Fn(Provider) -> std::result::Result<Option<String>, String> + Send + Sync;
#[cfg(target_os = "android")]
type DeleteCallback = dyn Fn(Provider) -> std::result::Result<(), String> + Send + Sync;

#[cfg(target_os = "android")]
pub struct AndroidCredentialCallbacks {
    pub save: Box<SaveCallback>,
    pub load: Box<LoadCallback>,
    pub delete: Box<DeleteCallback>,
}

#[cfg(target_os = "android")]
static CALLBACKS: std::sync::OnceLock<std::sync::Mutex<Option<AndroidCredentialCallbacks>>> =
    std::sync::OnceLock::new();

#[cfg(target_os = "android")]
pub fn register_android_callbacks(callbacks: AndroidCredentialCallbacks) {
    let slot = CALLBACKS.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = slot
        .lock()
        .expect("android credential callback lock poisoned");
    *guard = Some(callbacks);
}

#[cfg(target_os = "android")]
pub(super) fn save(provider: Provider, payload_json: &str) -> Result<()> {
    let slot = CALLBACKS.get().ok_or_else(|| {
        super::misconfigured(provider, BACKEND, "save", "callback hook is not registered")
    })?;
    let guard = slot
        .lock()
        .map_err(|_| super::misconfigured(provider, BACKEND, "save", "callback lock poisoned"))?;
    let callbacks = guard.as_ref().ok_or_else(|| {
        super::misconfigured(provider, BACKEND, "save", "callback hook is not registered")
    })?;
    (callbacks.save)(provider, payload_json)
        .map_err(|reason| super::failure(provider, BACKEND, "save", &reason))
}

#[cfg(not(target_os = "android"))]
pub(super) fn save(provider: Provider, _payload_json: &str) -> Result<()> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "save",
        "android keystore backend is only available on Android",
    ))
}

#[cfg(target_os = "android")]
pub(super) fn load(provider: Provider) -> Result<Option<String>> {
    let slot = CALLBACKS.get().ok_or_else(|| {
        super::misconfigured(provider, BACKEND, "load", "callback hook is not registered")
    })?;
    let guard = slot
        .lock()
        .map_err(|_| super::misconfigured(provider, BACKEND, "load", "callback lock poisoned"))?;
    let callbacks = guard.as_ref().ok_or_else(|| {
        super::misconfigured(provider, BACKEND, "load", "callback hook is not registered")
    })?;
    (callbacks.load)(provider).map_err(|reason| super::failure(provider, BACKEND, "load", &reason))
}

#[cfg(not(target_os = "android"))]
pub(super) fn load(provider: Provider) -> Result<Option<String>> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "load",
        "android keystore backend is only available on Android",
    ))
}

#[cfg(target_os = "android")]
pub(super) fn delete(provider: Provider) -> Result<()> {
    let slot = CALLBACKS.get().ok_or_else(|| {
        super::misconfigured(
            provider,
            BACKEND,
            "delete",
            "callback hook is not registered",
        )
    })?;
    let guard = slot
        .lock()
        .map_err(|_| super::misconfigured(provider, BACKEND, "delete", "callback lock poisoned"))?;
    let callbacks = guard.as_ref().ok_or_else(|| {
        super::misconfigured(
            provider,
            BACKEND,
            "delete",
            "callback hook is not registered",
        )
    })?;
    (callbacks.delete)(provider)
        .map_err(|reason| super::failure(provider, BACKEND, "delete", &reason))
}

#[cfg(not(target_os = "android"))]
pub(super) fn delete(provider: Provider) -> Result<()> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "delete",
        "android keystore backend is only available on Android",
    ))
}

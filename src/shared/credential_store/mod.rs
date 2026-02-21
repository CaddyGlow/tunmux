mod android;
mod file;
mod keyring;

use crate::config::{AppConfig, CredentialStore, Provider};
use crate::error::{AppError, Result};

#[cfg(target_os = "android")]
pub use android::{register_android_callbacks, AndroidCredentialCallbacks};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedCredentialBackend {
    File,
    Keyring,
    AndroidKeystore,
}

pub fn save_session_json(provider: Provider, payload_json: &str, config: &AppConfig) -> Result<()> {
    match resolve_backend(config) {
        ResolvedCredentialBackend::File => file::save(provider, payload_json),
        ResolvedCredentialBackend::Keyring => keyring::save(provider, payload_json),
        ResolvedCredentialBackend::AndroidKeystore => android::save(provider, payload_json),
    }
}

pub fn load_session_json(provider: Provider, config: &AppConfig) -> Result<Option<String>> {
    match resolve_backend(config) {
        ResolvedCredentialBackend::File => file::load(provider),
        ResolvedCredentialBackend::Keyring => keyring::load(provider),
        ResolvedCredentialBackend::AndroidKeystore => android::load(provider),
    }
}

pub fn delete_session_json(provider: Provider, config: &AppConfig) -> Result<()> {
    match resolve_backend(config) {
        ResolvedCredentialBackend::File => file::delete(provider),
        ResolvedCredentialBackend::Keyring => keyring::delete(provider),
        ResolvedCredentialBackend::AndroidKeystore => android::delete(provider),
    }
}

fn resolve_backend(config: &AppConfig) -> ResolvedCredentialBackend {
    match config.general.credential_store {
        CredentialStore::File => ResolvedCredentialBackend::File,
        CredentialStore::Keyring => ResolvedCredentialBackend::Keyring,
        CredentialStore::AndroidKeystore => ResolvedCredentialBackend::AndroidKeystore,
        CredentialStore::Auto => {
            #[cfg(target_os = "android")]
            {
                ResolvedCredentialBackend::AndroidKeystore
            }
            #[cfg(all(not(target_os = "android"), feature = "keyring"))]
            {
                ResolvedCredentialBackend::Keyring
            }
            #[cfg(all(not(target_os = "android"), not(feature = "keyring")))]
            {
                ResolvedCredentialBackend::File
            }
        }
    }
}

fn unavailable(provider: Provider, backend: &str, operation: &str, reason: &str) -> AppError {
    AppError::CredentialStoreUnavailable(format_message(provider, backend, operation, reason))
}

fn misconfigured(provider: Provider, backend: &str, operation: &str, reason: &str) -> AppError {
    AppError::CredentialStoreMisconfigured(format_message(provider, backend, operation, reason))
}

fn failure(provider: Provider, backend: &str, operation: &str, reason: &str) -> AppError {
    AppError::CredentialStoreFailure(format_message(provider, backend, operation, reason))
}

fn format_message(provider: Provider, backend: &str, operation: &str, reason: &str) -> String {
    format!(
        "provider={} backend={} operation={} reason={}",
        provider.dir_name(),
        backend,
        operation,
        reason
    )
}

#[cfg(test)]
mod tests {
    use super::{resolve_backend, ResolvedCredentialBackend};
    use crate::config::{AppConfig, CredentialStore};

    #[test]
    fn test_resolver_explicit_values() {
        let mut cfg = AppConfig::default();

        cfg.general.credential_store = CredentialStore::File;
        assert_eq!(resolve_backend(&cfg), ResolvedCredentialBackend::File);

        cfg.general.credential_store = CredentialStore::Keyring;
        assert_eq!(resolve_backend(&cfg), ResolvedCredentialBackend::Keyring);

        cfg.general.credential_store = CredentialStore::AndroidKeystore;
        assert_eq!(
            resolve_backend(&cfg),
            ResolvedCredentialBackend::AndroidKeystore
        );
    }

    #[test]
    fn test_resolver_auto() {
        let mut cfg = AppConfig::default();
        cfg.general.credential_store = CredentialStore::Auto;

        #[cfg(target_os = "android")]
        assert_eq!(
            resolve_backend(&cfg),
            ResolvedCredentialBackend::AndroidKeystore
        );

        #[cfg(all(not(target_os = "android"), feature = "keyring"))]
        assert_eq!(resolve_backend(&cfg), ResolvedCredentialBackend::Keyring);

        #[cfg(all(not(target_os = "android"), not(feature = "keyring")))]
        assert_eq!(resolve_backend(&cfg), ResolvedCredentialBackend::File);
    }
}

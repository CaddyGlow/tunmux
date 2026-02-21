use crate::config::Provider;
use crate::error::Result;

const BACKEND: &str = "keyring";

#[cfg(feature = "keyring")]
pub(super) fn save(provider: Provider, payload_json: &str) -> Result<()> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| super::unavailable(provider, BACKEND, "save", &e.to_string()))?;
    entry
        .set_password(payload_json)
        .map_err(|e| classify(provider, "save", e))?;
    tracing::info!( provider = ?provider.dir_name(), "session_saved_keyring");
    Ok(())
}

#[cfg(not(feature = "keyring"))]
pub(super) fn save(provider: Provider, _payload_json: &str) -> Result<()> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "save",
        "keyring backend not compiled (enable feature=keyring)",
    ))
}

#[cfg(feature = "keyring")]
pub(super) fn load(provider: Provider) -> Result<Option<String>> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| super::unavailable(provider, BACKEND, "load", &e.to_string()))?;
    match entry.get_password() {
        Ok(json) => Ok(Some(json)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(classify(provider, "load", e)),
    }
}

#[cfg(not(feature = "keyring"))]
pub(super) fn load(provider: Provider) -> Result<Option<String>> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "load",
        "keyring backend not compiled (enable feature=keyring)",
    ))
}

#[cfg(feature = "keyring")]
pub(super) fn delete(provider: Provider) -> Result<()> {
    let entry = keyring::Entry::new("tunmux", provider.dir_name())
        .map_err(|e| super::unavailable(provider, BACKEND, "delete", &e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {
            tracing::info!( provider = ?provider.dir_name(), "session_deleted_keyring");
            Ok(())
        }
        Err(e) => Err(classify(provider, "delete", e)),
    }
}

#[cfg(not(feature = "keyring"))]
pub(super) fn delete(provider: Provider) -> Result<()> {
    Err(super::unavailable(
        provider,
        BACKEND,
        "delete",
        "keyring backend not compiled (enable feature=keyring)",
    ))
}

#[cfg(feature = "keyring")]
fn classify(provider: Provider, operation: &str, error: keyring::Error) -> crate::error::AppError {
    match error {
        keyring::Error::NoStorageAccess(e) => {
            super::unavailable(provider, BACKEND, operation, &e.to_string())
        }
        other => super::failure(provider, BACKEND, operation, &other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "keyring")]
    use super::{delete, load, save};
    #[cfg(not(feature = "keyring"))]
    use super::{delete, load, save};
    #[cfg(feature = "keyring")]
    use crate::config::Provider;
    #[cfg(not(feature = "keyring"))]
    use crate::config::Provider;
    #[cfg(feature = "keyring")]
    use crate::error::AppError;
    #[cfg(not(feature = "keyring"))]
    use crate::error::AppError;

    #[cfg(feature = "keyring")]
    fn unique_payload() -> String {
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{{\"k\":\"{}-{}\"}}", std::process::id(), now_nanos)
    }

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn test_keyring_backend_unavailable_without_feature() {
        let save_err = save(Provider::Proton, "{}").expect_err("save should fail without feature");
        let load_err = load(Provider::Proton).expect_err("load should fail without feature");
        let delete_err = delete(Provider::Proton).expect_err("delete should fail without feature");

        assert!(matches!(save_err, AppError::CredentialStoreUnavailable(_)));
        assert!(matches!(load_err, AppError::CredentialStoreUnavailable(_)));
        assert!(matches!(
            delete_err,
            AppError::CredentialStoreUnavailable(_)
        ));
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn test_keyring_backend_roundtrip_or_unavailable() {
        let provider = Provider::Proton;
        let payload = unique_payload();

        match save(provider, &payload) {
            Ok(()) => {}
            Err(AppError::CredentialStoreUnavailable(_)) => return,
            Err(other) => panic!("unexpected save error: {other}"),
        }

        let loaded = load(provider).expect("load should succeed after save");
        if loaded.is_none() {
            let _ = delete(provider);
            return;
        }
        assert_eq!(loaded.as_deref(), Some(payload.as_str()));

        delete(provider).expect("first delete should succeed");
        delete(provider).expect("second delete should be idempotent");

        match load(provider) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("expected missing keyring entry after delete"),
            Err(AppError::CredentialStoreUnavailable(_)) => {}
            Err(other) => panic!("unexpected load error after delete: {other}"),
        }
    }
}

use crate::config::Provider;
use crate::error::Result;

const BACKEND: &str = "keyring";

#[cfg(feature = "keyring")]
fn new_entry(provider: Provider) -> keyring::Result<keyring::Entry> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        keyring::Entry::new("tunmux", provider.dir_name())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "native keyring is unsupported on this platform for {}",
                    provider.dir_name()
                ),
            ),
        )))
    }
}

#[cfg(feature = "keyring")]
pub(super) fn save(provider: Provider, payload_json: &str) -> Result<()> {
    let entry = new_entry(provider)
        .map_err(|e| super::unavailable(provider, BACKEND, "save", &e.to_string()))?;
    save_entry(provider, &entry, payload_json)
}

#[cfg(feature = "keyring")]
fn save_entry(provider: Provider, entry: &keyring::Entry, payload_json: &str) -> Result<()> {
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
    let entry = new_entry(provider)
        .map_err(|e| super::unavailable(provider, BACKEND, "load", &e.to_string()))?;
    load_entry(provider, &entry)
}

#[cfg(feature = "keyring")]
fn load_entry(provider: Provider, entry: &keyring::Entry) -> Result<Option<String>> {
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
    let entry = new_entry(provider)
        .map_err(|e| super::unavailable(provider, BACKEND, "delete", &e.to_string()))?;
    delete_entry(provider, &entry)
}

#[cfg(feature = "keyring")]
fn delete_entry(provider: Provider, entry: &keyring::Entry) -> Result<()> {
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
    #[cfg(not(feature = "keyring"))]
    use super::{delete, load, save};
    #[cfg(feature = "keyring")]
    use super::{delete_entry, load_entry, save_entry};
    use crate::config::Provider;
    use crate::error::AppError;

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn test_keyring_backend_unavailable_without_feature() {
        let save_err = save(Provider::Proton, "{}").expect_err("save should fail without feature");
        let load_err = load(Provider::Proton).expect_err("load should fail without feature");
        let delete_err = delete(Provider::Proton).expect_err("delete should fail without feature");
        for error in [save_err, load_err, delete_err] {
            assert!(matches!(error, AppError::CredentialStoreUnavailable(_)));
        }
    }

    #[cfg(feature = "keyring")]
    fn mock_entry() -> keyring::Entry {
        keyring::Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()))
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn test_keyring_roundtrip_and_idempotent_delete() {
        let entry = mock_entry();
        let provider = Provider::Proton;
        assert_eq!(load_entry(provider, &entry).unwrap(), None);
        save_entry(provider, &entry, "first").unwrap();
        assert_eq!(
            load_entry(provider, &entry).unwrap().as_deref(),
            Some("first")
        );
        save_entry(provider, &entry, "updated").unwrap();
        assert_eq!(
            load_entry(provider, &entry).unwrap().as_deref(),
            Some("updated")
        );
        delete_entry(provider, &entry).unwrap();
        delete_entry(provider, &entry).unwrap();
        assert_eq!(load_entry(provider, &entry).unwrap(), None);
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn test_keyring_storage_errors_are_not_missing_credentials() {
        let entry = mock_entry();
        let mock = entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .unwrap();
        for operation in ["save", "load", "delete"] {
            mock.set_error(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "locked store"),
            )));
            let error = match operation {
                "save" => save_entry(Provider::Proton, &entry, "test").unwrap_err(),
                "load" => load_entry(Provider::Proton, &entry).unwrap_err(),
                _ => delete_entry(Provider::Proton, &entry).unwrap_err(),
            };
            assert!(
                matches!(error, AppError::CredentialStoreUnavailable(_)),
                "{operation}: {error}"
            );
        }
        mock.set_error(keyring::Error::Invalid(
            "credential".into(),
            "invalid payload".into(),
        ));
        assert!(matches!(
            load_entry(Provider::Proton, &entry),
            Err(AppError::CredentialStoreFailure(_))
        ));
    }
}

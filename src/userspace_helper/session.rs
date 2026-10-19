//! Root-owned identities tied to the helper's network ownership lock.
use nix::libc;
use std::path::{Path, PathBuf};

use crate::privileged_api::{SessionHealthKind, SessionInspection};

fn path(interface: &str) -> PathBuf {
    PathBuf::from(super::SOCK_DIR).join(format!("{interface}.session"))
}

fn trusted_directory(directory: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(directory)?;
    anyhow::ensure!(
        meta.is_dir()
            && meta.uid() == nix::unistd::Uid::effective().as_raw()
            && meta.mode() & 0o022 == 0,
        "session directory ownership is untrusted"
    );
    Ok(())
}

fn trusted_metadata(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(
        metadata.uid() == nix::unistd::Uid::effective().as_raw() && metadata.mode() & 0o077 == 0,
        "session file ownership or permissions are untrusted"
    );
    Ok(())
}

fn read_identity(path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "session identity is not a regular file"
    );
    trusted_metadata(&file.metadata()?)?;
    let mut value = String::new();
    file.take(33).read_to_string(&mut value)?;
    anyhow::ensure!(
        value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid session identity"
    );
    Ok(value)
}

fn identity(interface: &str) -> anyhow::Result<String> {
    read_identity(&path(interface))
}

/// Called only while the helper owns the network session lock.
pub(super) fn start(interface: &str) -> anyhow::Result<String> {
    trusted_directory(Path::new(super::SOCK_DIR))?;
    let id = format!("{:032x}", rand::random::<u128>());
    crate::shared::persistence::write_private_atomic(&path(interface), id.as_bytes())?;
    Ok(id)
}

/// Retain the identity as a completed-session receipt until the next start.
/// A crash between cleanup acknowledgment and user-state removal can then be recovered.
pub(super) fn finish(interface: &str) -> anyhow::Result<()> {
    identity(interface).map(|_| ())
}

pub(crate) fn inspect(interface: &str, expected: Option<&str>) -> SessionInspection {
    inspect_at(Path::new(super::SOCK_DIR), interface, expected)
}

fn inspect_at(directory: &Path, interface: &str, expected: Option<&str>) -> SessionInspection {
    let mut result = SessionInspection {
        health: SessionHealthKind::Unknown,
        reason: "session ownership cannot be verified".into(),
        recovery_available: false,
        session_id: None,
    };
    if let Err(error) = trusted_directory(directory) {
        result.reason = error.to_string();
        return result;
    }
    // Open without creating state: status must remain a read-only operation.
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::OpenOptionsExt;
    let lock_path = directory.join(format!("{interface}.recovery.lock"));
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(lock_path)
    {
        Ok(file) => file,
        Err(error) => {
            result.reason = format!("session lock unavailable: {error}");
            return result;
        }
    };
    if !file
        .metadata()
        .is_ok_and(|meta| meta.is_file() && trusted_metadata(&meta).is_ok())
    {
        result.reason = "session lock ownership or permissions are untrusted".into();
        return result;
    }
    let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Some(lock),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => None,
        Err((_, error)) => {
            result.reason = format!("session lock observation failed: {error}");
            return result;
        }
    };
    let id = match read_identity(&directory.join(format!("{interface}.session"))) {
        Ok(id) => id,
        Err(error) => {
            result.reason = format!("session identity unavailable: {error}");
            return result;
        }
    };
    result.session_id = Some(id.clone());
    if expected.is_some_and(|expected| expected != id) {
        result.reason = "session identity differs; interface may have been reused".into();
        return result;
    }
    let endpoint =
        crate::wireguard::health::socket_connect(&directory.join(format!("{interface}.sock")));
    if lock.is_some() {
        match endpoint {
            Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED) => {
                result.health = SessionHealthKind::Inactive;
                result.reason =
                    "identified helper has released ownership and its endpoint is stopped".into();
                result.recovery_available = true;
            }
            observation => {
                result.reason = format!("control endpoint ownership is unsettled: {observation:?}")
            }
        }
    } else if endpoint.is_ok() {
        result.health = SessionHealthKind::Active;
        result.reason = "identified helper owns the network session and control endpoint".into();
    } else {
        result.reason = "helper owns session but endpoint is not ready".into();
    }
    result
}

pub(crate) fn recover(interface: &str, expected: &str) -> anyhow::Result<()> {
    trusted_directory(Path::new(super::SOCK_DIR))?;
    let lock = super::network::lock(interface)?;
    trusted_metadata(&lock.metadata()?)?;
    anyhow::ensure!(
        identity(interface)? == expected,
        "session identity changed; refusing recovery"
    );
    super::network::ensure_stopped(interface)?;
    super::network::recover_locked(interface)?;
    // SIGKILL leaves root-only socket nodes behind. Remove them before acknowledging
    // recovery so an unprivileged reconnect does not mistake EACCES for a live owner.
    super::network::remove_stopped_endpoints(Path::new(super::SOCK_DIR), interface)?;
    finish(interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_and_identity_are_required_before_recovery_is_available() {
        use nix::fcntl::{Flock, FlockArg};
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from("/tmp").join(format!("tmx-s-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = dir.join("wg-test.recovery.lock");
        std::fs::write(&lock_path, []).unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let metadata = dir.join("wg-test.session");
        crate::shared::persistence::write_private_atomic(&metadata, id.as_bytes()).unwrap();
        let held = Flock::lock(
            std::fs::File::open(lock_path).unwrap(),
            FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        let socket_path = dir.join("wg-test.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        assert_eq!(
            inspect_at(&dir, "wg-test", Some(id)).health,
            SessionHealthKind::Active
        );
        let mismatch = inspect_at(&dir, "wg-test", Some("another-session"));
        assert_eq!(mismatch.health, SessionHealthKind::Unknown);
        assert!(!mismatch.recovery_available);
        drop(held);
        assert_eq!(
            inspect_at(&dir, "wg-test", Some(id)).health,
            SessionHealthKind::Unknown
        );
        drop(listener);
        let inactive = inspect_at(&dir, "wg-test", Some(id));
        assert_eq!(inactive.health, SessionHealthKind::Inactive);
        assert!(inactive.recovery_available);
        // Completed sessions retain their receipt, so repeated preparation remains safe.
        assert_eq!(read_identity(&metadata).unwrap(), id);
        assert!(inspect_at(&dir, "wg-test", Some(id)).recovery_available);
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            inspect_at(&dir, "wg-test", Some(id)).health,
            SessionHealthKind::Unknown
        );
        std::fs::remove_file(&metadata).unwrap();
        std::os::unix::fs::symlink("missing", &metadata).unwrap();
        assert_eq!(
            inspect_at(&dir, "wg-test", Some(id)).health,
            SessionHealthKind::Unknown
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_identity_never_authorizes_recovery() {
        let result = inspect("wg-absent-test", Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(result.health, SessionHealthKind::Unknown);
        assert!(!result.recovery_available);
    }
}

//! Identity-aware control and cleanup acknowledgment for user-owned proxy sessions.
use crate::wireguard::health::{ConnectionHealth, HealthKind};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
struct Receipt {
    session_id: String,
    pid: u32,
}
fn control_directory() -> PathBuf {
    PathBuf::from(format!("/tmp/tunmux-proxy-{}", nix::unistd::geteuid()))
}
fn control(pid: &Path) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(pid.as_os_str().as_encoded_bytes()));
    control_directory().join(format!("{}.sock", &digest[..32]))
}
fn secure_control_directory(create: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = control_directory();
    if create {
        match std::fs::create_dir(&path) {
            Ok(()) => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "untrusted proxy control directory"
    );
    Ok(())
}
fn receipt(pid: &Path) -> PathBuf {
    pid.with_extension("identity.json")
}
fn exchange(pid: &Path, request: &str, timeout: Duration) -> anyhow::Result<String> {
    secure_control_directory(false)?;
    let mut stream = crate::wireguard::health::connect_probe(&control(pid))?;
    stream.set_nonblocking(true)?;
    stream
        .write_all(request.as_bytes())
        .context("proxy request write")?;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        anyhow::ensure!(Instant::now() < deadline, "proxy control deadline exceeded");
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("proxy control disconnected"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        if byte[0] == b'\n' {
            return Ok(String::from_utf8(bytes)?);
        }
        anyhow::ensure!(bytes.len() < 256, "proxy control frame too large");
        bytes.push(byte[0]);
    }
}
pub fn session_id(instance: &str) -> anyhow::Result<String> {
    let path = crate::proxy::local_pid_file(instance);
    let r: Receipt = serde_json::from_slice(&std::fs::read(receipt(&path))?)?;
    anyhow::ensure!(
        exchange(&path, "inspect\n", Duration::from_secs(2))? == r.session_id,
        "proxy identity changed"
    );
    Ok(r.session_id)
}
pub fn inspect(state: &crate::wireguard::connection::ConnectionState) -> ConnectionHealth {
    let result = (|| -> anyhow::Result<HealthKind> {
        let id = state
            .session_id
            .as_deref()
            .context("legacy proxy has no session identity")?;
        let path = crate::proxy::local_pid_file(&state.instance_name);
        let r: Receipt = serde_json::from_slice(&std::fs::read(receipt(&path))?)?;
        anyhow::ensure!(
            id == r.session_id && Some(r.pid) == state.proxy_pid,
            "proxy receipt identity differs"
        );
        match exchange(&path, "inspect\n", Duration::from_secs(2)) {
            Ok(actual) => {
                anyhow::ensure!(actual == id, "proxy control identity differs");
                Ok(HealthKind::Active)
            }
            Err(error) => {
                let unavailable = error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    )
                });
                // A process-held flock survives a missing socket. Absence is confirmed only
                // when the expected owner has released its session lock.
                if unavailable && try_lock(&path).is_ok() {
                    Ok(HealthKind::Inactive)
                } else {
                    Err(error)
                }
            }
        }
    })();
    match result {
        Ok(kind) => ConnectionHealth {
            kind,
            reason: "proxy session identity verified".into(),
            recovery_available: false,
        },
        Err(e) => ConnectionHealth {
            kind: HealthKind::Unknown,
            reason: e.to_string(),
            recovery_available: false,
        },
    }
}
pub fn stop(state: &crate::wireguard::connection::ConnectionState) -> anyhow::Result<()> {
    let health = inspect(state);
    if health.kind == HealthKind::Inactive {
        return Ok(());
    }
    anyhow::ensure!(
        health.kind == HealthKind::Active,
        "cannot stop proxy: {}",
        health.reason
    );
    let id = state
        .session_id
        .as_deref()
        .context("proxy identity missing")?;
    let response = exchange(
        &crate::proxy::local_pid_file(&state.instance_name),
        &format!("stop {id}\n"),
        Duration::from_secs(10),
    )?;
    anyhow::ensure!(
        response == format!("stopped {id}"),
        "proxy cleanup was not acknowledged"
    );
    Ok(())
}
fn try_lock(pid: &Path) -> anyhow::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(pid.with_extension("session.lock"))?;
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| e.into())
}
pub struct Control {
    pub stop: tokio::sync::mpsc::Receiver<UnixStream>,
    id: String,
    path: PathBuf,
    socket_identity: Option<(u64, u64)>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    lock: Option<nix::fcntl::Flock<std::fs::File>>,
}
impl Control {
    pub fn start(pid: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let id = std::env::var("TUNMUX_LOCAL_PROXY_SESSION")
            .unwrap_or_else(|_| format!("{:032x}", rand::random::<u128>()));
        anyhow::ensure!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid proxy session identity"
        );
        let lock = try_lock(pid)?;
        secure_control_directory(true)?;
        let path = control(pid);
        match std::fs::symlink_metadata(&path) {
            Ok(m) => {
                use std::os::unix::fs::FileTypeExt;
                anyhow::ensure!(
                    m.file_type().is_socket(),
                    "proxy control path is not a socket"
                );
                std::fs::remove_file(&path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&path)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&path)?;
        let socket_identity = Some((metadata.dev(), metadata.ino()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let r = Receipt {
            session_id: id.clone(),
            pid: std::process::id(),
        };
        crate::shared::persistence::write_private_atomic(&receipt(pid), &serde_json::to_vec(&r)?)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = stopped.clone();
        let expected = id.clone();
        let (send, stop) = tokio::sync::mpsc::channel(1);
        let thread = std::thread::Builder::new()
            .name("tunmux-proxy-control".into())
            .spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(25));
                            continue;
                        }
                        Err(_) => break,
                    };
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let mut request = Vec::new();
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let mut complete = false;
                    while request.len() < 128
                        && Instant::now() < deadline
                        && !flag.load(Ordering::Acquire)
                    {
                        let mut byte = [0];
                        match stream.read(&mut byte) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue
                            }
                            Err(_) => break,
                        }
                        if byte[0] == b'\n' {
                            complete = true;
                            break;
                        }
                        request.push(byte[0]);
                    }
                    if !complete {
                        continue;
                    }
                    if request == b"inspect" {
                        let _ = writeln!(stream, "{expected}");
                    } else if request == format!("stop {expected}").as_bytes() {
                        let _ = send.blocking_send(stream);
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            id,
            path,
            socket_identity,
            stopped,
            thread: Some(thread),
            lock: Some(lock),
        })
    }
    pub fn acknowledge(&mut self, mut stream: UnixStream) -> anyhow::Result<()> {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.remove_socket()?;
        self.lock.take();
        writeln!(stream, "stopped {}", self.id)?;
        Ok(())
    }
}
impl Control {
    fn remove_socket(&mut self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Some(identity) = self.socket_identity else {
            return Ok(());
        };
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) == identity => {
                std::fs::remove_file(&self.path)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }?;
        // A later socket can reuse this inode after we release the session lock.
        self.socket_identity = None;
        Ok(())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = self.remove_socket();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, Control) {
        let directory = std::env::temp_dir().join(format!(
            "tunmux-proxy-control-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let pid = directory.join("test.pid");
        let control = Control::start(&pid).unwrap();
        (pid, control)
    }
    #[test]
    fn stop_requires_identity_and_waits_for_cleanup_ack() {
        let (pid, mut owner) = fixture();
        assert_eq!(
            exchange(&pid, "inspect\n", Duration::from_secs(2)).unwrap(),
            owner.id
        );
        assert!(exchange(&pid, "stop wrong-owner\n", Duration::from_secs(1)).is_err());
        let path = pid.clone();
        let id = owner.id.clone();
        let client = std::thread::spawn(move || {
            exchange(&path, &format!("stop {id}\n"), Duration::from_secs(2))
        });
        let stream = owner.stop.blocking_recv().unwrap();
        assert!(!client.is_finished());
        owner.acknowledge(stream).unwrap();
        assert_eq!(
            client.join().unwrap().unwrap(),
            format!("stopped {}", owner.id)
        );
        assert!(!control(&pid).exists());
        drop(owner);
        std::fs::remove_dir_all(pid.parent().unwrap()).unwrap();
    }
    #[test]
    fn old_owner_cannot_unlink_replacement_socket() {
        let (pid, mut owner) = fixture();
        owner.stopped.store(true, Ordering::Release);
        owner.thread.take().unwrap().join().unwrap();
        owner.remove_socket().unwrap();
        owner.lock.take();
        let replacement = Control::start(&pid).unwrap();
        drop(owner);
        assert_eq!(
            exchange(&pid, "inspect\n", Duration::from_secs(2)).unwrap(),
            replacement.id
        );
        drop(replacement);
        assert!(receipt(&pid).exists());
        assert!(try_lock(&pid).is_ok());
        std::fs::remove_dir_all(pid.parent().unwrap()).unwrap();
    }
}

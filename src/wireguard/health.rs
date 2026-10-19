//! Conservative observations: failures never authorize destructive recovery.
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::privileged_api::{PrivilegedRequest, PrivilegedResponse};

use super::backend::WgBackend;
use super::connection::ConnectionState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthKind {
    Active,
    Inactive,
    Unknown,
}

impl fmt::Display for HealthKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Debug)]
pub struct ConnectionHealth {
    pub kind: HealthKind,
    pub reason: String,
}

/// Observe without starting a daemon, prompting for credentials, or changing state.
pub fn inspect(state: &ConnectionState) -> ConnectionHealth {
    if state.namespace_name.is_some() || state.backend == WgBackend::LocalProxy {
        return unknown("proxy session identity cannot be verified from saved PID alone");
    }
    #[cfg(target_os = "linux")]
    if state.backend == WgBackend::Kernel {
        match std::fs::metadata(format!("/sys/class/net/{}", state.interface_name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ConnectionHealth {
                    kind: HealthKind::Inactive,
                    reason: "saved kernel interface is absent; recovery may still be pending"
                        .into(),
                };
            }
            _ => {}
        }
    }
    match probe(&state.interface_name) {
        Ok(output) => classify_output(state.peer_public_key.as_deref(), &output),
        Err(error) => unknown(format!("backend observation unavailable: {error}")),
    }
}

fn unknown(reason: impl Into<String>) -> ConnectionHealth {
    ConnectionHealth {
        kind: HealthKind::Unknown,
        reason: reason.into(),
    }
}

fn classify_output(expected_peer: Option<&str>, output: &str) -> ConnectionHealth {
    let Some(peer) = expected_peer else {
        return unknown("backend responds, but legacy state has no peer identity");
    };
    if output
        .lines()
        .any(|line| line.trim().strip_prefix("peer: ") == Some(peer))
    {
        ConnectionHealth {
            kind: HealthKind::Active,
            reason: "backend responds with the saved peer identity".into(),
        }
    } else {
        unknown("backend peer differs from saved session; interface may have been reused")
    }
}

fn probe(interface: &str) -> anyhow::Result<String> {
    let stream = UnixStream::connect(crate::config::privileged_socket_path())?;
    probe_stream(stream, interface, Duration::from_secs(2))
}

fn probe_stream(
    mut stream: UnixStream,
    interface: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let deadline = Instant::now() + timeout;
    stream.set_write_timeout(Some(timeout))?;
    let request = PrivilegedRequest::WgShow {
        interface: interface.into(),
    };
    request.validate().map_err(anyhow::Error::msg)?;
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut response = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("health probe deadline expired"))?;
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        if stream.read(&mut byte)? == 0 {
            anyhow::bail!("health probe disconnected");
        }
        if byte[0] == b'\n' {
            break;
        }
        if response.len() >= 256 * 1024 {
            anyhow::bail!("health probe response too large");
        }
        response.push(byte[0]);
    }
    match serde_json::from_slice(&response)? {
        PrivilegedResponse::Text(output) => Ok(output),
        PrivilegedResponse::Error { message, .. } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected health probe response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_stalled_backend_probe_is_bounded() {
        let (client, _server) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(probe_stream(client, "wg-test", Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn test_reused_interface_is_unknown() {
        assert_eq!(
            classify_output(Some("expected"), "peer: another\n").kind,
            HealthKind::Unknown
        );
    }
    #[test]
    fn test_matching_peer_is_active() {
        assert_eq!(
            classify_output(Some("expected"), "  peer: expected\n").kind,
            HealthKind::Active
        );
    }
    #[test]
    fn test_legacy_state_remains_unknown() {
        assert_eq!(
            classify_output(None, "peer: expected\n").kind,
            HealthKind::Unknown
        );
    }
}

/// Occupancy is only a connect guard, never proof of session identity.
/// A stale socket is reusable; permission errors and unsettled observations block.
pub fn userspace_endpoint_occupied(interface: &str) -> bool {
    socket_occupied(&std::path::Path::new("/var/run/wireguard").join(format!("{interface}.sock")))
}

fn socket_occupied(path: &std::path::Path) -> bool {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    let result = (|| {
        let address = UnixAddr::new(path)?;
        #[cfg(target_os = "macos")]
        let flags = SockFlag::empty();
        #[cfg(not(target_os = "macos"))]
        let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
        let socket = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
        #[cfg(target_os = "macos")]
        {
            // macOS requires setting these properties after socket creation.
            use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
            fcntl(&socket, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            fcntl(&socket, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
        }
        connect(socket.as_raw_fd(), &address)
    })();
    !matches!(
        result,
        Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED)
    )
}

#[cfg(test)]
mod occupancy_tests {
    use super::*;

    #[test]
    fn test_stale_socket_does_not_block_recovery() {
        let path =
            std::env::temp_dir().join(format!("tunmux-stale-{}.sock", rand::random::<u64>()));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(socket_occupied(&path));
        drop(listener);
        assert!(!socket_occupied(&path));
        std::fs::remove_file(&path).unwrap();
        assert!(!socket_occupied(&path));
    }
}

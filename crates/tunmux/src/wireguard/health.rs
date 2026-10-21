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
    pub recovery_available: bool,
}

fn uses_helper(backend: WgBackend) -> bool {
    backend == WgBackend::Userspace || (cfg!(target_os = "macos") && backend == WgBackend::Kernel)
}

/// Observe without starting a daemon, prompting for credentials, or changing state.
pub fn inspect(state: &ConnectionState) -> ConnectionHealth {
    if state.backend == WgBackend::LocalProxy {
        return crate::local_proxy_control::inspect(state);
    }
    if state.namespace_name.is_some() {
        return unknown("proxy session identity cannot be verified from saved PID alone");
    }
    if uses_helper(state.backend) {
        let Some(id) = state.session_id.as_deref() else {
            return unknown("legacy userspace state has no verifiable session identity");
        };
        return match probe(&state.interface_name, Some(id)) {
            Ok(result) => ConnectionHealth {
                kind: match result.health {
                    crate::privileged_api::SessionHealthKind::Active => HealthKind::Active,
                    crate::privileged_api::SessionHealthKind::Inactive => HealthKind::Inactive,
                    crate::privileged_api::SessionHealthKind::Unknown => HealthKind::Unknown,
                },
                reason: result.reason,
                recovery_available: result.recovery_available,
            },
            Err(error) => unknown(format!("backend observation unavailable: {error}")),
        };
    }
    #[cfg(target_os = "linux")]
    if state.backend == WgBackend::Kernel
        && std::fs::metadata(format!("/sys/class/net/{}", state.interface_name))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return ConnectionHealth {
            kind: HealthKind::Inactive,
            recovery_available: false,
            reason: "saved kernel interface is absent; recovery ownership is unverified".into(),
        };
    }
    match probe_request(
        &state.interface_name,
        PrivilegedRequest::WgShow {
            interface: state.interface_name.clone(),
        },
    ) {
        Ok(PrivilegedResponse::Text(output))
            if state.peer_public_key.as_ref().is_some_and(|peer| {
                output
                    .lines()
                    .any(|line| line.trim().strip_prefix("peer: ") == Some(peer.as_str()))
            }) =>
        {
            ConnectionHealth {
                kind: HealthKind::Active,
                reason: "backend responds with saved peer identity".into(),
                recovery_available: false,
            }
        }
        Ok(_) => unknown("backend identity differs or is unavailable"),
        Err(error) => unknown(format!("backend observation unavailable: {error}")),
    }
}

/// Explicit connect preparation may use the already-authorized command transport.
pub fn inspect_for_connect(state: &ConnectionState) -> ConnectionHealth {
    if uses_helper(state.backend) && state.namespace_name.is_none() {
        let Some(id) = state.session_id.as_deref() else {
            return unknown("legacy userspace state has no verifiable session identity");
        };
        return match crate::privileged_client::PrivilegedClient::new()
            .inspect_session(&state.interface_name, Some(id))
        {
            Ok(result) => ConnectionHealth {
                kind: match result.health {
                    crate::privileged_api::SessionHealthKind::Active => HealthKind::Active,
                    crate::privileged_api::SessionHealthKind::Inactive => HealthKind::Inactive,
                    crate::privileged_api::SessionHealthKind::Unknown => HealthKind::Unknown,
                },
                reason: result.reason,
                recovery_available: result.recovery_available,
            },
            Err(error) => unknown(format!("session observation unavailable: {error}")),
        };
    }
    inspect(state)
}

fn unknown(reason: impl Into<String>) -> ConnectionHealth {
    ConnectionHealth {
        kind: HealthKind::Unknown,
        recovery_available: false,
        reason: reason.into(),
    }
}

fn probe(
    interface: &str,
    session_id: Option<&str>,
) -> anyhow::Result<crate::privileged_api::SessionInspection> {
    match probe_request(
        interface,
        PrivilegedRequest::InspectSession {
            interface: interface.into(),
            session_id: session_id.map(str::to_owned),
        },
    )? {
        PrivilegedResponse::Session(output) => Ok(output),
        _ => anyhow::bail!("unexpected health probe response"),
    }
}

pub(crate) fn connect_probe(path: &std::path::Path) -> std::io::Result<UnixStream> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "macos")]
    let flags = SockFlag::empty();
    #[cfg(not(target_os = "macos"))]
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    let socket = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
    #[cfg(target_os = "macos")]
    {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
        fcntl(&socket, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&socket, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    }
    connect(socket.as_raw_fd(), &UnixAddr::new(path)?)?;
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn probe_request(
    _interface: &str,
    request: PrivilegedRequest,
) -> anyhow::Result<PrivilegedResponse> {
    let stream = connect_probe(&crate::config::privileged_socket_path())?;
    probe_stream(stream, request, Duration::from_secs(2))
}

fn probe_stream(
    mut stream: UnixStream,
    request: PrivilegedRequest,
    timeout: Duration,
) -> anyhow::Result<PrivilegedResponse> {
    let deadline = Instant::now() + timeout;
    stream.set_write_timeout(Some(timeout))?;
    request.validate().map_err(anyhow::Error::msg)?;
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.set_nonblocking(true)?;
    let mut response = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("health probe deadline expired"))?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("health probe disconnected"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
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
        PrivilegedResponse::Error { message, .. } => anyhow::bail!("{message}"),
        output => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_stalled_backend_probe_is_bounded() {
        let (client, _server) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(probe_stream(
            client,
            PrivilegedRequest::WgShow {
                interface: "wg-test".into()
            },
            Duration::from_millis(30)
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

/// Occupancy is only a connect guard, never proof of session identity.
/// A stale socket is reusable; permission errors and unsettled observations block.
pub fn userspace_endpoint_occupied(interface: &str) -> bool {
    socket_occupied(&std::path::Path::new("/var/run/wireguard").join(format!("{interface}.sock")))
}

fn socket_occupied(path: &std::path::Path) -> bool {
    !matches!(
        socket_connect(path),
        Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED)
    )
}

pub(crate) fn socket_connect(path: &std::path::Path) -> Result<(), nix::errno::Errno> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    (|| {
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
    })()
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

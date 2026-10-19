//! Listener acquisition keeps service-manager sockets outside application cleanup.
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

pub(super) struct Listener {
    pub socket: UnixListener,
    owned_path: Option<(PathBuf, u64, u64)>,
}

impl Listener {
    fn activated(socket: UnixListener) -> Self {
        Self {
            socket,
            owned_path: None,
        }
    }

    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "refusing to replace non-socket {}",
                    path.display()
                );
                match UnixStream::connect(path) {
                    Ok(_) => {
                        anyhow::bail!("privileged service already listening at {}", path.display())
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let socket = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(Self {
            socket,
            owned_path: Some((path.into(), metadata.dev(), metadata.ino())),
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some((path, dev, ino)) = &self.owned_path {
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.dev() == *dev && metadata.ino() == *ino)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

pub(super) fn activated_listener() -> anyhow::Result<Option<Listener>> {
    #[cfg(target_os = "macos")]
    {
        launchd_listener()
    }
    #[cfg(not(target_os = "macos"))]
    {
        systemd_listener()
    }
}

#[cfg(target_os = "macos")]
fn launchd_listener() -> anyhow::Result<Option<Listener>> {
    use nix::libc;
    use std::os::fd::FromRawFd;
    // Apple launch.h: the array is allocated by launch_activate_socket and must be freed.
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            count: *mut libc::size_t,
        ) -> libc::c_int;
    }
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    let result =
        unsafe { launch_activate_socket(c"PrivilegedListener".as_ptr(), &mut fds, &mut count) };
    if result != 0 {
        if matches!(result, libc::ENOENT | libc::ESRCH)
            && std::env::var_os("TUNMUX_LAUNCHD_SOCKET").is_none()
        {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(result).into());
    }
    anyhow::ensure!(!fds.is_null(), "launchd returned a null descriptor array");
    let descriptors = unsafe { std::slice::from_raw_parts(fds, count) };
    let listeners: Vec<UnixListener> = descriptors
        .iter()
        .map(|fd| unsafe { UnixListener::from_raw_fd(*fd) })
        .collect();
    unsafe { libc::free(fds.cast()) };
    anyhow::ensure!(
        listeners.len() == 1,
        "launchd must provide exactly one PrivilegedListener socket"
    );
    let socket = listeners.into_iter().next().expect("checked length");
    validate_activated(&socket)?;
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(Some(Listener::activated(socket)))
}

#[cfg(not(target_os = "macos"))]
fn systemd_listener() -> anyhow::Result<Option<Listener>> {
    use std::os::fd::FromRawFd;
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        != Some(std::process::id())
    {
        return Ok(None);
    }
    let count = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if count == 0 {
        return Ok(None);
    }
    anyhow::ensure!(count == 1, "expected exactly one systemd listener");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");
    let socket = unsafe { UnixListener::from_raw_fd(3) };
    validate_activated(&socket)?;
    Ok(Some(Listener::activated(socket)))
}

fn validate_activated(socket: &UnixListener) -> anyhow::Result<()> {
    use nix::sys::socket::{getsockname, AddressFamily, SockaddrLike, SockaddrStorage};
    use std::os::fd::AsRawFd;
    let address: SockaddrStorage = getsockname(socket.as_raw_fd())?;
    anyhow::ensure!(
        address.family() == Some(AddressFamily::Unix),
        "activation descriptor is not a Unix socket"
    );
    let mut actual = 0i32;
    let mut length = std::mem::size_of_val(&actual) as nix::libc::socklen_t;
    let result = unsafe {
        nix::libc::getsockopt(
            socket.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_TYPE,
            (&mut actual as *mut i32).cast(),
            &mut length,
        )
    };
    anyhow::ensure!(
        result == 0 && actual == nix::libc::SOCK_STREAM,
        "activation descriptor is not a stream socket"
    );
    // Reassert listening state rather than relying on SO_ACCEPTCONN, whose
    // observation is not reliable for native Darwin Unix sockets. Connected
    // streams are rejected by listen; inherited listeners retain their binding.
    let result = unsafe { nix::libc::listen(socket.as_raw_fd(), 128) };
    anyhow::ensure!(
        result == 0,
        "activation socket cannot listen: {}",
        std::io::Error::last_os_error()
    );
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    let flags = FdFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFD)?);
    fcntl(socket, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    socket.set_nonblocking(false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunmux-socket-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn activation_accepts_a_listening_unix_socket_without_path_spelling_assumptions() {
        let path = path("validation");
        let socket = UnixListener::bind(&path).unwrap();
        validate_activated(&socket).unwrap();
        drop(socket);
        std::fs::remove_file(path).unwrap();
        use std::os::fd::OwnedFd;
        let (stream, _peer) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = stream.into();
        assert!(validate_activated(&UnixListener::from(descriptor)).is_err());
    }
    #[test]
    fn activated_socket_is_not_unlinked() {
        let path = path("activated");
        let socket = UnixListener::bind(&path).unwrap();
        drop(Listener::activated(socket));
        assert!(path.exists());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn self_bound_socket_is_cleaned_up() {
        let path = path("bound");
        drop(Listener::bind(&path).unwrap());
        assert!(!path.exists());
    }
    #[test]
    fn active_socket_and_regular_files_are_preserved() {
        let path = path("preserved");
        let socket = UnixListener::bind(&path).unwrap();
        assert!(Listener::bind(&path).is_err());
        drop(socket);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "keep").unwrap();
        assert!(Listener::bind(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
        std::fs::remove_file(path).unwrap();
    }
}

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nix::libc;
use tracing::debug;

use crate::config::PrivilegedTransport;
use crate::error::{AppError, Result};
use crate::privileged_api::PrivilegedRequest;

use super::elevation::{run_with_timeout, Elevation};
use super::util::{
    configured_privileged_stdio_log_path, request_kind, shell_quote, startup_lock_dir,
};
use super::PrivilegedClient;

pub(crate) struct StdioSession {
    pub(crate) child: Child,
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: BufReader<ChildStdout>,
}

impl StdioSession {
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn shutdown(mut self) {
        let pid = self.child.id();
        debug!( pid = ?pid, "privileged_stdio_helper_closing");
        let _ = self.stdin.flush();
        drop(self.stdin);
        for _ in 0..10 {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    debug!(
                        pid = ?pid,
                        status = ?status.to_string(), "privileged_stdio_helper_exited");
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    debug!(
                        pid = ?pid,
                        error = ?e.to_string(), "privileged_stdio_helper_wait_failed");
                    return;
                }
            }
        }
        debug!(
            pid = ?pid, "privileged_stdio_helper_still_running_after_grace");
        let _ = self.child.kill();
        match self.child.wait() {
            Ok(status) => debug!(
                pid = ?pid,
                status = ?status.to_string(), "privileged_stdio_helper_exited_after_kill"),
            Err(e) => debug!(
                pid = ?pid,
                error = ?e.to_string(), "privileged_stdio_helper_wait_after_kill_failed"),
        }
    }
}

pub(crate) fn is_autostart_connect_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
        || err.kind() == std::io::ErrorKind::ConnectionRefused
        || err.kind() == std::io::ErrorKind::PermissionDenied
}

pub(crate) fn is_transport_error(err: &AppError) -> bool {
    match err {
        AppError::Other(message) => {
            message.starts_with("write request:")
                || message.starts_with("write request delimiter:")
                || message.starts_with("flush request:")
                || message.starts_with("read response:")
                || message.starts_with("write request stdin:")
                || message.starts_with("write request delimiter stdin:")
                || message.starts_with("flush request stdin:")
                || message.starts_with("read response stdout:")
                || message == "empty response from privileged server"
        }
        _ => false,
    }
}

impl PrivilegedClient {
    pub(crate) fn connect_or_autostart(&self) -> Result<UnixStream> {
        debug!(
            "privileged ctl connect attempt socket={}",
            self.socket_path.display()
        );
        match self.try_connect_socket() {
            Ok(mut stream) => {
                if crate::service::installed() {
                    self.verify_activation(&mut stream)?;
                }
                debug!(
                    "privileged ctl connect ok socket={}",
                    self.socket_path.display()
                );
                return Ok(stream);
            }
            Err(e) if !is_autostart_connect_error(&e) => {
                debug!(
                    "privileged ctl connect failed socket={} err={}",
                    self.socket_path.display(),
                    e
                );
                return Err(AppError::Other(format!(
                    "failed to connect to privileged socket: {}",
                    e
                )));
            }
            Err(e) => {
                debug!(
                    "privileged ctl connect recoverable socket={} err={}",
                    self.socket_path.display(),
                    e
                );
            }
        }

        if !self.autostart_enabled {
            return Err(AppError::Other(format!(
                "autostart disabled and privileged socket unavailable; run: {}",
                self.manual_start_command()
            )));
        }

        if crate::service::installed() {
            let deadline = Instant::now() + self.autostart_timeout;
            while Instant::now() < deadline {
                if let Ok(mut stream) = self.try_connect_socket() {
                    self.verify_activation(&mut stream)?;
                    return Ok(stream);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            return Err(AppError::Other(
                "installed launchd service did not activate; run tunmux service diagnose".into(),
            ));
        }
        if std::env::var_os("TUNMUX_NONINTERACTIVE").is_some() {
            return Err(AppError::Other(
                "background connect requires an available privileged service; install it first"
                    .into(),
            ));
        }
        self.autostart_daemon()?;
        self.try_connect_socket().map_err(|e| {
            AppError::Other(format!(
                "privileged socket unavailable after autostart: {}; run: {}",
                e,
                self.manual_start_command()
            ))
        })
    }

    fn verify_activation(&self, stream: &mut UnixStream) -> Result<()> {
        match self.send_on_stream(stream, &PrivilegedRequest::Capabilities) {
            Ok(super::PrivilegedResponse::Text(_)) => Ok(()),
            _ => Err(AppError::Other("installed launchd service did not answer its activation probe within two seconds; run tunmux service diagnose".into())),
        }
    }

    fn autostart_daemon(&self) -> Result<()> {
        tracing::trace!("privileged_ctl_autostart_begin");
        let _lock = self.acquire_startup_lock()?;
        tracing::trace!("privileged_ctl_autostart_lock_acquired");

        if self.try_connect_socket().is_ok() {
            return Ok(());
        }

        self.spawn_privileged_daemon()?;
        self.wait_until_ready()?;
        tracing::trace!("privileged_ctl_autostart_ready");
        Ok(())
    }

    fn acquire_startup_lock(&self) -> Result<std::fs::File> {
        let lock_dir = startup_lock_dir();
        fs::create_dir_all(&lock_dir).map_err(|e| {
            AppError::Other(format!(
                "failed to create autostart lock dir {}: {}",
                lock_dir.display(),
                e
            ))
        })?;
        let _ = fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700));

        let lock_path = lock_dir.join("privileged-start.lock");
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| {
                AppError::Other(format!(
                    "failed to open autostart lock {}: {}",
                    lock_path.display(),
                    e
                ))
            })?;

        let deadline = Instant::now() + self.autostart_timeout;
        loop {
            let lock_result =
                unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if lock_result == 0 {
                return Ok(lock_file);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                if Instant::now() >= deadline {
                    return Err(AppError::Other(
                        "another client is starting daemon; retry shortly".into(),
                    ));
                }
                thread::sleep(Duration::from_millis(50));
            } else {
                return Err(AppError::Other(format!(
                    "failed to acquire startup lock: {}",
                    err
                )));
            }
        }
    }

    fn spawn_privileged_daemon(&self) -> Result<()> {
        const PROMPT_TIMEOUT: Duration = Duration::from_secs(90);

        let elevation = Elevation::resolve(&self.elevation)?;
        let interactive = elevation.can_prompt();
        let mut command = self.elevated_daemon_command(&elevation, interactive)?;
        if let Some(log_path) = configured_privileged_stdio_log_path() {
            let (stdout, stderr) = open_stdio_log(&log_path)?;
            command.stdout(stdout).stderr(stderr);
            debug!(
                "privileged daemon start: capturing elevation/daemon stdio to {}",
                log_path.display()
            );
        }

        debug!(
            elevation = ?elevation.display_name(),
            interactive = interactive,
            "privileged_daemon_start"
        );
        // The daemon detaches itself, so this returns once it is running.
        let status = run_with_timeout(command, PROMPT_TIMEOUT)
            .map_err(|e| elevation.map_spawn_error(e, self.manual_start_command()))?;
        if status.success() {
            return Ok(());
        }
        Err(AppError::Other(format!(
            "failed to start privileged daemon{}: {}{}; run: {}",
            via_elevation(&elevation),
            status,
            prompt_hint(&elevation, interactive),
            self.manual_start_command()
        )))
    }

    pub(crate) fn spawn_privileged_stdio_session(&self) -> Result<StdioSession> {
        let elevation = Elevation::resolve(&self.elevation)?;
        if !elevation.supports_pipes() {
            return Err(AppError::Other(format!(
                "privileged stdio transport cannot run through {}; set general.privileged_transport = \"socket\" or another general.privileged_elevation",
                elevation.display_name().unwrap_or_default()
            )));
        }

        let interactive = elevation.can_prompt();
        let mut command = self.elevated_daemon_command(&elevation, interactive)?;
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        if let Some(log_path) = configured_privileged_stdio_log_path() {
            let (_, stderr) = open_stdio_log(&log_path)?;
            command.stderr(stderr);
            debug!(
                "privileged stdio helper: capturing stderr to {}",
                log_path.display()
            );
        } else {
            command.stderr(Stdio::inherit());
        }

        debug!(
            elevation = ?elevation.display_name(),
            interactive = interactive,
            "privileged_stdio_helper_spawn_begin"
        );
        let mut child = command
            .spawn()
            .map_err(|e| elevation.map_spawn_error(e, self.manual_start_command()))?;
        debug!( pid = ?child.id(), "privileged_stdio_helper_spawned");
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AppError::Other("failed to capture privileged stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AppError::Other("failed to capture privileged stdout".to_string()))?;

        Ok(StdioSession {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn elevated_daemon_command(&self, elevation: &Elevation, interactive: bool) -> Result<Command> {
        let exe = crate::shared::executable::cli_executable()
            .map_err(|e| AppError::Other(format!("cannot resolve current executable: {}", e)))?;
        elevation
            .command(&exe, &self.daemon_args(), interactive)
            .ok_or_else(|| {
                AppError::Other(format!(
                    "{} cannot run without a password prompt{}; run: {}",
                    elevation.display_name().unwrap_or_default(),
                    prompt_hint(elevation, interactive),
                    self.manual_start_command()
                ))
            })
    }

    fn daemon_args(&self) -> Vec<String> {
        let mode = match self.transport {
            PrivilegedTransport::Stdio => "--stdio",
            PrivilegedTransport::Socket => "--detach",
        };
        let mut args: Vec<String> = ["privileged", "--serve", mode, "--autostarted"]
            .into_iter()
            .map(str::to_string)
            .collect();
        args.push("--authorized-group".to_string());
        args.push(self.authorized_group.clone());
        args.extend(crate::logging::forwarded_args());
        if let Some(idle_timeout_ms) = self.daemon_idle_timeout_ms {
            args.push("--idle-timeout-ms".to_string());
            args.push(idle_timeout_ms.to_string());
        }
        args
    }

    fn wait_until_ready(&self) -> Result<()> {
        debug!(
            "privileged ctl readiness wait timeout_ms={}",
            self.autostart_timeout.as_millis()
        );
        let deadline = Instant::now() + self.autostart_timeout;
        loop {
            match self.readiness_probe_once() {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => return Err(e),
            }

            if Instant::now() >= deadline {
                return Err(AppError::Other(format!(
                    "startup timeout waiting for privileged daemon readiness; run: {}",
                    self.manual_start_command()
                )));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn readiness_probe_once(&self) -> Result<bool> {
        let mut stream = match self.try_connect_socket() {
            Ok(stream) => stream,
            Err(e) if is_autostart_connect_error(&e) => return Ok(false),
            Err(e) => {
                return Err(AppError::Other(format!(
                    "failed while probing privileged daemon socket: {}",
                    e
                )));
            }
        };

        let probe = PrivilegedRequest::NamespaceExists {
            name: "tunmux_probe".to_string(),
        };
        match self.send_on_stream(&mut stream, &probe) {
            Ok(_) => Ok(true),
            Err(AppError::Auth(message)) => Err(AppError::Other(format!(
                "authorization denied by privileged daemon: {}; run: {}",
                message,
                self.manual_start_command()
            ))),
            Err(AppError::Other(message))
                if message.starts_with("read response:")
                    || message.starts_with("decode response:")
                    || message == "empty response from privileged server" =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn try_connect_socket(&self) -> std::io::Result<UnixStream> {
        crate::wireguard::health::connect_probe(&self.socket_path)
    }

    pub(crate) fn manual_start_command(&self) -> String {
        let exe =
            crate::shared::executable::cli_executable().unwrap_or_else(|_| PathBuf::from("tunmux"));
        let stdio = if matches!(self.transport, PrivilegedTransport::Stdio) {
            " --stdio"
        } else {
            ""
        };
        let prefix = Elevation::resolve(&self.elevation)
            .map(|elevation| elevation.manual_prefix())
            .unwrap_or_else(|_| "sudo ".to_string());
        format!(
            "{}{} privileged --serve{} --authorized-group {}{}",
            prefix,
            shell_quote(&exe.to_string_lossy()),
            stdio,
            shell_quote(&self.authorized_group),
            self.daemon_idle_timeout_ms
                .map(|ms| format!(" --idle-timeout-ms {}", ms))
                .unwrap_or_default()
        )
    }

    pub(crate) fn send_on_stream(
        &self,
        stream: &mut UnixStream,
        request: &PrivilegedRequest,
    ) -> Result<super::PrivilegedResponse> {
        tracing::trace!( request = ?request_kind(request), "privileged_ctl_write");
        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| AppError::Other(format!("serialize request: {}", e)))?;
        let mut writer = stream
            .try_clone()
            .map_err(|e| AppError::Other(format!("read response: {e}")))?;
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| AppError::Other(format!("read response: {e}")))?,
        );
        let response_line = bounded_exchange(
            &mut writer,
            &mut reader,
            &request_bytes,
            request_timeout(request),
        )
        .map_err(|e| AppError::Other(format!("read response: {e}")))?;
        let response = serde_json::from_str(&response_line)
            .map_err(|e| AppError::Other(format!("decode response: {e}")))?;
        super::map_privileged_error(response)
    }

    pub(crate) fn send_on_stdio_session(
        &self,
        session: &mut StdioSession,
        request: &PrivilegedRequest,
    ) -> Result<super::PrivilegedResponse> {
        tracing::trace!(
            request = ?request_kind(request), "privileged_ctl_stdio_write");
        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| AppError::Other(format!("serialize request: {}", e)))?;
        let response_line = bounded_exchange(
            &mut session.stdin,
            &mut session.stdout,
            &request_bytes,
            request_timeout(request),
        )
        .map_err(|e| AppError::Other(format!("read response: {e}")))?;
        let response = serde_json::from_str(&response_line)
            .map_err(|e| AppError::Other(format!("decode response: {e}")))?;
        super::map_privileged_error(response)
    }
}

fn request_timeout(request: &PrivilegedRequest) -> Duration {
    match request {
        PrivilegedRequest::Capabilities
        | PrivilegedRequest::InspectSession { .. }
        | PrivilegedRequest::WgShow { .. }
        | PrivilegedRequest::LeaseAcquire { .. }
        | PrivilegedRequest::LeaseRelease { .. }
        | PrivilegedRequest::ShutdownIfIdle
        | PrivilegedRequest::NamespaceExists { .. } => Duration::from_secs(2),
        PrivilegedRequest::RecoverSession { .. } => Duration::from_secs(65),
        _ => Duration::from_secs(150),
    }
}

/// A duplicate keeps the shared file description alive until its original flags are restored.
struct NonblockingGuard {
    descriptor: std::os::fd::OwnedFd,
    flags: libc::c_int,
}

impl NonblockingGuard {
    fn new(descriptor: std::os::fd::RawFd) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;
        let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) };
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    descriptor.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { descriptor, flags })
    }
}

impl Drop for NonblockingGuard {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.descriptor.as_raw_fd(), libc::F_SETFL, self.flags);
        }
    }
}

fn bounded_exchange<W: Write + AsRawFd, R: std::io::Read + AsRawFd>(
    writer: &mut W,
    reader: &mut BufReader<R>,
    request: &[u8],
    timeout: Duration,
) -> std::io::Result<String> {
    let deadline = Instant::now() + timeout;
    let _write_flags = NonblockingGuard::new(writer.as_raw_fd())?;
    let _read_flags = NonblockingGuard::new(reader.get_ref().as_raw_fd())?;
    let retry = || -> std::io::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "privileged response deadline expired",
            ));
        }
        thread::sleep(remaining.min(Duration::from_millis(5)));
        Ok(())
    };
    let mut request = request.to_vec();
    if request.last() != Some(&b'\n') {
        request.push(b'\n');
    }
    let mut pending = request.as_slice();
    while !pending.is_empty() {
        if Instant::now() >= deadline {
            retry()?;
        }
        match writer.write(pending) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => pending = &pending[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                retry()?
            }
            Err(error) => return Err(error),
        }
    }
    loop {
        if Instant::now() >= deadline {
            retry()?;
        }
        match writer.flush() {
            Ok(()) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                retry()?
            }
            Err(error) => return Err(error),
        }
    }
    let mut response = Vec::new();
    loop {
        if Instant::now() >= deadline {
            retry()?;
        }
        let available = match reader.fill_buf() {
            Ok([]) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "privileged response ended before newline",
                ))
            }
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                retry()?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if response.len() + count > 256 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "privileged response exceeds 256 KiB",
            ));
        }
        response.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            return String::from_utf8(response)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
        }
    }
}

fn open_stdio_log(log_path: &std::path::Path) -> Result<(fs::File, fs::File)> {
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| {
            AppError::Other(format!(
                "failed to open privileged stdio log {}: {}",
                log_path.display(),
                e
            ))
        })?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| AppError::Other(format!("failed to clone log fd: {}", e)))?;
    Ok((log_file, log_file_err))
}

fn via_elevation(elevation: &Elevation) -> String {
    elevation
        .display_name()
        .map(|name| format!(" via {}", name))
        .unwrap_or_default()
}

fn prompt_hint(elevation: &Elevation, interactive: bool) -> &'static str {
    if interactive || matches!(elevation, Elevation::Direct) {
        ""
    } else {
        " (password prompts unavailable: no TTY or passwordless elevation)"
    }
}

#[cfg(test)]
mod inspection_deadline_tests {
    use super::*;

    fn exchange(
        response: &[u8],
        delay: Duration,
        trickle: bool,
        timeout: Duration,
    ) -> std::io::Result<String> {
        let (client, mut server) = UnixStream::pair().unwrap();
        let mut writer = client.try_clone().unwrap();
        let response = response.to_vec();
        let worker = thread::spawn(move || {
            use std::io::Read;
            let mut request = [0];
            server.read_exact(&mut request).unwrap();
            if trickle {
                for byte in response {
                    thread::sleep(delay);
                    if server.write_all(&[byte]).is_err() {
                        break;
                    }
                }
            } else {
                thread::sleep(delay);
                let _ = server.write_all(&response);
            }
        });
        let before = unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFL) };
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let result = bounded_exchange(&mut writer, &mut reader, b"\n", timeout);
        assert_eq!(
            unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFL) },
            before
        );
        drop(reader);
        drop(client);
        drop(writer);
        worker.join().unwrap();
        result
    }

    #[test]
    fn stalled_inspection_has_deadline() {
        assert_eq!(
            exchange(
                b"ok\n",
                Duration::from_millis(80),
                false,
                Duration::from_millis(20)
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn trickled_inspection_does_not_reset_deadline() {
        assert_eq!(
            exchange(
                b"okay\n",
                Duration::from_millis(25),
                true,
                Duration::from_millis(60)
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn inspection_rejects_eof_before_newline() {
        assert_eq!(
            exchange(b"ok", Duration::ZERO, false, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn inspection_caps_response_and_restores_flags() {
        assert!(exchange(
            &vec![b'x'; 256 * 1024 + 1],
            Duration::ZERO,
            false,
            Duration::from_secs(1)
        )
        .unwrap_err()
        .to_string()
        .contains("256 KiB"));
        assert_eq!(
            exchange(b"ok\n", Duration::ZERO, false, Duration::from_secs(1)).unwrap(),
            "ok\n"
        );
    }
}

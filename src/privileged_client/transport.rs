use std::io::IsTerminal;
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

use super::util::{
    configured_privileged_stdio_log_path, map_sudo_spawn_error, request_kind,
    run_sudo_validate_with_timeout, shell_quote, startup_lock_dir, stderr_requires_password,
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
            Ok(stream) => {
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

        self.autostart_daemon()?;
        self.try_connect_socket().map_err(|e| {
            AppError::Other(format!(
                "privileged socket unavailable after autostart: {}; run: {}",
                e,
                self.manual_start_command()
            ))
        })
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
        const SUDO_PROMPT_TIMEOUT: Duration = Duration::from_secs(90);
        debug!("privileged_daemon_start_non_interactive_launch_attempt");
        if self.run_sudo_non_interactive_launch()? {
            debug!("privileged_daemon_start_non_interactive_launch_ok");
            return Ok(());
        }

        let probe = self.run_sudo_non_interactive_probe()?;
        let stderr = String::from_utf8_lossy(&probe.stderr);
        if !stderr_requires_password(&stderr) {
            debug!(
                "privileged daemon start: non-interactive launch failed without password-prompt hint stderr={}",
                stderr.trim()
            );
            return Err(AppError::Other(format!(
                "failed to start privileged daemon via sudo: {}; run: {}",
                stderr.trim(),
                self.manual_start_command()
            )));
        }

        if !std::io::stdin().is_terminal() {
            debug!("privileged_daemon_start_password_required_no_tty");
            return Err(AppError::Other(format!(
                "sudo password required but no TTY available; run: {}",
                self.manual_start_command()
            )));
        }

        eprintln!("sudo authentication required for tunmux privileged autostart.");
        debug!(
            "privileged daemon start: running sudo -v with timeout={}s",
            SUDO_PROMPT_TIMEOUT.as_secs()
        );
        let validate = run_sudo_validate_with_timeout(SUDO_PROMPT_TIMEOUT)
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))?;
        if !validate {
            debug!("privileged_daemon_start_sudo_validate_failed");
            return Err(AppError::Other(format!(
                "sudo authentication failed; run: {}",
                self.manual_start_command()
            )));
        }

        debug!("privileged_daemon_start_retry_non_interactive_after_validate");
        if self.run_sudo_non_interactive_launch()? {
            debug!("privileged_daemon_start_retry_launch_ok");
            return Ok(());
        }
        let retry_probe = self.run_sudo_non_interactive_probe()?;
        let retry_stderr = String::from_utf8_lossy(&retry_probe.stderr)
            .trim()
            .to_string();
        debug!(
            "privileged daemon start: retry launch failed stderr={}",
            retry_stderr
        );
        Err(AppError::Other(format!(
            "failed to start privileged daemon after sudo auth: {}; run: {}",
            retry_stderr,
            self.manual_start_command()
        )))
    }

    fn run_sudo_non_interactive_launch(&self) -> Result<bool> {
        let exe = std::env::current_exe()
            .map_err(|e| AppError::Other(format!("cannot resolve current executable: {}", e)))?;
        let mut command = Command::new("sudo");
        command
            .arg("-n")
            .arg("-b")
            .arg(exe)
            .arg("privileged")
            .arg("--serve")
            .arg("--autostarted")
            .arg("--authorized-group")
            .arg(self.authorized_group.as_str());
        if crate::logging::debug_enabled() {
            command.arg("--debug");
        }
        if let Some(idle_timeout_ms) = self.daemon_idle_timeout_ms {
            command
                .arg("--idle-timeout-ms")
                .arg(idle_timeout_ms.to_string());
        }
        // Detach the daemon's stdio. It is a long-lived background service; if it inherited the
        // foreground process's stdout/stderr it would hold those fds (e.g. a `| tee` pipe) open
        // for its whole lifetime, so the shell pipeline would never see EOF and would hang long
        // after this command exited. Capture to the configured log file when set, else /dev/null.
        command.stdin(Stdio::null());
        if let Some(log_path) = configured_privileged_stdio_log_path() {
            if let Some(parent) = log_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let log_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
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
            command.stdout(Stdio::from(log_file));
            command.stderr(Stdio::from(log_file_err));
            debug!(
                "privileged daemon start: capturing sudo/daemon stdio to {}",
                log_path.display()
            );
        } else {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }
        debug!(cmd = "sudo -n -b tunmux privileged --serve", "exec");
        let status = command
            .status()
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))?;
        Ok(status.success())
    }

    fn run_sudo_non_interactive_probe(&self) -> Result<std::process::Output> {
        debug!(cmd = "sudo -n -v", "exec");
        Command::new("sudo")
            .arg("-n")
            .arg("-v")
            .output()
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))
    }

    pub(crate) fn spawn_privileged_stdio_session(&self) -> Result<StdioSession> {
        const SUDO_PROMPT_TIMEOUT: Duration = Duration::from_secs(90);

        let probe = self.run_sudo_non_interactive_probe()?;
        if !probe.status.success() {
            let stderr = String::from_utf8_lossy(&probe.stderr);
            if !stderr_requires_password(&stderr) {
                return Err(AppError::Other(format!(
                    "failed to start privileged stdio helper via sudo: {}; run: {}",
                    stderr.trim(),
                    self.manual_start_command()
                )));
            }
            if !std::io::stdin().is_terminal() {
                return Err(AppError::Other(format!(
                    "sudo password required but no TTY available; run: {}",
                    self.manual_start_command()
                )));
            }

            eprintln!("sudo authentication required for tunmux privileged stdio mode.");
            let validate = run_sudo_validate_with_timeout(SUDO_PROMPT_TIMEOUT)
                .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))?;
            if !validate {
                return Err(AppError::Other(format!(
                    "sudo authentication failed; run: {}",
                    self.manual_start_command()
                )));
            }
        }

        self.spawn_privileged_stdio_session_non_interactive()
    }

    fn spawn_privileged_stdio_session_non_interactive(&self) -> Result<StdioSession> {
        let exe = std::env::current_exe()
            .map_err(|e| AppError::Other(format!("cannot resolve current executable: {}", e)))?;

        debug!("privileged_stdio_helper_spawn_begin");
        let mut command = Command::new("sudo");
        command
            .arg("-n")
            .arg(exe)
            .arg("privileged")
            .arg("--serve")
            .arg("--stdio")
            .arg("--autostarted")
            .arg("--authorized-group")
            .arg(self.authorized_group.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if crate::logging::debug_enabled() {
            command.arg("--debug");
        }

        if let Some(idle_timeout_ms) = self.daemon_idle_timeout_ms {
            command
                .arg("--idle-timeout-ms")
                .arg(idle_timeout_ms.to_string());
        }

        if let Some(log_path) = configured_privileged_stdio_log_path() {
            if let Some(parent) = log_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let log_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| {
                    AppError::Other(format!(
                        "failed to open privileged stdio log {}: {}",
                        log_path.display(),
                        e
                    ))
                })?;
            command.stderr(Stdio::from(log_file));
            debug!(
                "privileged stdio helper: capturing stderr to {}",
                log_path.display()
            );
        } else {
            command.stderr(Stdio::inherit());
        }

        let mut child = command
            .spawn()
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))?;
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
        UnixStream::connect(&self.socket_path)
    }

    pub(crate) fn manual_start_command(&self) -> String {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tunmux"));
        let stdio = if matches!(self.transport, PrivilegedTransport::Stdio) {
            " --stdio"
        } else {
            ""
        };
        format!(
            "sudo {} privileged --serve{} --authorized-group {}{}",
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
        stream
            .write_all(&request_bytes)
            .map_err(|e| AppError::Other(format!("write request: {}", e)))?;
        stream
            .write_all(b"\n")
            .map_err(|e| AppError::Other(format!("write request delimiter: {}", e)))?;
        stream
            .flush()
            .map_err(|e| AppError::Other(format!("flush request: {}", e)))?;

        let mut reader = BufReader::new(stream);
        let response = read_framed_response(&mut reader)?;
        tracing::trace!( request = ?request_kind(request), "privileged_ctl_response");

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
        session
            .stdin
            .write_all(&request_bytes)
            .map_err(|e| AppError::Other(format!("write request stdin: {}", e)))?;
        session
            .stdin
            .write_all(b"\n")
            .map_err(|e| AppError::Other(format!("write request delimiter stdin: {}", e)))?;
        session
            .stdin
            .flush()
            .map_err(|e| AppError::Other(format!("flush request stdin: {}", e)))?;

        let response = read_framed_response(&mut session.stdout)?;
        tracing::trace!(
            request = ?request_kind(request), "privileged_ctl_stdio_response");
        super::map_privileged_error(response)
    }
}

/// Read the server's reply, which is zero or more log frames (`{"log":"…"}`) followed by exactly
/// one response frame (`{"kind":…}`). Log frames are printed to stderr (so the operation's
/// privileged-side logs appear in the caller's terminal); the response frame is returned.
///
/// Backward compatible: an older server that sends only a response produces no log frames, so the
/// first line is parsed as the response.
fn read_framed_response<R: BufRead>(reader: &mut R) -> Result<super::PrivilegedResponse> {
    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| AppError::Other(format!("read response: {}", e)))?;
        if bytes == 0 {
            return Err(AppError::Other(
                "privileged server closed connection before responding".into(),
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // One deserialize per line: a log frame (`{"log":"…"}`) and a response frame
        // (`{"kind":…}`) are structurally disjoint, so an untagged enum picks the right one.
        match serde_json::from_str::<Frame>(trimmed)
            .map_err(|e| AppError::Other(format!("decode response: {}", e)))?
        {
            Frame::Log { log } => eprintln!("{log}"),
            Frame::Response(response) => return Ok(response),
        }
    }
}

/// One newline-delimited reply frame: either a streamed log line or the final response.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Frame {
    Log { log: String },
    Response(super::PrivilegedResponse),
}

#[cfg(test)]
mod tests {
    use super::super::PrivilegedResponse;
    use super::{read_framed_response, Frame};
    use std::io::Cursor;

    fn reader(s: &str) -> Cursor<Vec<u8>> {
        Cursor::new(s.as_bytes().to_vec())
    }

    #[test]
    fn reads_lone_response_frame() {
        // Backward compatible: a server that sends only a response (no logs) still works.
        let mut r = reader("{\"kind\":\"unit\"}\n");
        assert!(matches!(
            read_framed_response(&mut r).unwrap(),
            PrivilegedResponse::Unit
        ));
    }

    #[test]
    fn skips_log_frames_then_returns_response() {
        let input =
            "{\"log\":\"first\"}\n{\"log\":\"second\"}\n{\"kind\":\"bool\",\"value\":true}\n";
        let mut r = reader(input);
        assert!(matches!(
            read_framed_response(&mut r).unwrap(),
            PrivilegedResponse::Bool(true)
        ));
    }

    #[test]
    fn log_and_response_frames_are_disjoint() {
        // The response frame must not be misread as a log frame, and vice versa.
        let log: Frame = serde_json::from_str("{\"log\":\"hi\"}").unwrap();
        assert!(matches!(log, Frame::Log { .. }));
        let resp: Frame = serde_json::from_str("{\"kind\":\"unit\"}").unwrap();
        assert!(matches!(resp, Frame::Response(PrivilegedResponse::Unit)));
    }

    #[test]
    fn errors_when_closed_before_response() {
        let mut r = reader("{\"log\":\"only a log\"}\n");
        assert!(read_framed_response(&mut r).is_err());
    }
}

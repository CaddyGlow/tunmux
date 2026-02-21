use std::io::IsTerminal;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nix::libc;
use nix::unistd::Uid;
#[cfg(not(target_os = "android"))]
use nix::unistd::{Gid, Group};
use tracing::debug;

use crate::config;
use crate::config::{PrivilegedAutostopMode, PrivilegedTransport};
use crate::error::{AppError, Result};

use crate::privileged_api::{
    GotaTunAction, KillSignal, PrivilegedRequest, PrivilegedResponse, WgQuickAction,
};

const FALLBACK_AUTH_GROUP: &str = "tunmux";

pub struct PrivilegedClient {
    socket_path: PathBuf,
    transport: PrivilegedTransport,
    autostart_enabled: bool,
    autostart_timeout: Duration,
    authorized_group: String,
    autostop_mode: PrivilegedAutostopMode,
    daemon_idle_timeout_ms: Option<u64>,
}

#[derive(Default)]
struct CommandSessionState {
    enabled_count: usize,
    lease_token: Option<String>,
    transport: Option<CommandSessionTransport>,
}

enum CommandSessionTransport {
    Socket(UnixStream),
    Stdio(StdioSession),
}

struct StdioSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl StdioSession {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn shutdown(mut self) {
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

fn command_session_state() -> &'static Mutex<CommandSessionState> {
    static COMMAND_SESSION: OnceLock<Mutex<CommandSessionState>> = OnceLock::new();
    COMMAND_SESSION.get_or_init(|| Mutex::new(CommandSessionState::default()))
}

pub struct CommandScopeGuard {
    enabled: bool,
}

impl CommandScopeGuard {
    pub fn begin(_mode: PrivilegedAutostopMode) -> Self {
        if let Ok(mut state) = command_session_state().lock() {
            state.enabled_count = state.enabled_count.saturating_add(1);
        }
        Self { enabled: true }
    }
}

impl Drop for CommandScopeGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }

        let mut token_to_release = None;
        let mut session_transport = None;
        if let Ok(mut state) = command_session_state().lock() {
            if state.enabled_count > 0 {
                state.enabled_count -= 1;
            }
            if state.enabled_count == 0 {
                token_to_release = state.lease_token.take();
                session_transport = state.transport.take();
            }
        }

        let client = PrivilegedClient::new();
        if let Some(mut transport) = session_transport.take() {
            debug!("privileged_command_scoped_transport_closing");
            if let Some(token) = token_to_release {
                debug!("privileged_daemon_release_command_lease_on_scoped_transport");
                let token_for_fallback = token.clone();
                if client
                    .send_on_transport(&mut transport, &PrivilegedRequest::LeaseRelease { token })
                    .is_err()
                    && matches!(client.transport, PrivilegedTransport::Socket)
                {
                    let _ = client.send_control_request_if_connected(
                        &PrivilegedRequest::LeaseRelease {
                            token: token_for_fallback,
                        },
                    );
                }
                debug!("privileged_daemon_request_shutdown_if_idle");
                if client
                    .send_on_transport(&mut transport, &PrivilegedRequest::ShutdownIfIdle)
                    .is_err()
                    && matches!(client.transport, PrivilegedTransport::Socket)
                {
                    let _ = client
                        .send_control_request_if_connected(&PrivilegedRequest::ShutdownIfIdle);
                }
            }
            client.close_transport(transport);
            return;
        }

        if let Some(token) = token_to_release {
            if matches!(client.transport, PrivilegedTransport::Socket) {
                debug!("privileged_daemon_release_command_lease");
                let _ = client
                    .send_control_request_if_connected(&PrivilegedRequest::LeaseRelease { token });
                debug!("privileged_daemon_request_shutdown_if_idle");
                let _ =
                    client.send_control_request_if_connected(&PrivilegedRequest::ShutdownIfIdle);
            }
        }
    }
}

impl PrivilegedClient {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let cfg = config::load_config();
        let autostop_mode = cfg.general.privileged_autostop_mode;
        let timeout_ms = cfg.general.privileged_autostart_timeout_ms.max(100);
        let daemon_idle_timeout_ms = if matches!(autostop_mode, PrivilegedAutostopMode::Timeout) {
            Some(cfg.general.privileged_autostop_timeout_ms.max(100))
        } else {
            None
        };
        Self {
            socket_path: config::privileged_socket_path(),
            transport: cfg.general.privileged_transport,
            autostart_enabled: cfg.general.privileged_autostart,
            autostart_timeout: Duration::from_millis(timeout_ms),
            authorized_group: resolve_client_authorized_group(
                cfg.general.privileged_authorized_group.as_str(),
            ),
            autostop_mode,
            daemon_idle_timeout_ms,
        }
    }

    pub fn namespace_create(&self, name: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::NamespaceCreate {
            name: name.to_string(),
        })
    }

    pub fn namespace_delete(&self, name: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::NamespaceDelete {
            name: name.to_string(),
        })
    }

    pub fn interface_create_wireguard(&self, name: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::InterfaceCreateWireguard {
            name: name.to_string(),
        })
    }

    pub fn interface_delete(&self, name: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::InterfaceDelete {
            name: name.to_string(),
        })
    }

    pub fn interface_move_to_netns(&self, interface: &str, namespace: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::InterfaceMoveToNetns {
            interface: interface.to_string(),
            namespace: namespace.to_string(),
        })
    }

    pub fn netns_exec(&self, namespace: &str, args: &[&str]) -> Result<()> {
        self.send(PrivilegedRequest::NetnsExec {
            namespace: namespace.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        })
        .map(|_| ())
    }

    pub fn host_ip_addr_add(&self, interface: &str, cidr: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::HostIpAddrAdd {
            interface: interface.to_string(),
            cidr: cidr.to_string(),
        })
    }

    pub fn host_ip_link_set_up(&self, interface: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::HostIpLinkSetUp {
            interface: interface.to_string(),
        })
    }

    pub fn host_ip_route_add(&self, destination: &str, via: Option<&str>, dev: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::HostIpRouteAdd {
            destination: destination.to_string(),
            via: via.map(ToString::to_string),
            dev: dev.to_string(),
        })
    }

    pub fn host_ip_route_del(&self, destination: &str, via: Option<&str>, dev: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::HostIpRouteDel {
            destination: destination.to_string(),
            via: via.map(ToString::to_string),
            dev: dev.to_string(),
        })
    }

    pub fn wireguard_set(
        &self,
        interface: &str,
        private_key: &str,
        peer_public_key: &str,
        endpoint: &str,
        allowed_ips: &str,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::WireguardSet {
            interface: interface.to_string(),
            private_key: private_key.to_string(),
            peer_public_key: peer_public_key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ips: allowed_ips.to_string(),
        })
    }

    pub fn wireguard_set_psk(
        &self,
        interface: &str,
        peer_public_key: &str,
        psk: &str,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::WireguardSetPsk {
            interface: interface.to_string(),
            peer_public_key: peer_public_key.to_string(),
            psk: psk.to_string(),
        })
    }

    pub fn wg_quick_run(
        &self,
        action: WgQuickAction,
        interface: &str,
        provider: &str,
        config_content: &str,
        prefer_userspace: bool,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::WgQuickRun {
            action,
            interface: interface.to_string(),
            provider: provider.to_string(),
            config_content: config_content.to_string(),
            prefer_userspace,
        })
    }

    pub fn gotatun_run(
        &self,
        action: GotaTunAction,
        interface: &str,
        config_content: &str,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::GotaTunRun {
            action,
            interface: interface.to_string(),
            config_content: config_content.to_string(),
        })
    }

    /// Run `wg show <interface>` as root and return the output.
    /// Works for kernel, wg-quick, and userspace (gotatun) backends.
    #[allow(dead_code)]
    pub fn wg_show(&self, interface: &str) -> Result<String> {
        match self.send(PrivilegedRequest::WgShow {
            interface: interface.to_string(),
        })? {
            PrivilegedResponse::Text(output) => Ok(output),
            _ => Err(AppError::Other(
                "invalid privileged response for WgShow".into(),
            )),
        }
    }

    pub fn ensure_dir(&self, path: &str, mode: u32) -> Result<()> {
        self.send_unit(PrivilegedRequest::EnsureDir {
            path: path.to_string(),
            mode,
        })
    }

    pub fn write_file(&self, path: &str, contents: &[u8], mode: u32) -> Result<()> {
        self.send_unit(PrivilegedRequest::WriteFile {
            path: path.to_string(),
            contents: contents.to_vec(),
            mode,
        })
    }

    pub fn remove_dir_all(&self, path: &str) -> Result<()> {
        self.send_unit(PrivilegedRequest::RemoveDirAll {
            path: path.to_string(),
        })
    }

    pub fn kill_pid(&self, pid: u32, signal: KillSignal) -> Result<()> {
        self.send_unit(PrivilegedRequest::KillPid { pid, signal })
    }

    pub fn spawn_proxy_daemon(
        &self,
        netns: &str,
        socks_port: u16,
        http_port: u16,
        proxy_access_log: bool,
        pid_file: &str,
        log_file: &str,
    ) -> Result<u32> {
        match self.send(PrivilegedRequest::SpawnProxyDaemon {
            netns: netns.to_string(),
            socks_port,
            http_port,
            proxy_access_log,
            pid_file: pid_file.to_string(),
            log_file: log_file.to_string(),
        })? {
            PrivilegedResponse::Pid(pid) => Ok(pid),
            _ => Err(AppError::Other(
                "invalid privileged response for SpawnProxyDaemon".into(),
            )),
        }
    }

    fn send_unit(&self, request: PrivilegedRequest) -> Result<()> {
        self.send(request).map(|_| ())
    }

    fn send(&self, request: PrivilegedRequest) -> Result<PrivilegedResponse> {
        request.validate().map_err(AppError::Other)?;
        tracing::trace!( request = ?request_kind(&request), "privileged_ctl_request");
        if self.command_session_enabled()? {
            return self.send_with_command_session(&request);
        }

        match self.transport {
            PrivilegedTransport::Socket => {
                self.ensure_command_lease_if_enabled()?;
                let mut stream = self.connect_or_autostart()?;
                self.send_on_stream(&mut stream, &request)
            }
            PrivilegedTransport::Stdio => {
                let mut session = self.spawn_privileged_stdio_session()?;
                let response = self.send_on_stdio_session(&mut session, &request);
                session.shutdown();
                response
            }
        }
    }

    fn command_session_enabled(&self) -> Result<bool> {
        let state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        Ok(state.enabled_count > 0)
    }

    fn send_with_command_session(&self, request: &PrivilegedRequest) -> Result<PrivilegedResponse> {
        let mut state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        self.ensure_command_lease_in_session(&mut state)?;
        let response = self.send_on_session_transport(&mut state, request);
        if let Err(err) = &response {
            if is_transport_error(err) {
                if let Some(transport) = state.transport.take() {
                    self.close_transport(transport);
                }
            }
        }
        response
    }

    fn ensure_command_lease_in_session(&self, state: &mut CommandSessionState) -> Result<()> {
        if !matches!(self.autostop_mode, PrivilegedAutostopMode::Command)
            || state.lease_token.is_some()
        {
            return Ok(());
        }
        let token = build_lease_token();
        self.send_on_session_transport(
            state,
            &PrivilegedRequest::LeaseAcquire {
                token: token.clone(),
            },
        )?;
        state.lease_token = Some(token);
        Ok(())
    }

    fn send_on_session_transport(
        &self,
        state: &mut CommandSessionState,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
        if state.transport.is_none() {
            state.transport = Some(self.open_transport()?);
        }
        let transport = state
            .transport
            .as_mut()
            .ok_or_else(|| AppError::Other("command-scoped transport unavailable".to_string()))?;
        self.send_on_transport(transport, request)
    }

    fn open_transport(&self) -> Result<CommandSessionTransport> {
        match self.transport {
            PrivilegedTransport::Socket => {
                debug!( mode = ?"socket", "privileged_command_transport_open");
                self.connect_or_autostart()
                    .map(CommandSessionTransport::Socket)
            }
            PrivilegedTransport::Stdio => {
                debug!( mode = ?"stdio", "privileged_command_transport_open");
                self.spawn_privileged_stdio_session()
                    .map(CommandSessionTransport::Stdio)
            }
        }
    }

    fn close_transport(&self, transport: CommandSessionTransport) {
        match transport {
            CommandSessionTransport::Socket(_) => {
                debug!( mode = ?"socket", "privileged_command_transport_closed");
            }
            CommandSessionTransport::Stdio(session) => {
                debug!(
                    mode = ?"stdio",
                    pid = ?session.pid(), "privileged_command_transport_closed");
                session.shutdown();
            }
        }
    }

    fn send_on_transport(
        &self,
        transport: &mut CommandSessionTransport,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
        match transport {
            CommandSessionTransport::Socket(stream) => self.send_on_stream(stream, request),
            CommandSessionTransport::Stdio(session) => self.send_on_stdio_session(session, request),
        }
    }

    fn send_on_stream(
        &self,
        stream: &mut UnixStream,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
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
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| AppError::Other(format!("read response: {}", e)))?;
        if response_line.trim().is_empty() {
            return Err(AppError::Other(
                "empty response from privileged server".into(),
            ));
        }
        let response: PrivilegedResponse = serde_json::from_str(&response_line)
            .map_err(|e| AppError::Other(format!("decode response: {}", e)))?;
        tracing::trace!( request = ?request_kind(request), "privileged_ctl_response");

        map_privileged_error(response)
    }

    fn send_on_stdio_session(
        &self,
        session: &mut StdioSession,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
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

        let mut response_line = String::new();
        session
            .stdout
            .read_line(&mut response_line)
            .map_err(|e| AppError::Other(format!("read response stdout: {}", e)))?;
        if response_line.trim().is_empty() {
            return Err(AppError::Other(
                "empty response from privileged server".into(),
            ));
        }
        let response: PrivilegedResponse = serde_json::from_str(&response_line)
            .map_err(|e| AppError::Other(format!("decode response: {}", e)))?;
        tracing::trace!(
            request = ?request_kind(request), "privileged_ctl_stdio_response");
        map_privileged_error(response)
    }

    fn ensure_command_lease_if_enabled(&self) -> Result<()> {
        if !matches!(self.autostop_mode, PrivilegedAutostopMode::Command) {
            return Ok(());
        }

        {
            let state = command_session_state()
                .lock()
                .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
            if state.enabled_count == 0 || state.lease_token.is_some() {
                return Ok(());
            }
        }

        let token = build_lease_token();
        self.send_control_request_with_autostart(&PrivilegedRequest::LeaseAcquire {
            token: token.clone(),
        })?;

        let mut state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        if state.enabled_count > 0 {
            state.lease_token = Some(token);
        } else {
            drop(state);
            let _ =
                self.send_control_request_if_connected(&PrivilegedRequest::LeaseRelease { token });
        }
        Ok(())
    }

    fn send_control_request_with_autostart(&self, request: &PrivilegedRequest) -> Result<()> {
        let mut stream = self.connect_or_autostart()?;
        self.send_on_stream(&mut stream, request).map(|_| ())
    }

    fn send_control_request_if_connected(&self, request: &PrivilegedRequest) -> Result<()> {
        let mut stream = match self.try_connect_socket() {
            Ok(stream) => stream,
            Err(e) if is_autostart_connect_error(&e) => return Ok(()),
            Err(e) => {
                return Err(AppError::Other(format!(
                    "failed to connect to privileged socket: {}",
                    e
                )))
            }
        };
        self.send_on_stream(&mut stream, request).map(|_| ())
    }

    fn connect_or_autostart(&self) -> Result<UnixStream> {
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
            let log_file_err = log_file
                .try_clone()
                .map_err(|e| AppError::Other(format!("failed to clone log fd: {}", e)))?;
            command.stdout(Stdio::from(log_file));
            command.stderr(Stdio::from(log_file_err));
            debug!(
                "privileged daemon start: capturing sudo/daemon stdio to {}",
                log_path.display()
            );
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

    fn spawn_privileged_stdio_session(&self) -> Result<StdioSession> {
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

    fn try_connect_socket(&self) -> std::io::Result<UnixStream> {
        UnixStream::connect(&self.socket_path)
    }

    fn manual_start_command(&self) -> String {
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
}

fn map_privileged_error(response: PrivilegedResponse) -> Result<PrivilegedResponse> {
    match response {
        PrivilegedResponse::Error { code, message } => Err(match code.as_str() {
            "Namespace" => AppError::Namespace(message),
            "WireGuard" => AppError::WireGuard(message),
            "Proxy" => AppError::Proxy(message),
            "Auth" => AppError::Auth(message),
            "Control" => AppError::Other(message),
            _ => AppError::Other(message),
        }),
        other => Ok(other),
    }
}

fn is_autostart_connect_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
        || err.kind() == std::io::ErrorKind::ConnectionRefused
        || err.kind() == std::io::ErrorKind::PermissionDenied
}

fn is_transport_error(err: &AppError) -> bool {
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

fn stderr_requires_password(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("password is required")
        || lower.contains("a password is required")
        || lower.contains("a terminal is required")
        || lower.contains("no tty")
}

fn resolve_client_authorized_group(configured_group: &str) -> String {
    let configured = configured_group.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    current_user_primary_group_name().unwrap_or_else(|| FALLBACK_AUTH_GROUP.to_string())
}

#[cfg(not(target_os = "android"))]
fn current_user_primary_group_name() -> Option<String> {
    Group::from_gid(Gid::current())
        .ok()
        .flatten()
        .and_then(|group| {
            let name = group.name.trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
}

#[cfg(target_os = "android")]
fn current_user_primary_group_name() -> Option<String> {
    None
}

fn startup_lock_dir() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("tunmux");
    }
    let uid = Uid::current().as_raw();
    PathBuf::from(format!("/tmp/tunmux-{}", uid))
}

fn build_lease_token() -> String {
    let pid = std::process::id();
    let start_ticks = process_start_ticks(pid).unwrap_or(0);
    format!("{}:{}", pid, start_ticks)
}

fn configured_privileged_stdio_log_path() -> Option<PathBuf> {
    let value = std::env::var_os("TUNMUX_PRIVILEGED_STDIO_LOG")?;
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(path)
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = fs::read_to_string(path).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

fn map_sudo_spawn_error(err: std::io::Error, manual_command: String) -> AppError {
    if err.kind() == std::io::ErrorKind::NotFound {
        AppError::Other(format!("sudo not found in PATH; run: {}", manual_command))
    } else {
        AppError::Other(format!("failed to execute sudo: {}", err))
    }
}

fn shell_quote(value: &str) -> String {
    if !value.contains([' ', '\t', '\'', '"', '\\']) {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn request_kind(request: &PrivilegedRequest) -> &'static str {
    match request {
        PrivilegedRequest::NamespaceCreate { .. } => "NamespaceCreate",
        PrivilegedRequest::NamespaceDelete { .. } => "NamespaceDelete",
        PrivilegedRequest::NamespaceExists { .. } => "NamespaceExists",
        PrivilegedRequest::InterfaceCreateWireguard { .. } => "InterfaceCreateWireguard",
        PrivilegedRequest::InterfaceDelete { .. } => "InterfaceDelete",
        PrivilegedRequest::InterfaceMoveToNetns { .. } => "InterfaceMoveToNetns",
        PrivilegedRequest::NetnsExec { .. } => "NetnsExec",
        PrivilegedRequest::HostIpAddrAdd { .. } => "HostIpAddrAdd",
        PrivilegedRequest::HostIpLinkSetUp { .. } => "HostIpLinkSetUp",
        PrivilegedRequest::HostIpRouteAdd { .. } => "HostIpRouteAdd",
        PrivilegedRequest::HostIpRouteDel { .. } => "HostIpRouteDel",
        PrivilegedRequest::WireguardSet { .. } => "WireguardSet",
        PrivilegedRequest::WireguardSetPsk { .. } => "WireguardSetPsk",
        PrivilegedRequest::WgQuickRun { .. } => "WgQuickRun",
        PrivilegedRequest::GotaTunRun { .. } => "GotaTunRun",
        PrivilegedRequest::EnsureDir { .. } => "EnsureDir",
        PrivilegedRequest::WriteFile { .. } => "WriteFile",
        PrivilegedRequest::RemoveDirAll { .. } => "RemoveDirAll",
        PrivilegedRequest::KillPid { .. } => "KillPid",
        PrivilegedRequest::SpawnProxyDaemon { .. } => "SpawnProxyDaemon",
        PrivilegedRequest::LeaseAcquire { .. } => "LeaseAcquire",
        PrivilegedRequest::LeaseRelease { .. } => "LeaseRelease",
        PrivilegedRequest::ShutdownIfIdle => "ShutdownIfIdle",
        PrivilegedRequest::WgShow { .. } => "WgShow",
    }
}

fn run_sudo_validate_with_timeout(timeout: Duration) -> std::io::Result<bool> {
    debug!(cmd = "sudo -v", "exec");
    let mut child = Command::new("sudo").arg("-v").spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "sudo authentication prompt timed out after {}s",
                    timeout.as_secs()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

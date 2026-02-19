use std::io::IsTerminal;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nix::libc;
use nix::unistd::Uid;

use crate::config;
use crate::config::PrivilegedAutostopMode;
use crate::error::{AppError, Result};

use crate::privileged_api::{KillSignal, PrivilegedRequest, PrivilegedResponse, WgQuickAction};

pub struct PrivilegedClient {
    socket_path: PathBuf,
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
}

fn command_session_state() -> &'static Mutex<CommandSessionState> {
    static COMMAND_SESSION: OnceLock<Mutex<CommandSessionState>> = OnceLock::new();
    COMMAND_SESSION.get_or_init(|| Mutex::new(CommandSessionState::default()))
}

pub struct CommandScopeGuard {
    enabled: bool,
}

impl CommandScopeGuard {
    pub fn begin(mode: PrivilegedAutostopMode) -> Self {
        if !matches!(mode, PrivilegedAutostopMode::Command) {
            return Self { enabled: false };
        }
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
        if let Ok(mut state) = command_session_state().lock() {
            if state.enabled_count > 0 {
                state.enabled_count -= 1;
            }
            if state.enabled_count == 0 {
                token_to_release = state.lease_token.take();
            }
        }

        if let Some(token) = token_to_release {
            let client = PrivilegedClient::new();
            let _ = client
                .send_control_request_if_connected(&PrivilegedRequest::LeaseRelease { token });
            let _ = client.send_control_request_if_connected(&PrivilegedRequest::ShutdownIfIdle);
        }
    }
}

impl PrivilegedClient {
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
            autostart_enabled: cfg.general.privileged_autostart,
            autostart_timeout: Duration::from_millis(timeout_ms),
            authorized_group: cfg.general.privileged_authorized_group,
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
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::WgQuickRun {
            action,
            interface: interface.to_string(),
            provider: provider.to_string(),
            config_content: config_content.to_string(),
        })
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
        pid_file: &str,
        log_file: &str,
    ) -> Result<u32> {
        match self.send(PrivilegedRequest::SpawnProxyDaemon {
            netns: netns.to_string(),
            socks_port,
            http_port,
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
        self.ensure_command_lease_if_enabled()?;
        let mut stream = self.connect_or_autostart()?;
        self.send_on_stream(&mut stream, &request)
    }

    fn send_on_stream(
        &self,
        stream: &mut UnixStream,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
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
        match self.try_connect_socket() {
            Ok(stream) => return Ok(stream),
            Err(e) if !is_autostart_connect_error(&e) => {
                return Err(AppError::Other(format!(
                    "failed to connect to privileged socket: {}",
                    e
                )));
            }
            Err(_) => {}
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
        let _lock = self.acquire_startup_lock()?;

        if self.try_connect_socket().is_ok() {
            return Ok(());
        }

        self.spawn_privileged_daemon()?;
        self.wait_until_ready()
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
        let non_interactive = self.run_sudo_non_interactive()?;
        if non_interactive.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&non_interactive.stderr);
        if !stderr_requires_password(&stderr) {
            return Err(AppError::Other(format!(
                "failed to start privileged daemon via sudo: {}; run: {}",
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

        let validate = Command::new("sudo")
            .arg("-v")
            .status()
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))?;
        if !validate.success() {
            return Err(AppError::Other(format!(
                "sudo authentication failed; run: {}",
                self.manual_start_command()
            )));
        }

        let retry = self.run_sudo_non_interactive()?;
        if retry.status.success() {
            return Ok(());
        }
        let retry_stderr = String::from_utf8_lossy(&retry.stderr).trim().to_string();
        Err(AppError::Other(format!(
            "failed to start privileged daemon after sudo auth: {}; run: {}",
            retry_stderr,
            self.manual_start_command()
        )))
    }

    fn run_sudo_non_interactive(&self) -> Result<std::process::Output> {
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
        command
            .output()
            .map_err(|e| map_sudo_spawn_error(e, self.manual_start_command()))
    }

    fn wait_until_ready(&self) -> Result<()> {
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
        format!(
            "sudo {} privileged --serve --authorized-group {}{}",
            shell_quote(&exe.to_string_lossy()),
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
}

fn stderr_requires_password(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("password is required")
        || lower.contains("a password is required")
        || lower.contains("a terminal is required")
        || lower.contains("no tty")
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

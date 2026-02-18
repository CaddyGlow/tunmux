use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::config;
use crate::error::{AppError, Result};

use crate::privileged_api::{KillSignal, PrivilegedRequest, PrivilegedResponse, WgQuickAction};

pub struct PrivilegedClient {
    socket_path: PathBuf,
}

impl PrivilegedClient {
    pub fn new() -> Self {
        Self {
            socket_path: config::privileged_socket_path(),
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
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            AppError::Other(format!("failed to connect to privileged socket: {}", e))
        })?;

        let request_bytes = serde_json::to_vec(&request)
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
}

fn map_privileged_error(response: PrivilegedResponse) -> Result<PrivilegedResponse> {
    match response {
        PrivilegedResponse::Error { code, message } => Err(match code.as_str() {
            "Namespace" => AppError::Namespace(message),
            "WireGuard" => AppError::WireGuard(message),
            "Proxy" => AppError::Proxy(message),
            _ => AppError::Other(message),
        }),
        other => Ok(other),
    }
}

//! Userspace WireGuard proxy tunnel.
//!
//! Runs a WireGuard session backed by boringtun + smoltcp and exposes it as
//! SOCKS5 and HTTP proxies on loopback -- no TUN device, root, or netns needed.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

const UDP_BUF: usize = 65536;
const TCP_SOCKET_BUF: usize = 65536;
const LOCAL_PORT_START: u16 = 40000;
const LOCAL_PORT_END: u16 = 65000;

fn smoltcp_now() -> smoltcp::time::Instant {
    let millis = std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    smoltcp::time::Instant::from_millis(millis)
}

// ── Public config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProxyConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: SocketAddr,
    /// CIDR strings for addresses assigned to the virtual interface.
    pub virtual_ips: Vec<String>,
    pub keepalive: Option<u16>,
    pub socks_port: u16,
    pub http_port: u16,
}

// ── Internal message types ────────────────────────────────────────────────────

struct ConnRequest {
    target_ip: IpAddress,
    target_port: u16,
    to_client_tx: mpsc::Sender<Vec<u8>>,
    from_client_rx: mpsc::Receiver<Vec<u8>>,
    connected_tx: oneshot::Sender<Result<(), String>>,
}

// ── Virtual phy device for smoltcp ───────────────────────────────────────────

struct VirtualDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    caps: DeviceCapabilities,
}

impl VirtualDevice {
    fn new() -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420;
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            caps,
        }
    }
}

struct VirtRxToken(Vec<u8>);
impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VirtTxToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl smoltcp::phy::Device for VirtualDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound
            .pop_front()
            .map(|pkt| (VirtRxToken(pkt), VirtTxToken(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

// ── Per-connection state ──────────────────────────────────────────────────────

struct ConnEntry {
    handle: smoltcp::iface::SocketHandle,
    to_client_tx: mpsc::Sender<Vec<u8>>,
    from_client_rx: mpsc::Receiver<Vec<u8>>,
    /// Present until the virtual TCP handshake completes.
    connected_tx: Option<oneshot::Sender<Result<(), String>>>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run the local proxy. Returns when the tokio task is aborted or on fatal error.
pub async fn run_local_proxy(cfg: LocalProxyConfig) -> anyhow::Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind WireGuard UDP socket")?;
    udp.connect(cfg.endpoint)
        .await
        .context("connect UDP to WireGuard endpoint")?;
    let udp = Arc::new(udp);

    let mut tunn = Tunn::new(
        StaticSecret::from(cfg.private_key),
        PublicKey::from(cfg.peer_public_key),
        cfg.preshared_key,
        cfg.keepalive,
        0,
        None,
    );

    let virtual_ipv4: Ipv4Addr = cfg
        .virtual_ips
        .iter()
        .find_map(|s| s.split('/').next()?.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| anyhow!("no IPv4 address in virtual_ips"))?;
    let virtual_ip = IpAddress::Ipv4(virtual_ipv4);

    let mut device = VirtualDevice::new();
    let mut iface = Interface::new(
        Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut device,
        smoltcp_now(),
    );
    iface.update_ip_addrs(|addrs| {
        for s in &cfg.virtual_ips {
            if let Ok(cidr) = s.parse::<smoltcp::wire::IpCidr>() {
                let _ = addrs.push(cidr);
            }
        }
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1));

    let mut sockets = SocketSet::new(vec![]);

    let socks_listener = TcpListener::bind(("127.0.0.1", cfg.socks_port))
        .await
        .with_context(|| format!("bind SOCKS5 port {}", cfg.socks_port))?;
    let http_listener = TcpListener::bind(("127.0.0.1", cfg.http_port))
        .await
        .with_context(|| format!("bind HTTP port {}", cfg.http_port))?;

    info!(
        socks_port = cfg.socks_port,
        http_port = cfg.http_port,
        endpoint = ?cfg.endpoint,
        "local_proxy_started"
    );

    let (conn_req_tx, mut conn_req_rx) = mpsc::channel::<ConnRequest>(64);

    let tx = conn_req_tx.clone();
    tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "socks5_accepted");
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = socks5_serve(stream, tx).await {
                            debug!(error = ?e.to_string(), "socks5_error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = ?e.to_string(), "socks5_accept_error");
                    break;
                }
            }
        }
    });

    let tx = conn_req_tx.clone();
    tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "http_accepted");
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = http_connect_serve(stream, tx).await {
                            debug!(error = ?e.to_string(), "http_error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = ?e.to_string(), "http_accept_error");
                    break;
                }
            }
        }
    });

    let mut udp_buf = vec![0u8; UDP_BUF];
    let mut enc_buf = vec![0u8; UDP_BUF + 32];
    let mut conns: Vec<ConnEntry> = Vec::new();
    let mut next_port: u16 = LOCAL_PORT_START;

    loop {
        // 1. Drain incoming UDP -> boringtun -> smoltcp inbound
        loop {
            match udp.try_recv(&mut udp_buf) {
                Ok(n) => {
                    let mut tmp = vec![0u8; UDP_BUF];
                    match tunn.decapsulate(None, &udp_buf[..n], &mut tmp) {
                        TunnResult::WriteToTunnelV4(plain, _) => {
                            device.inbound.push_back(plain.to_vec());
                        }
                        TunnResult::WriteToTunnelV6(plain, _) => {
                            device.inbound.push_back(plain.to_vec());
                        }
                        TunnResult::WriteToNetwork(out) => {
                            let _ = udp.try_send(out);
                        }
                        _ => {}
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(error = ?e.to_string(), "udp_recv_error");
                    break;
                }
            }
        }

        // 2. WireGuard keepalive / handshake timers
        if let TunnResult::WriteToNetwork(out) = tunn.update_timers(&mut enc_buf) {
            let _ = udp.try_send(out);
        }

        // 3. New connection requests
        while let Ok(req) = conn_req_rx.try_recv() {
            let local_port = next_port;
            next_port = if next_port >= LOCAL_PORT_END {
                LOCAL_PORT_START
            } else {
                next_port + 1
            };

            let mut sock = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]),
                TcpSocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]),
            );
            let remote = IpEndpoint::new(req.target_ip, req.target_port);
            let local = IpListenEndpoint {
                addr: Some(virtual_ip),
                port: local_port,
            };
            match sock.connect(iface.context(), remote, local) {
                Ok(()) => {
                    let h = sockets.add(sock);
                    conns.push(ConnEntry {
                        handle: h,
                        to_client_tx: req.to_client_tx,
                        from_client_rx: req.from_client_rx,
                        connected_tx: Some(req.connected_tx),
                    });
                }
                Err(e) => {
                    let _ = req.connected_tx.send(Err(format!("connect: {}", e)));
                }
            }
        }

        // 4. Poll smoltcp
        let now = smoltcp_now();
        let _ = iface.poll(now, &mut device, &mut sockets);

        // 5. smoltcp outbound -> boringtun -> UDP
        while let Some(plain) = device.outbound.pop_front() {
            if let TunnResult::WriteToNetwork(out) = tunn.encapsulate(&plain, &mut enc_buf) {
                let _ = udp.try_send(out);
            }
        }

        // 6. Service connections
        let mut remove: Vec<usize> = Vec::new();
        for (i, entry) in conns.iter_mut().enumerate() {
            let sock = sockets.get_mut::<TcpSocket>(entry.handle);

            if let Some(tx) = entry.connected_tx.take() {
                if sock.may_send() {
                    let _ = tx.send(Ok(()));
                } else if sock.state() == smoltcp::socket::tcp::State::Closed {
                    let _ = tx.send(Err("connection refused".into()));
                    remove.push(i);
                    continue;
                } else {
                    entry.connected_tx = Some(tx);
                }
            }

            if sock.can_recv() {
                let mut buf = vec![0u8; 16384];
                if let Ok(n) = sock.recv_slice(&mut buf) {
                    if n > 0 {
                        buf.truncate(n);
                        if entry.to_client_tx.try_send(buf).is_err() {
                            sock.close();
                            remove.push(i);
                            continue;
                        }
                    }
                }
            }

            loop {
                match entry.from_client_rx.try_recv() {
                    Ok(data) => {
                        if sock.can_send() {
                            let _ = sock.send_slice(&data);
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        sock.close();
                        remove.push(i);
                        break;
                    }
                }
            }

            if !sock.is_open() {
                remove.push(i);
            }
        }

        remove.sort_unstable();
        remove.dedup();
        for &i in remove.iter().rev() {
            if i < conns.len() {
                let e = conns.remove(i);
                sockets.remove(e.handle);
            }
        }

        // 7. Yield to tokio so the task can be aborted
        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(5))
            .min(Duration::from_millis(5));
        tokio::time::sleep(delay).await;
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

async fn socks5_serve(
    mut stream: TcpStream,
    conn_req_tx: mpsc::Sender<ConnRequest>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    anyhow::ensure!(buf[0] == 0x05, "not SOCKS5");
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        anyhow::bail!("only CONNECT supported");
    }

    let (target_ip, target_port) = read_socks5_addr(&mut stream, hdr[3]).await?;

    let (to_client_tx, mut to_client_rx) = mpsc::channel::<Vec<u8>>(64);
    let (from_client_tx, from_client_rx) = mpsc::channel::<Vec<u8>>(64);
    let (connected_tx, connected_rx) = oneshot::channel();

    conn_req_tx
        .send(ConnRequest { target_ip, target_port, to_client_tx, from_client_rx, connected_tx })
        .await
        .map_err(|_| anyhow!("proxy tunnel exited"))?;

    match connected_rx.await {
        Ok(Ok(())) => {
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        }
        Ok(Err(e)) => {
            stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("virtual connect: {}", e);
        }
        Err(_) => anyhow::bail!("proxy tunnel dropped response"),
    }

    bridge(&mut stream, from_client_tx, &mut to_client_rx).await;
    Ok(())
}

async fn read_socks5_addr(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<(IpAddress, u16)> {
    match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            Ok((IpAddress::Ipv4(Ipv4Addr::from(a)), u16::from_be_bytes(p)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; len[0] as usize];
            stream.read_exact(&mut dom).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let host = std::str::from_utf8(&dom)?;
            let sa = resolve_ipv4_preferred(host, port).await?;
            Ok((ip_to_smoltcp(sa.ip()), sa.port()))
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            Ok((IpAddress::Ipv6(Ipv6Addr::from(a)), u16::from_be_bytes(p)))
        }
        other => anyhow::bail!("unsupported SOCKS5 atyp {}", other),
    }
}

// ── HTTP proxy (CONNECT + plain HTTP) ────────────────────────────────────────

async fn http_connect_serve(
    mut stream: TcpStream,
    conn_req_tx: mpsc::Sender<ConnRequest>,
) -> anyhow::Result<()> {
    let request_line = read_crlf_line(&mut stream).await?;
    let mut headers: Vec<String> = Vec::new();
    loop {
        let line = read_crlf_line(&mut stream).await?;
        if line.is_empty() {
            break;
        }
        headers.push(line);
    }

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    anyhow::ensure!(!parts.is_empty(), "empty HTTP request line");
    let method = parts[0];

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS tunnel: CONNECT host:port HTTP/1.x
        let target = parts.get(1).copied().unwrap_or("");
        let (host, port_str) = target
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("no port in CONNECT target: {}", target))?;
        let port: u16 = port_str.parse()?;
        let sa = resolve_ipv4_preferred(host, port).await?;

        let (to_client_tx, mut to_client_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_client_tx, from_client_rx) = mpsc::channel::<Vec<u8>>(64);
        let (connected_tx, connected_rx) = oneshot::channel();

        conn_req_tx
            .send(ConnRequest {
                target_ip: ip_to_smoltcp(sa.ip()),
                target_port: sa.port(),
                to_client_tx,
                from_client_rx,
                connected_tx,
            })
            .await
            .map_err(|_| anyhow!("proxy tunnel exited"))?;

        match connected_rx.await {
            Ok(Ok(())) => {
                stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            }
            Ok(Err(e)) => {
                stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                anyhow::bail!("virtual connect: {}", e);
            }
            Err(_) => anyhow::bail!("proxy tunnel dropped response"),
        }

        bridge(&mut stream, from_client_tx, &mut to_client_rx).await;
    } else {
        // Plain HTTP: GET http://host/path HTTP/1.x
        let url = parts.get(1).copied().unwrap_or("/");
        let version = parts.get(2).copied().unwrap_or("HTTP/1.1");

        let (host, port, path) = if url.starts_with("http://") {
            parse_http_url(url)?
        } else {
            // Relative URL — extract host from Host header
            let host_val = headers
                .iter()
                .find(|h| h.to_ascii_lowercase().starts_with("host:"))
                .map(|h| h[5..].trim().to_string())
                .ok_or_else(|| anyhow!("plain HTTP request missing Host header"))?;
            let (host, port) = if let Some((h, p)) = host_val.rsplit_once(':') {
                (h.to_string(), p.parse::<u16>().unwrap_or(80))
            } else {
                (host_val, 80u16)
            };
            (host, port, url.to_string())
        };

        let sa = resolve_ipv4_preferred(&host, port).await?;

        let (to_client_tx, mut to_client_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_client_tx, from_client_rx) = mpsc::channel::<Vec<u8>>(64);
        let (connected_tx, connected_rx) = oneshot::channel();

        conn_req_tx
            .send(ConnRequest {
                target_ip: ip_to_smoltcp(sa.ip()),
                target_port: sa.port(),
                to_client_tx,
                from_client_rx,
                connected_tx,
            })
            .await
            .map_err(|_| anyhow!("proxy tunnel exited"))?;

        match connected_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => anyhow::bail!("virtual connect: {}", e),
            Err(_) => anyhow::bail!("proxy tunnel dropped response"),
        }

        // Reconstruct request with relative path; strip proxy-only headers
        let mut req = format!("{} {} {}\r\n", method, path, version);
        for h in &headers {
            let lower = h.to_ascii_lowercase();
            if lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authorization:") {
                continue;
            }
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        from_client_tx
            .send(req.into_bytes())
            .await
            .map_err(|_| anyhow!("virtual channel closed"))?;

        bridge(&mut stream, from_client_tx, &mut to_client_rx).await;
    }

    Ok(())
}

fn parse_http_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let without_scheme = url.strip_prefix("http://").unwrap_or(url);
    let (authority, rest) = without_scheme
        .split_once('/')
        .map(|(a, r)| (a, format!("/{}", r)))
        .unwrap_or((without_scheme, "/".to_string()));
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(80))
    } else {
        (authority.to_string(), 80u16)
    };
    Ok((host, port, rest))
}

async fn read_crlf_line(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut line = String::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        match byte[0] {
            b'\n' => return Ok(line.trim_end_matches('\r').to_string()),
            b => line.push(b as char),
        }
        anyhow::ensure!(line.len() <= 8192, "line too long");
    }
}

// ── Bidirectional data bridge ─────────────────────────────────────────────────

async fn bridge(
    stream: &mut TcpStream,
    from_client_tx: mpsc::Sender<Vec<u8>>,
    to_client_rx: &mut mpsc::Receiver<Vec<u8>>,
) {
    let (mut reader, mut writer) = stream.split();
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            result = reader.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if from_client_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
            data = to_client_rx.recv() => {
                match data {
                    None => break,
                    Some(d) => {
                        if writer.write_all(&d).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Resolve `host` to a `SocketAddr`, preferring IPv4.
///
/// The smoltcp virtual interface only has a default IPv4 route, so IPv6
/// targets would be unroutable. Prefer the first IPv4 result; fall back to
/// the first address of any family only when no IPv4 address is returned.
async fn resolve_ipv4_preferred(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("DNS lookup failed: {}", host))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.into_iter().next())
        .ok_or_else(|| anyhow!("DNS returned no addresses for {}", host))
}

fn ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

//! Userspace WireGuard proxy tunnel.
//!
//! Runs a WireGuard session backed by boringtun + smoltcp and exposes it as
//! SOCKS5 and HTTP proxies on loopback -- no TUN device, root, or netns needed.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, warn};

const UDP_BUF: usize = 65536;
const TCP_SOCKET_BUF: usize = 262144;
const STREAM_BUF: usize = 65536;
const LOCAL_PORT_START: u16 = 40000;
const LOCAL_PORT_END: u16 = 65000;
const WG_TIMER_TICK_MAX: Duration = Duration::from_millis(100);
const ACTIVE_CONN_POLL_MAX: Duration = Duration::from_millis(1);
const CLIENT_CHANNEL_CAP: usize = 1024;
const REMOTE_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const CLIENT_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const UDP_RECV_BURST_MAX: usize = 64;
const UDP_SEND_BURST_MAX: usize = 64;
const ACTIVE_CONN_BATCH_MAX: usize = 256;
const ACTIVE_CONN_FULL_SCAN_INTERVAL: Duration = Duration::from_millis(25);
const DNS_CACHE_TTL: Duration = Duration::from_secs(15);

type DnsCache = HashMap<String, (Instant, Vec<SocketAddr>)>;
static DNS_CACHE: LazyLock<StdRwLock<DnsCache>> = LazyLock::new(|| StdRwLock::new(HashMap::new()));

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
    to_client_tx: Arc<ByteQueue>,
    from_client_rx: Arc<ByteQueue>,
    connected_tx: oneshot::Sender<Result<(), String>>,
}

enum QueuePushError {
    Full(Bytes),
    Closed,
}

struct ByteQueue {
    queue: ArrayQueue<Bytes>,
    has_data_notify: Notify,
    has_space_notify: Notify,
    loop_notify: Arc<Notify>,
    closed: AtomicBool,
}

impl ByteQueue {
    fn new(capacity: usize, loop_notify: Arc<Notify>) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            has_data_notify: Notify::new(),
            has_space_notify: Notify::new(),
            loop_notify,
            closed: AtomicBool::new(false),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.has_data_notify.notify_waiters();
        self.has_space_notify.notify_waiters();
        self.loop_notify.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn try_push(&self, chunk: Bytes) -> Result<(), QueuePushError> {
        if self.is_closed() {
            return Err(QueuePushError::Closed);
        }
        match self.queue.push(chunk) {
            Ok(()) => {
                self.has_data_notify.notify_one();
                self.loop_notify.notify_one();
                Ok(())
            }
            Err(chunk) => Err(QueuePushError::Full(chunk)),
        }
    }

    async fn push(&self, mut chunk: Bytes) -> Result<(), ()> {
        loop {
            match self.try_push(chunk) {
                Ok(()) => return Ok(()),
                Err(QueuePushError::Closed) => return Err(()),
                Err(QueuePushError::Full(returned)) => {
                    chunk = returned;
                    if self.is_closed() {
                        return Err(());
                    }
                    self.has_space_notify.notified().await;
                }
            }
        }
    }

    fn try_pop(&self) -> Option<Bytes> {
        let out = self.queue.pop();
        if out.is_some() {
            self.has_space_notify.notify_one();
        }
        out
    }

    async fn pop(&self) -> Option<Bytes> {
        loop {
            if let Some(out) = self.try_pop() {
                return Some(out);
            }
            if self.is_closed() {
                return None;
            }
            self.has_data_notify.notified().await;
        }
    }
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
    to_client_tx: Arc<ByteQueue>,
    from_client_rx: Arc<ByteQueue>,
    /// Present until the virtual TCP handshake completes.
    connected_tx: Option<oneshot::Sender<Result<(), String>>>,
    pending_to_remote: VecDeque<Bytes>,
    pending_to_client: VecDeque<Bytes>,
    pending_remote_bytes: usize,
    pending_client_bytes: usize,
    active: bool,
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

    let (conn_req_tx, mut conn_req_rx) = mpsc::channel::<ConnRequest>(CLIENT_CHANNEL_CAP);
    let loop_notify = Arc::new(Notify::new());

    let tx = conn_req_tx.clone();
    let notify = loop_notify.clone();
    tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "socks5_accepted");
                    let tx = tx.clone();
                    let notify = notify.clone();
                    tokio::spawn(async move {
                        if let Err(e) = socks5_serve(stream, tx, notify).await {
                            debug!(error = ?e.to_string(), "socks5_error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = ?e.to_string(), "socks5_accept_error");
                    // Keep the listener alive across transient accept errors (e.g. fd pressure).
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        }
    });

    let tx = conn_req_tx.clone();
    let notify = loop_notify.clone();
    tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "http_accepted");
                    let tx = tx.clone();
                    let notify = notify.clone();
                    tokio::spawn(async move {
                        if let Err(e) = http_connect_serve(stream, tx, notify).await {
                            debug!(error = ?e.to_string(), "http_error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = ?e.to_string(), "http_accept_error");
                    // Keep the listener alive across transient accept errors (e.g. fd pressure).
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        }
    });

    let mut udp_buf = vec![0u8; UDP_BUF];
    let mut decap_buf = vec![0u8; UDP_BUF];
    let mut enc_buf = vec![0u8; UDP_BUF + 32];
    let mut conns: Vec<ConnEntry> = Vec::new();
    let mut next_port: u16 = LOCAL_PORT_START;
    let mut wg_pending_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut active_conns: VecDeque<usize> = VecDeque::new();
    let mut last_full_scan = Instant::now();
    let mut wg_timer_deadline = Instant::now();

    loop {
        let now_std = Instant::now();
        let now = smoltcp_now();

        if now_std >= wg_timer_deadline {
            queue_tunn_network_write(tunn.update_timers(&mut enc_buf), &mut wg_pending_tx);
            wg_timer_deadline = now_std + WG_TIMER_TICK_MAX;
        }

        while let Ok(req) = conn_req_rx.try_recv() {
            add_virtual_connection(
                req,
                &mut next_port,
                virtual_ip,
                &mut iface,
                &mut sockets,
                &mut conns,
                &mut active_conns,
            );
        }

        for _ in 0..UDP_RECV_BURST_MAX {
            match udp.try_recv(&mut udp_buf) {
                Ok(n) => match tunn.decapsulate(None, &udp_buf[..n], &mut decap_buf) {
                    TunnResult::WriteToTunnelV4(plain, _)
                    | TunnResult::WriteToTunnelV6(plain, _) => {
                        device.inbound.push_back(Vec::from(plain));
                    }
                    TunnResult::WriteToNetwork(out) => {
                        wg_pending_tx.push_back(out.to_vec());
                    }
                    _ => {}
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(error = ?e.to_string(), "udp_recv_error");
                    break;
                }
            }
        }
        flush_udp_writes(udp.as_ref(), &mut wg_pending_tx);

        let _ = iface.poll(now, &mut device, &mut sockets);

        while let Some(plain) = device.outbound.pop_front() {
            queue_tunn_network_write(tunn.encapsulate(&plain, &mut enc_buf), &mut wg_pending_tx);
        }
        flush_udp_writes(udp.as_ref(), &mut wg_pending_tx);

        if active_conns.is_empty()
            || now_std.saturating_duration_since(last_full_scan) >= ACTIVE_CONN_FULL_SCAN_INTERVAL
        {
            for i in 0..conns.len() {
                mark_conn_active(&mut conns, &mut active_conns, i);
            }
            last_full_scan = now_std;
        }

        let mut remove: Vec<usize> = Vec::new();
        let process_budget = active_conns.len().min(ACTIVE_CONN_BATCH_MAX);
        for _ in 0..process_budget {
            let Some(i) = active_conns.pop_front() else {
                break;
            };
            if i >= conns.len() {
                continue;
            }
            conns[i].active = false;

            let mut requeue = false;
            let mut remove_current = false;
            let entry = &mut conns[i];
            let sock = sockets.get_mut::<TcpSocket>(entry.handle);

            if let Some(tx) = entry.connected_tx.take() {
                if sock.may_send() {
                    let _ = tx.send(Ok(()));
                } else if sock.state() == smoltcp::socket::tcp::State::Closed {
                    let _ = tx.send(Err("connection refused".into()));
                    remove_current = true;
                } else {
                    entry.connected_tx = Some(tx);
                }
            }

            if !remove_current && sock.can_recv() && entry.pending_client_bytes < CLIENT_PENDING_MAX_BYTES
            {
                let mut recv_buf = [0u8; STREAM_BUF];
                if let Ok(n) = sock.recv_slice(&mut recv_buf) {
                    if n > 0 {
                        let chunk = Bytes::copy_from_slice(&recv_buf[..n]);
                        entry.pending_client_bytes += chunk.len();
                        entry.pending_to_client.push_back(chunk);
                    }
                }
            }

            while !remove_current && entry.pending_remote_bytes < REMOTE_PENDING_MAX_BYTES {
                let Some(data) = entry.from_client_rx.try_pop() else {
                    break;
                };
                entry.pending_remote_bytes += data.len();
                entry.pending_to_remote.push_back(data);
            }
            if !remove_current
                && entry.from_client_rx.is_closed()
                && entry.pending_to_remote.is_empty()
            {
                sock.close();
                remove_current = true;
            }

            while !remove_current && sock.can_send() {
                let Some(front) = entry.pending_to_remote.front_mut() else {
                    break;
                };
                match sock.send_slice(front.as_ref()) {
                    Ok(sent) => {
                        if sent == front.len() {
                            let sent_len = front.len();
                            let _ = entry.pending_to_remote.pop_front();
                            entry.pending_remote_bytes =
                                entry.pending_remote_bytes.saturating_sub(sent_len);
                        } else {
                            let remaining = front.slice(sent..);
                            *front = remaining;
                            entry.pending_remote_bytes =
                                entry.pending_remote_bytes.saturating_sub(sent);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            while !remove_current {
                let Some(front) = entry.pending_to_client.pop_front() else {
                    break;
                };
                let front_len = front.len();
                match entry.to_client_tx.try_push(front) {
                    Ok(()) => {
                        entry.pending_client_bytes =
                            entry.pending_client_bytes.saturating_sub(front_len);
                    }
                    Err(QueuePushError::Full(front)) => {
                        entry.pending_to_client.push_front(front);
                        break;
                    }
                    Err(QueuePushError::Closed) => {
                        sock.close();
                        remove_current = true;
                        break;
                    }
                }
            }

            if !remove_current && entry.to_client_tx.is_closed() {
                sock.close();
                remove_current = true;
            }

            if remove_current || !sock.is_open() {
                remove.push(i);
                continue;
            }

            if entry.connected_tx.is_some()
                || !entry.pending_to_remote.is_empty()
                || !entry.pending_to_client.is_empty()
                || !entry.from_client_rx.is_empty()
                || sock.can_recv()
                || sock.can_send()
            {
                requeue = true;
            }

            if requeue {
                mark_conn_active(&mut conns, &mut active_conns, i);
            }
        }

        remove.sort_unstable();
        remove.dedup();
        for &i in remove.iter().rev() {
            if i < conns.len() {
                let e = conns.remove(i);
                e.to_client_tx.close();
                e.from_client_rx.close();
                sockets.remove(e.handle);
            }
        }
        if !remove.is_empty() {
            active_conns.clear();
            for entry in &mut conns {
                entry.active = false;
            }
        }

        let has_pending_work = !device.inbound.is_empty()
            || !device.outbound.is_empty()
            || !wg_pending_tx.is_empty()
            || !active_conns.is_empty()
            || conns.iter().any(|entry| {
                !entry.pending_to_remote.is_empty()
                    || !entry.pending_to_client.is_empty()
                    || !entry.from_client_rx.is_empty()
            });
        if has_pending_work {
            tokio::task::yield_now().await;
            continue;
        }

        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(WG_TIMER_TICK_MAX);

        let activity_cap = if conns.is_empty() {
            WG_TIMER_TICK_MAX
        } else {
            ACTIVE_CONN_POLL_MAX
        };
        let delay = delay.min(activity_cap);

        let timer_wait = wg_timer_deadline.saturating_duration_since(Instant::now());
        let wait_for = delay.min(timer_wait);

        tokio::select! {
            _ = udp.readable() => {}
            maybe_req = conn_req_rx.recv() => {
                if let Some(req) = maybe_req {
                    add_virtual_connection(
                        req,
                        &mut next_port,
                        virtual_ip,
                        &mut iface,
                        &mut sockets,
                        &mut conns,
                        &mut active_conns,
                    );
                }
            }
            _ = loop_notify.notified() => {}
            _ = tokio::time::sleep(wait_for) => {}
        }
    }
}

fn queue_tunn_network_write(result: TunnResult<'_>, wg_pending_tx: &mut VecDeque<Vec<u8>>) {
    if let TunnResult::WriteToNetwork(out) = result {
        wg_pending_tx.push_back(out.to_vec());
    }
}

fn flush_udp_writes(udp: &UdpSocket, wg_pending_tx: &mut VecDeque<Vec<u8>>) {
    for _ in 0..UDP_SEND_BURST_MAX {
        let Some(front) = wg_pending_tx.front() else {
            break;
        };
        match udp.try_send(front) {
            Ok(_) => {
                let _ = wg_pending_tx.pop_front();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => {
                warn!(error = ?e.to_string(), "udp_send_error");
                let _ = wg_pending_tx.pop_front();
            }
        }
    }
}

fn mark_conn_active(conns: &mut [ConnEntry], active_conns: &mut VecDeque<usize>, idx: usize) {
    if idx >= conns.len() || conns[idx].active {
        return;
    }
    conns[idx].active = true;
    active_conns.push_back(idx);
}

fn add_virtual_connection(
    req: ConnRequest,
    next_port: &mut u16,
    virtual_ip: IpAddress,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    conns: &mut Vec<ConnEntry>,
    active_conns: &mut VecDeque<usize>,
) {
    let local_port = *next_port;
    *next_port = if *next_port >= LOCAL_PORT_END {
        LOCAL_PORT_START
    } else {
        *next_port + 1
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
                pending_to_remote: VecDeque::new(),
                pending_to_client: VecDeque::new(),
                pending_remote_bytes: 0,
                pending_client_bytes: 0,
                active: false,
            });
            let new_idx = conns.len() - 1;
            mark_conn_active(conns, active_conns, new_idx);
        }
        Err(e) => {
            let _ = req.connected_tx.send(Err(format!("connect: {}", e)));
        }
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

async fn socks5_serve(
    mut stream: TcpStream,
    conn_req_tx: mpsc::Sender<ConnRequest>,
    loop_notify: Arc<Notify>,
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
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("only CONNECT supported");
    }

    let (target_ip, target_port) = read_socks5_addr(&mut stream, hdr[3]).await?;

    let to_client_tx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
    let from_client_rx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify));
    let (connected_tx, connected_rx) = oneshot::channel();

    conn_req_tx
        .send(ConnRequest {
            target_ip,
            target_port,
            to_client_tx: to_client_tx.clone(),
            from_client_rx: from_client_rx.clone(),
            connected_tx,
        })
        .await
        .map_err(|_| anyhow!("proxy tunnel exited"))?;

    match connected_rx.await {
        Ok(Ok(())) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
        Ok(Err(e)) => {
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            anyhow::bail!("virtual connect: {}", e);
        }
        Err(_) => anyhow::bail!("proxy tunnel dropped response"),
    }

    bridge(&mut stream, from_client_rx, to_client_tx).await;
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
    loop_notify: Arc<Notify>,
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

        let to_client_tx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
        let from_client_rx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
        let (connected_tx, connected_rx) = oneshot::channel();

        conn_req_tx
            .send(ConnRequest {
                target_ip: ip_to_smoltcp(sa.ip()),
                target_port: sa.port(),
                to_client_tx: to_client_tx.clone(),
                from_client_rx: from_client_rx.clone(),
                connected_tx,
            })
            .await
            .map_err(|_| anyhow!("proxy tunnel exited"))?;

        match connected_rx.await {
            Ok(Ok(())) => {
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
            }
            Ok(Err(e)) => {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                anyhow::bail!("virtual connect: {}", e);
            }
            Err(_) => anyhow::bail!("proxy tunnel dropped response"),
        }

        bridge(&mut stream, from_client_rx, to_client_tx).await;
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

        let to_client_tx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
        let from_client_rx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
        let (connected_tx, connected_rx) = oneshot::channel();

        conn_req_tx
            .send(ConnRequest {
                target_ip: ip_to_smoltcp(sa.ip()),
                target_port: sa.port(),
                to_client_tx: to_client_tx.clone(),
                from_client_rx: from_client_rx.clone(),
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

        from_client_rx
            .push(Bytes::from(req.into_bytes()))
            .await
            .map_err(|_| anyhow!("virtual channel closed"))?;

        bridge(&mut stream, from_client_rx, to_client_tx).await;
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
    from_client_tx: Arc<ByteQueue>,
    to_client_rx: Arc<ByteQueue>,
) {
    let (mut reader, mut writer) = stream.split();
    let mut read_buf = BytesMut::with_capacity(STREAM_BUF);
    loop {
        tokio::select! {
            result = reader.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let chunk = read_buf.split().freeze();
                        if from_client_tx.push(chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
            data = to_client_rx.pop() => {
                match data {
                    None => break,
                    Some(d) => {
                        if writer.write_all(d.as_ref()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    from_client_tx.close();
    to_client_rx.close();
}

/// Resolve `host` to a `SocketAddr`, preferring IPv4.
///
/// The smoltcp virtual interface only has a default IPv4 route, so IPv6
/// targets would be unroutable. Prefer the first IPv4 result; fall back to
/// the first address of any family only when no IPv4 address is returned.
async fn resolve_ipv4_preferred(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let cache_key = format!("{}:{}", host, port);
    if let Some(hit) = dns_cache_get(&cache_key) {
        return select_ipv4_preferred(hit.into_iter())
            .ok_or_else(|| anyhow!("DNS returned no addresses for {}", host));
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("DNS lookup failed: {}", host))?
        .collect();
    dns_cache_put(cache_key, addrs.clone());
    select_ipv4_preferred(addrs.into_iter())
        .ok_or_else(|| anyhow!("DNS returned no addresses for {}", host))
}

fn select_ipv4_preferred(mut addrs: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut first: Option<SocketAddr> = None;
    for addr in addrs.by_ref() {
        if first.is_none() {
            first = Some(addr);
        }
        if addr.is_ipv4() {
            return Some(addr);
        }
    }
    first
}

fn dns_cache_get(key: &str) -> Option<Vec<SocketAddr>> {
    let map = DNS_CACHE.read().ok()?;
    let (inserted_at, addrs) = map.get(key)?;
    if inserted_at.elapsed() > DNS_CACHE_TTL {
        return None;
    }
    Some(addrs.clone())
}

fn dns_cache_put(key: String, addrs: Vec<SocketAddr>) {
    if let Ok(mut map) = DNS_CACHE.write() {
        map.retain(|_, (inserted_at, _)| inserted_at.elapsed() <= DNS_CACHE_TTL);
        map.insert(key, (Instant::now(), addrs));
    }
}

fn ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

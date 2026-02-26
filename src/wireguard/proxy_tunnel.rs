//! Userspace WireGuard proxy tunnel.
//!
//! Runs a WireGuard session backed by boringtun + smoltcp and exposes it as
//! SOCKS5 and HTTP proxies on loopback -- no TUN device, root, or netns needed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, LazyLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::{Bytes, BytesMut};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as SmolUdpSocket,
};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, warn};

const UDP_BUF: usize = 65536;
const TCP_SOCKET_BUF: usize = 2097152;
const STREAM_BUF: usize = 65536;
const LOCAL_PORT_START: u16 = 40000;
const LOCAL_PORT_END: u16 = 65000;
const WG_TIMER_TICK_MAX: Duration = Duration::from_millis(100);
const CLIENT_CHANNEL_CAP: usize = 1024;
const REMOTE_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const CLIENT_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const UDP_RECV_BURST_MAX: usize = 192;
const UDP_SEND_BURST_MAX: usize = 192;
const ACTIVE_CONN_BATCH_MAX: usize = 384;
const ACTIVE_CONN_TOPUP_TARGET: usize = 768;
const ACTIVE_CONN_SWEEP_BATCH_MAX: usize = 384;
const DNS_CACHE_TTL: Duration = Duration::from_secs(15);
const DNS_TUNNEL_QUERY_TTL: Duration = Duration::from_secs(5);
const DNS_UDP_PACKET_CAP: usize = 2048;
const PERF_LOG_INTERVAL: Duration = Duration::from_secs(5);

type DnsCache = HashMap<String, (Instant, Vec<SocketAddr>)>;
static DNS_CACHE: LazyLock<StdRwLock<DnsCache>> = LazyLock::new(|| StdRwLock::new(HashMap::new()));
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

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
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Clone)]
struct TunnelDnsResolver {
    dns_servers: Arc<Vec<IpAddr>>,
    virtual_ipv4: Ipv4Addr,
    virtual_ipv6: Option<Ipv6Addr>,
    dns_req_tx: mpsc::Sender<DnsUdpRequest>,
}

// ── Internal message types ────────────────────────────────────────────────────

struct ConnRequest {
    target_ip: IpAddress,
    target_port: u16,
    to_client_tx: Arc<ByteQueue>,
    from_client_rx: Arc<ByteQueue>,
    connected_tx: oneshot::Sender<Result<(), String>>,
}

struct DnsUdpRequest {
    dns_server: IpAddress,
    source_ip: IpAddress,
    payload: Vec<u8>,
    response_tx: oneshot::Sender<Result<Vec<u8>, String>>,
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

    fn is_full(&self) -> bool {
        self.queue.is_full()
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
            self.loop_notify.notify_one();
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

struct DnsUdpEntry {
    handle: smoltcp::iface::SocketHandle,
    response_tx: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct VirtualTunnelIps {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

fn conn_has_runnable_work(entry: &ConnEntry, sock: &TcpSocket<'_>) -> bool {
    entry.connected_tx.is_some()
        || (!entry.from_client_rx.is_empty()
            && entry.pending_remote_bytes < REMOTE_PENDING_MAX_BYTES)
        || (!entry.pending_to_remote.is_empty() && sock.can_send())
        || (!entry.pending_to_client.is_empty() && !entry.to_client_tx.is_full())
        || (sock.can_recv() && entry.pending_client_bytes < CLIENT_PENDING_MAX_BYTES)
}

struct DataplanePerf {
    enabled: bool,
    last_log: Instant,
    loops: u64,
    iface_polls: u64,
    iface_poll_ns: u64,
    udp_rx_packets: u64,
    udp_rx_bytes: u64,
    udp_tx_packets: u64,
    udp_tx_bytes: u64,
    tunn_net_writes: u64,
    tunn_net_write_copies: u64,
    conn_visits: u64,
    conn_requeues: u64,
    active_q_peak: usize,
    udp_pending_peak: usize,
    idle_wakes: u64,
    idle_wait_ns: u64,
    idle_wake_udp: u64,
    idle_wake_conn_req: u64,
    idle_wake_loop_notify: u64,
    idle_wake_timeout: u64,
}

#[derive(Clone, Copy)]
enum IdleWakeReason {
    Udp,
    ConnReq,
    LoopNotify,
    Timeout,
}

impl DataplanePerf {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_log: Instant::now(),
            loops: 0,
            iface_polls: 0,
            iface_poll_ns: 0,
            udp_rx_packets: 0,
            udp_rx_bytes: 0,
            udp_tx_packets: 0,
            udp_tx_bytes: 0,
            tunn_net_writes: 0,
            tunn_net_write_copies: 0,
            conn_visits: 0,
            conn_requeues: 0,
            active_q_peak: 0,
            udp_pending_peak: 0,
            idle_wakes: 0,
            idle_wait_ns: 0,
            idle_wake_udp: 0,
            idle_wake_conn_req: 0,
            idle_wake_loop_notify: 0,
            idle_wake_timeout: 0,
        }
    }

    fn observe_loop(&mut self, active_q_len: usize, udp_pending_len: usize) {
        if !self.enabled {
            return;
        }
        self.loops = self.loops.saturating_add(1);
        self.active_q_peak = self.active_q_peak.max(active_q_len);
        self.udp_pending_peak = self.udp_pending_peak.max(udp_pending_len);
    }

    fn maybe_log_and_reset(&mut self, conns: usize) {
        if !self.enabled || self.last_log.elapsed() < PERF_LOG_INTERVAL {
            return;
        }
        let elapsed = self.last_log.elapsed();
        let elapsed_s = elapsed.as_secs_f64();
        let idle_wake_hz = if elapsed_s > 0.0 {
            self.idle_wakes as f64 / elapsed_s
        } else {
            0.0
        };
        info!(
            interval_ms = elapsed.as_millis() as u64,
            conns = conns,
            loops = self.loops,
            iface_polls = self.iface_polls,
            iface_poll_ms = self.iface_poll_ns as f64 / 1_000_000.0,
            udp_rx_packets = self.udp_rx_packets,
            udp_rx_mib = self.udp_rx_bytes as f64 / (1024.0 * 1024.0),
            udp_tx_packets = self.udp_tx_packets,
            udp_tx_mib = self.udp_tx_bytes as f64 / (1024.0 * 1024.0),
            tunn_net_writes = self.tunn_net_writes,
            tunn_net_write_copies = self.tunn_net_write_copies,
            conn_visits = self.conn_visits,
            conn_requeues = self.conn_requeues,
            active_q_peak = self.active_q_peak,
            udp_pending_peak = self.udp_pending_peak,
            idle_wakes = self.idle_wakes,
            idle_wake_hz = idle_wake_hz,
            idle_wait_ms = self.idle_wait_ns as f64 / 1_000_000.0,
            idle_wake_udp = self.idle_wake_udp,
            idle_wake_conn_req = self.idle_wake_conn_req,
            idle_wake_loop_notify = self.idle_wake_loop_notify,
            idle_wake_timeout = self.idle_wake_timeout,
            "local_proxy_perf"
        );

        self.last_log = Instant::now();
        self.loops = 0;
        self.iface_polls = 0;
        self.iface_poll_ns = 0;
        self.udp_rx_packets = 0;
        self.udp_rx_bytes = 0;
        self.udp_tx_packets = 0;
        self.udp_tx_bytes = 0;
        self.tunn_net_writes = 0;
        self.tunn_net_write_copies = 0;
        self.conn_visits = 0;
        self.conn_requeues = 0;
        self.active_q_peak = 0;
        self.udp_pending_peak = 0;
        self.idle_wakes = 0;
        self.idle_wait_ns = 0;
        self.idle_wake_udp = 0;
        self.idle_wake_conn_req = 0;
        self.idle_wake_loop_notify = 0;
        self.idle_wake_timeout = 0;
    }

    fn observe_idle_wake(&mut self, wait_time: Duration, reason: IdleWakeReason) {
        if !self.enabled {
            return;
        }
        self.idle_wakes = self.idle_wakes.saturating_add(1);
        self.idle_wait_ns = self
            .idle_wait_ns
            .saturating_add(wait_time.as_nanos() as u64);
        match reason {
            IdleWakeReason::Udp => {
                self.idle_wake_udp = self.idle_wake_udp.saturating_add(1);
            }
            IdleWakeReason::ConnReq => {
                self.idle_wake_conn_req = self.idle_wake_conn_req.saturating_add(1);
            }
            IdleWakeReason::LoopNotify => {
                self.idle_wake_loop_notify = self.idle_wake_loop_notify.saturating_add(1);
            }
            IdleWakeReason::Timeout => {
                self.idle_wake_timeout = self.idle_wake_timeout.saturating_add(1);
            }
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run the local proxy. Returns when the tokio task is aborted or on fatal error.
pub async fn run_local_proxy(
    cfg: LocalProxyConfig,
    startup_status_file: Option<&str>,
) -> anyhow::Result<()> {
    let dns_servers = parse_dns_servers(&cfg);

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
    let virtual_ipv6: Option<Ipv6Addr> = cfg
        .virtual_ips
        .iter()
        .find_map(|s| s.split('/').next()?.parse::<Ipv6Addr>().ok());
    let virtual_ips = VirtualTunnelIps {
        ipv4: virtual_ipv4,
        ipv6: virtual_ipv6,
    };

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
    if virtual_ipv6.is_some() {
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::LOCALHOST);
    }

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
        dns_servers = dns_servers.len(),
        custom_dns = !dns_servers.is_empty(),
        endpoint = ?cfg.endpoint,
        "local_proxy_started"
    );
    info!(
        tcp_socket_buf = TCP_SOCKET_BUF,
        stream_buf = STREAM_BUF,
        remote_pending_max_bytes = REMOTE_PENDING_MAX_BYTES,
        client_pending_max_bytes = CLIENT_PENDING_MAX_BYTES,
        udp_recv_burst_max = UDP_RECV_BURST_MAX,
        udp_send_burst_max = UDP_SEND_BURST_MAX,
        "local_proxy_tuning_enabled"
    );
    let perf_enabled = std::env::var_os("TUNMUX_LOCAL_PROXY_PERF").is_some();
    if perf_enabled {
        info!("local_proxy_perf_enabled");
    }

    let (conn_req_tx, mut conn_req_rx) = mpsc::channel::<ConnRequest>(CLIENT_CHANNEL_CAP);
    let (dns_req_tx, mut dns_req_rx) = mpsc::channel::<DnsUdpRequest>(CLIENT_CHANNEL_CAP);
    let loop_notify = Arc::new(Notify::new());
    let dns_resolver = if dns_servers.is_empty() {
        None
    } else {
        Some(TunnelDnsResolver {
            dns_servers: Arc::new(dns_servers),
            virtual_ipv4,
            virtual_ipv6,
            dns_req_tx: dns_req_tx.clone(),
        })
    };

    let tx = conn_req_tx.clone();
    let notify = loop_notify.clone();
    let socks_dns_resolver = dns_resolver.clone();
    tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "socks5_accepted");
                    if let Err(e) = stream.set_nodelay(true) {
                        debug!(peer = ?peer, error = ?e.to_string(), "socks5_set_nodelay_failed");
                    }
                    let tx = tx.clone();
                    let notify = notify.clone();
                    let dns_resolver = socks_dns_resolver.clone();
                    tokio::spawn(async move {
                        if let Err(e) = socks5_serve(stream, tx, notify, dns_resolver).await {
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
    let http_dns_resolver = dns_resolver.clone();
    tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, peer)) => {
                    debug!(peer = ?peer, "http_accepted");
                    if let Err(e) = stream.set_nodelay(true) {
                        debug!(peer = ?peer, error = ?e.to_string(), "http_set_nodelay_failed");
                    }
                    let tx = tx.clone();
                    let notify = notify.clone();
                    let dns_resolver = http_dns_resolver.clone();
                    tokio::spawn(async move {
                        if let Err(e) = http_connect_serve(stream, tx, notify, dns_resolver).await {
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
    let mut dns_udp_entries: Vec<DnsUdpEntry> = Vec::new();
    let mut next_port: u16 = LOCAL_PORT_START;
    let mut wg_pending_tx: VecDeque<Bytes> = VecDeque::new();
    let mut active_conns: VecDeque<usize> = VecDeque::new();
    let mut scan_cursor: usize = 0;
    let mut wg_timer_deadline = Instant::now();
    let mut perf = DataplanePerf::new(perf_enabled);
    let mut startup_ready_written = startup_status_file.is_none();

    // Trigger an initial handshake proactively so the parent connect command
    // can report success only after an actual tunnel handshake.
    queue_tunn_network_write(
        tunn.format_handshake_initiation(&mut enc_buf, false),
        udp.as_ref(),
        &mut wg_pending_tx,
        &mut perf,
    );
    flush_udp_writes(udp.as_ref(), &mut wg_pending_tx, &mut perf);

    loop {
        let now_std = Instant::now();
        let now = smoltcp_now();

        if !startup_ready_written && tunn.time_since_last_handshake().is_some() {
            if let Some(path) = startup_status_file {
                if let Err(error) = std::fs::write(path, "ready\n") {
                    warn!(
                        status_file = path,
                        error = %error,
                        "local_proxy_startup_status_write_failed"
                    );
                }
            }
            startup_ready_written = true;
            info!("local_proxy_handshake_established");
        }

        if now_std >= wg_timer_deadline {
            queue_tunn_network_write(
                tunn.update_timers(&mut enc_buf),
                udp.as_ref(),
                &mut wg_pending_tx,
                &mut perf,
            );
            wg_timer_deadline = now_std + WG_TIMER_TICK_MAX;
        }

        while let Ok(req) = conn_req_rx.try_recv() {
            add_virtual_connection(
                req,
                &mut next_port,
                virtual_ips,
                &mut iface,
                &mut sockets,
                &mut conns,
                &mut active_conns,
            );
        }
        while let Ok(req) = dns_req_rx.try_recv() {
            add_dns_udp_query(req, &mut next_port, &mut sockets, &mut dns_udp_entries);
        }

        for _ in 0..UDP_RECV_BURST_MAX {
            match udp.try_recv(&mut udp_buf) {
                Ok(n) => match tunn.decapsulate(None, &udp_buf[..n], &mut decap_buf) {
                    TunnResult::WriteToTunnelV4(plain, _)
                    | TunnResult::WriteToTunnelV6(plain, _) => {
                        perf.udp_rx_packets = perf.udp_rx_packets.saturating_add(1);
                        perf.udp_rx_bytes = perf.udp_rx_bytes.saturating_add(n as u64);
                        device.inbound.push_back(Vec::from(plain));
                    }
                    TunnResult::WriteToNetwork(out) => {
                        queue_tunn_network_write(
                            TunnResult::WriteToNetwork(out),
                            udp.as_ref(),
                            &mut wg_pending_tx,
                            &mut perf,
                        );
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
        flush_udp_writes(udp.as_ref(), &mut wg_pending_tx, &mut perf);

        let poll_start = Instant::now();
        let _ = iface.poll(now, &mut device, &mut sockets);
        perf.iface_polls = perf.iface_polls.saturating_add(1);
        perf.iface_poll_ns = perf
            .iface_poll_ns
            .saturating_add(poll_start.elapsed().as_nanos() as u64);

        while let Some(plain) = device.outbound.pop_front() {
            queue_tunn_network_write(
                tunn.encapsulate(&plain, &mut enc_buf),
                udp.as_ref(),
                &mut wg_pending_tx,
                &mut perf,
            );
        }
        flush_udp_writes(udp.as_ref(), &mut wg_pending_tx, &mut perf);
        process_dns_udp_entries(&mut sockets, &mut dns_udp_entries, now_std);

        if active_conns.len() < ACTIVE_CONN_TOPUP_TARGET {
            top_up_active_conns(
                &mut conns,
                &sockets,
                &mut active_conns,
                &mut scan_cursor,
                ACTIVE_CONN_SWEEP_BATCH_MAX,
            );
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
            perf.conn_visits = perf.conn_visits.saturating_add(1);

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

            if !remove_current
                && sock.can_recv()
                && entry.pending_client_bytes < CLIENT_PENDING_MAX_BYTES
            {
                if let Ok(Some(chunk)) = sock.recv(|recv_buf| {
                    let n = recv_buf.len().min(STREAM_BUF);
                    if n == 0 {
                        (0, None)
                    } else {
                        (n, Some(Bytes::copy_from_slice(&recv_buf[..n])))
                    }
                }) {
                    entry.pending_client_bytes += chunk.len();
                    entry.pending_to_client.push_back(chunk);
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

            if conn_has_runnable_work(entry, sock) {
                requeue = true;
            }

            if requeue {
                perf.conn_requeues = perf.conn_requeues.saturating_add(1);
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
            if conns.is_empty() || scan_cursor >= conns.len() {
                scan_cursor = 0;
            }
        }

        let has_pending_work = !device.inbound.is_empty()
            || !device.outbound.is_empty()
            || !active_conns.is_empty()
            || conns.iter().any(|entry| entry.connected_tx.is_some())
            || !dns_udp_entries.is_empty();
        perf.observe_loop(active_conns.len(), wg_pending_tx.len());
        perf.maybe_log_and_reset(conns.len());
        if has_pending_work {
            tokio::task::yield_now().await;
            continue;
        }

        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(WG_TIMER_TICK_MAX);

        let timer_wait = wg_timer_deadline.saturating_duration_since(Instant::now());
        let wait_for = delay.min(timer_wait);

        let wait_started = Instant::now();
        let wake_reason = tokio::select! {
            _ = udp.readable() => IdleWakeReason::Udp,
            _ = udp.writable(), if !wg_pending_tx.is_empty() => IdleWakeReason::Udp,
            maybe_req = conn_req_rx.recv() => {
                if let Some(req) = maybe_req {
                    add_virtual_connection(
                        req,
                        &mut next_port,
                        virtual_ips,
                        &mut iface,
                        &mut sockets,
                        &mut conns,
                        &mut active_conns,
                    );
                }
                IdleWakeReason::ConnReq
            }
            maybe_dns_req = dns_req_rx.recv() => {
                if let Some(req) = maybe_dns_req {
                    add_dns_udp_query(
                        req,
                        &mut next_port,
                        &mut sockets,
                        &mut dns_udp_entries,
                    );
                }
                IdleWakeReason::ConnReq
            }
            _ = loop_notify.notified() => IdleWakeReason::LoopNotify,
            _ = tokio::time::sleep(wait_for) => IdleWakeReason::Timeout,
        };
        perf.observe_idle_wake(wait_started.elapsed(), wake_reason);
    }
}

fn queue_tunn_network_write(
    result: TunnResult<'_>,
    udp: &UdpSocket,
    wg_pending_tx: &mut VecDeque<Bytes>,
    perf: &mut DataplanePerf,
) {
    if let TunnResult::WriteToNetwork(out) = result {
        perf.tunn_net_writes = perf.tunn_net_writes.saturating_add(1);

        if wg_pending_tx.is_empty() {
            match udp.try_send(out) {
                Ok(sent) if sent == out.len() => {
                    perf.udp_tx_packets = perf.udp_tx_packets.saturating_add(1);
                    perf.udp_tx_bytes = perf.udp_tx_bytes.saturating_add(sent as u64);
                    return;
                }
                Ok(sent) => {
                    warn!(sent = sent, expected = out.len(), "udp_send_partial");
                    return;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    warn!(error = ?e.to_string(), "udp_send_error");
                    return;
                }
            }
        }

        wg_pending_tx.push_back(Bytes::copy_from_slice(out));
        perf.tunn_net_write_copies = perf.tunn_net_write_copies.saturating_add(1);
    }
}

fn flush_udp_writes(
    udp: &UdpSocket,
    wg_pending_tx: &mut VecDeque<Bytes>,
    perf: &mut DataplanePerf,
) {
    for _ in 0..UDP_SEND_BURST_MAX {
        let Some(front) = wg_pending_tx.front() else {
            break;
        };
        match udp.try_send(front.as_ref()) {
            Ok(sent) if sent == front.len() => {
                perf.udp_tx_packets = perf.udp_tx_packets.saturating_add(1);
                perf.udp_tx_bytes = perf.udp_tx_bytes.saturating_add(sent as u64);
                let _ = wg_pending_tx.pop_front();
            }
            Ok(sent) => {
                warn!(sent = sent, expected = front.len(), "udp_send_partial");
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

fn top_up_active_conns(
    conns: &mut [ConnEntry],
    sockets: &SocketSet<'_>,
    active_conns: &mut VecDeque<usize>,
    scan_cursor: &mut usize,
    sweep_batch_max: usize,
) {
    if conns.is_empty() {
        *scan_cursor = 0;
        return;
    }
    if *scan_cursor >= conns.len() {
        *scan_cursor = 0;
    }

    let mut scanned = 0usize;
    let scan_limit = sweep_batch_max.min(conns.len());
    while scanned < scan_limit && active_conns.len() < ACTIVE_CONN_TOPUP_TARGET {
        let idx = *scan_cursor;
        *scan_cursor += 1;
        if *scan_cursor >= conns.len() {
            *scan_cursor = 0;
        }
        if conn_has_runnable_work(&conns[idx], sockets.get::<TcpSocket>(conns[idx].handle)) {
            mark_conn_active(conns, active_conns, idx);
        }
        scanned += 1;
    }
}

fn add_virtual_connection(
    req: ConnRequest,
    next_port: &mut u16,
    virtual_ips: VirtualTunnelIps,
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
    sock.set_nagle_enabled(false);
    sock.set_ack_delay(None);
    let remote = IpEndpoint::new(req.target_ip, req.target_port);
    let local_ip = match req.target_ip {
        IpAddress::Ipv4(_) => IpAddress::Ipv4(virtual_ips.ipv4),
        IpAddress::Ipv6(_) => {
            let Some(v6) = virtual_ips.ipv6 else {
                let _ = req
                    .connected_tx
                    .send(Err("IPv6 is not available in this VPN profile".into()));
                return;
            };
            IpAddress::Ipv6(v6)
        }
    };
    let local = IpListenEndpoint {
        addr: Some(local_ip),
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

fn add_dns_udp_query(
    req: DnsUdpRequest,
    next_port: &mut u16,
    sockets: &mut SocketSet<'_>,
    dns_udp_entries: &mut Vec<DnsUdpEntry>,
) {
    let local_port = *next_port;
    *next_port = if *next_port >= LOCAL_PORT_END {
        LOCAL_PORT_START
    } else {
        *next_port + 1
    };

    let rx_meta = vec![UdpPacketMetadata::EMPTY; 1];
    let tx_meta = vec![UdpPacketMetadata::EMPTY; 1];
    let rx_buf = UdpPacketBuffer::new(rx_meta, vec![0u8; DNS_UDP_PACKET_CAP]);
    let tx_buf = UdpPacketBuffer::new(tx_meta, vec![0u8; DNS_UDP_PACKET_CAP]);
    let mut sock = SmolUdpSocket::new(rx_buf, tx_buf);

    let bind_endpoint = IpListenEndpoint {
        addr: Some(req.source_ip),
        port: local_port,
    };
    if let Err(error) = sock.bind(bind_endpoint) {
        let _ = req
            .response_tx
            .send(Err(format!("DNS UDP bind failed: {}", error)));
        return;
    }

    let remote = IpEndpoint::new(req.dns_server, 53);
    if let Err(error) = sock.send_slice(req.payload.as_slice(), remote) {
        let _ = req
            .response_tx
            .send(Err(format!("DNS UDP send failed: {}", error)));
        return;
    }

    let handle = sockets.add(sock);
    dns_udp_entries.push(DnsUdpEntry {
        handle,
        response_tx: Some(req.response_tx),
        deadline: Instant::now() + DNS_TUNNEL_QUERY_TTL,
    });
}

fn process_dns_udp_entries(
    sockets: &mut SocketSet<'_>,
    dns_udp_entries: &mut Vec<DnsUdpEntry>,
    now: Instant,
) {
    let mut remove = Vec::new();

    for (idx, entry) in dns_udp_entries.iter_mut().enumerate() {
        let mut remove_entry = false;
        let mut timeout_error = false;
        let mut response_packet: Option<Vec<u8>> = None;

        {
            let sock = sockets.get_mut::<SmolUdpSocket>(entry.handle);
            if sock.can_recv() {
                match sock.recv() {
                    Ok((packet, _)) => {
                        response_packet = Some(packet.to_vec());
                        remove_entry = true;
                    }
                    Err(_) => {
                        remove_entry = true;
                    }
                }
            }
        }

        if !remove_entry && now >= entry.deadline {
            timeout_error = true;
            remove_entry = true;
        }

        if remove_entry {
            if let Some(tx) = entry.response_tx.take() {
                if let Some(packet) = response_packet {
                    let _ = tx.send(Ok(packet));
                } else if timeout_error {
                    let _ = tx.send(Err("tunnel DNS UDP response timeout".to_string()));
                } else {
                    let _ = tx.send(Err("tunnel DNS UDP receive failed".to_string()));
                }
            }
            remove.push(idx);
        }
    }

    for idx in remove.into_iter().rev() {
        if idx < dns_udp_entries.len() {
            let entry = dns_udp_entries.remove(idx);
            sockets.remove(entry.handle);
        }
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

async fn socks5_serve(
    mut stream: TcpStream,
    conn_req_tx: mpsc::Sender<ConnRequest>,
    loop_notify: Arc<Notify>,
    dns_resolver: Option<TunnelDnsResolver>,
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

    let (target_ip, target_port) =
        read_socks5_addr(&mut stream, hdr[3], dns_resolver.as_ref()).await?;

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

async fn read_socks5_addr(
    stream: &mut TcpStream,
    atyp: u8,
    dns_resolver: Option<&TunnelDnsResolver>,
) -> anyhow::Result<(IpAddress, u16)> {
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
            let sa = resolve_ipv4_preferred(host, port, dns_resolver).await?;
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
    dns_resolver: Option<TunnelDnsResolver>,
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
        let sa = resolve_ipv4_preferred(host, port, dns_resolver.as_ref()).await?;

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

        let sa = resolve_ipv4_preferred(&host, port, dns_resolver.as_ref()).await?;

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

fn parse_dns_servers(cfg: &LocalProxyConfig) -> Vec<IpAddr> {
    cfg.dns_servers
        .iter()
        .filter_map(|dns| normalize_dns_server(dns))
        .filter_map(|dns| match dns.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(error) => {
                warn!(dns_server = dns, error = %error, "local_proxy_dns_server_parse_failed");
                None
            }
        })
        .collect()
}

fn normalize_dns_server(value: &str) -> Option<&str> {
    let host = value
        .trim()
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('[')
        .trim_matches(']');
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Resolve `host` to a `SocketAddr`, preferring IPv4.
///
/// The smoltcp virtual interface only has a default IPv4 route, so IPv6
/// targets would be unroutable. Prefer the first IPv4 result; fall back to
/// the first address of any family only when no IPv4 address is returned.
async fn resolve_ipv4_preferred(
    host: &str,
    port: u16,
    dns_resolver: Option<&TunnelDnsResolver>,
) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let cache_key = format!("{}:{}", host, port);
    if let Some(hit) = dns_cache_get(&cache_key) {
        return select_ipv4_preferred(hit.into_iter())
            .ok_or_else(|| anyhow!("DNS returned no addresses for {}", host));
    }

    let addrs: Vec<SocketAddr> = if let Some(resolver) = dns_resolver {
        resolve_with_tunnel_dns(resolver, host, port).await?
    } else {
        // Keep system resolver only as a compatibility fallback when config
        // carries no DNS servers at all.
        resolve_with_system_dns(host, port).await?
    };

    dns_cache_put(cache_key, addrs.clone());
    select_ipv4_preferred(addrs.into_iter())
        .ok_or_else(|| anyhow!("DNS returned no addresses for {}", host))
}

async fn resolve_with_tunnel_dns(
    resolver: &TunnelDnsResolver,
    host: &str,
    port: u16,
) -> anyhow::Result<Vec<SocketAddr>> {
    let ips = resolve_host_via_tunnel_dns(resolver, host).await?;
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

async fn resolve_host_via_tunnel_dns(
    resolver: &TunnelDnsResolver,
    host: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut last_error: Option<anyhow::Error> = None;

    let mut v4_results: Vec<IpAddr> = Vec::new();
    for dns_server in resolver.dns_servers.iter().copied() {
        match dns_query_over_tunnel(resolver, dns_server, host, 1).await {
            Ok(mut ips) => v4_results.append(&mut ips),
            Err(error) => {
                warn!(
                    host = host,
                    dns_server = %dns_server,
                    error = %error,
                    "tunnel_dns_a_query_failed"
                );
                last_error = Some(error);
            }
        }
        if !v4_results.is_empty() {
            return Ok(dedup_ips(v4_results));
        }
    }

    let mut v6_results: Vec<IpAddr> = Vec::new();
    for dns_server in resolver.dns_servers.iter().copied() {
        match dns_query_over_tunnel(resolver, dns_server, host, 28).await {
            Ok(mut ips) => v6_results.append(&mut ips),
            Err(error) => {
                warn!(
                    host = host,
                    dns_server = %dns_server,
                    error = %error,
                    "tunnel_dns_aaaa_query_failed"
                );
                last_error = Some(error);
            }
        }
        if !v6_results.is_empty() {
            return Ok(dedup_ips(v6_results));
        }
    }

    if let Some(error) = last_error {
        return Err(error).context(format!("tunnel DNS lookup failed for {}", host));
    }

    anyhow::bail!("tunnel DNS returned no addresses for {}", host);
}

fn dedup_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut unique = Vec::with_capacity(ips.len());
    for ip in ips {
        if seen.insert(ip) {
            unique.push(ip);
        }
    }
    unique
}

async fn dns_query_over_tunnel(
    resolver: &TunnelDnsResolver,
    dns_server: IpAddr,
    host: &str,
    qtype: u16,
) -> anyhow::Result<Vec<IpAddr>> {
    let query_id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_query(host, qtype, query_id)?;
    let source_ip = dns_source_ip_for_server(resolver, dns_server)
        .ok_or_else(|| anyhow!("no matching local source IP for DNS server {}", dns_server))?;
    let (response_tx, response_rx) = oneshot::channel();

    resolver
        .dns_req_tx
        .send(DnsUdpRequest {
            dns_server: ip_to_smoltcp(dns_server),
            source_ip,
            payload: query,
            response_tx,
        })
        .await
        .map_err(|_| anyhow!("proxy tunnel exited"))?;

    let response_wait = DNS_TUNNEL_QUERY_TTL + Duration::from_secs(1);
    let response = tokio::time::timeout(response_wait, response_rx)
        .await
        .context("tunnel DNS response wait timeout")?
        .map_err(|_| anyhow!("tunnel DNS response dropped"))?
        .map_err(|error| anyhow!(error))?;

    parse_dns_response_ips(response.as_slice(), query_id, qtype)
}

fn dns_source_ip_for_server(resolver: &TunnelDnsResolver, dns_server: IpAddr) -> Option<IpAddress> {
    match dns_server {
        IpAddr::V4(_) => Some(IpAddress::Ipv4(resolver.virtual_ipv4)),
        IpAddr::V6(_) => resolver.virtual_ipv6.map(IpAddress::Ipv6),
    }
}

fn build_dns_query(host: &str, qtype: u16, query_id: u16) -> anyhow::Result<Vec<u8>> {
    let qname = host.trim().trim_end_matches('.');
    anyhow::ensure!(!qname.is_empty(), "DNS host is empty");

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in qname.split('.') {
        anyhow::ensure!(!label.is_empty(), "DNS host contains empty label");
        anyhow::ensure!(label.len() <= 63, "DNS label too long (max 63): {}", label);
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn parse_dns_response_ips(
    response: &[u8],
    query_id: u16,
    qtype: u16,
) -> anyhow::Result<Vec<IpAddr>> {
    anyhow::ensure!(response.len() >= 12, "DNS response too short");
    let id = u16::from_be_bytes([response[0], response[1]]);
    anyhow::ensure!(
        id == query_id,
        "DNS response id mismatch: expected {}, got {}",
        query_id,
        id
    );
    let flags = u16::from_be_bytes([response[2], response[3]]);
    anyhow::ensure!((flags & 0x8000) != 0, "DNS response missing QR flag");
    anyhow::ensure!((flags & 0x0200) == 0, "DNS response was truncated");
    let rcode = flags & 0x000F;
    if rcode == 3 {
        return Ok(Vec::new());
    }
    anyhow::ensure!(rcode == 0, "DNS query failed with rcode {}", rcode);

    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(response, offset)?;
        anyhow::ensure!(offset + 4 <= response.len(), "DNS question truncated");
        offset += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(response, offset)?;
        anyhow::ensure!(offset + 10 <= response.len(), "DNS answer header truncated");
        let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rr_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        anyhow::ensure!(
            offset + rdlength <= response.len(),
            "DNS answer rdata truncated"
        );

        if rr_class == 1 {
            if rr_type == 1 && rdlength == 4 {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                )));
            } else if rr_type == 28 && rdlength == 16 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&response[offset..offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
            }
        }
        offset += rdlength;
    }

    if qtype == 1 {
        ips.retain(|ip| ip.is_ipv4());
    } else if qtype == 28 {
        ips.retain(|ip| ip.is_ipv6());
    }

    Ok(dedup_ips(ips))
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> anyhow::Result<usize> {
    loop {
        anyhow::ensure!(offset < packet.len(), "DNS name out of bounds");
        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }

        let kind = len & 0xC0;
        if kind == 0xC0 {
            anyhow::ensure!(
                offset + 1 < packet.len(),
                "DNS name compression pointer truncated"
            );
            return Ok(offset + 2);
        }

        anyhow::ensure!(kind == 0, "DNS name label has invalid high bits");
        let label_len = len as usize;
        anyhow::ensure!(label_len <= 63, "DNS label too long in response");
        offset += 1;
        anyhow::ensure!(
            offset + label_len <= packet.len(),
            "DNS name label truncated in response"
        );
        offset += label_len;
    }
}

async fn resolve_with_system_dns(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("DNS lookup failed: {}", host))?
        .collect())
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

#[cfg(test)]
mod tests {
    use super::{
        build_dns_query, dns_source_ip_for_server, normalize_dns_server, parse_dns_response_ips,
        TunnelDnsResolver,
    };
    use std::net::IpAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn normalize_dns_server_trims_cidr_and_brackets() {
        assert_eq!(
            normalize_dns_server("[2001:4860:4860::8888]/128"),
            Some("2001:4860:4860::8888")
        );
    }

    #[test]
    fn build_dns_query_encodes_labels() {
        let query = build_dns_query("example.com", 1, 0x1234).expect("build query");
        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(query[12], 7);
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3);
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0);
    }

    #[test]
    fn parse_dns_response_extracts_a_record() {
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        response.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
        response.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        response.extend_from_slice(&1u16.to_be_bytes()); // ancount
        response.extend_from_slice(&0u16.to_be_bytes()); // nscount
        response.extend_from_slice(&0u16.to_be_bytes()); // arcount
        response.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        response.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        response.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        response.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        response.extend_from_slice(&1u16.to_be_bytes()); // type A
        response.extend_from_slice(&1u16.to_be_bytes()); // class IN
        response.extend_from_slice(&60u32.to_be_bytes()); // ttl
        response.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        response.extend_from_slice(&[1, 2, 3, 4]); // rdata

        let ips = parse_dns_response_ips(&response, 0x1234, 1).expect("parse response");
        assert_eq!(
            ips,
            vec!["1.2.3.4".parse::<IpAddr>().expect("parse expected ip")]
        );
    }

    #[test]
    fn parse_dns_response_nxdomain_returns_empty() {
        let mut response = Vec::new();
        response.extend_from_slice(&0x4321u16.to_be_bytes()); // id
        response.extend_from_slice(&0x8183u16.to_be_bytes()); // flags with NXDOMAIN
        response.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        response.extend_from_slice(&0u16.to_be_bytes()); // ancount
        response.extend_from_slice(&0u16.to_be_bytes()); // nscount
        response.extend_from_slice(&0u16.to_be_bytes()); // arcount
        response.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        response.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        response.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

        let ips = parse_dns_response_ips(&response, 0x4321, 1).expect("parse response");
        assert!(ips.is_empty());
    }

    #[test]
    fn dns_source_ip_matches_server_family() {
        let (dns_req_tx, _dns_req_rx) = mpsc::channel(1);
        let resolver = TunnelDnsResolver {
            dns_servers: Arc::new(vec!["10.0.0.1"
                .parse::<IpAddr>()
                .expect("parse DNS server")]),
            virtual_ipv4: Ipv4Addr::new(10, 0, 0, 2),
            virtual_ipv6: Some("fd00::2".parse::<Ipv6Addr>().expect("parse virtual IPv6")),
            dns_req_tx,
        };

        let v4 = dns_source_ip_for_server(&resolver, "10.0.0.1".parse().expect("parse v4 DNS"));
        assert_eq!(
            v4,
            Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)))
        );

        let v6 = dns_source_ip_for_server(&resolver, "fd00::1".parse().expect("parse v6 DNS"));
        assert_eq!(
            v6,
            Some(smoltcp::wire::IpAddress::Ipv6(
                "fd00::2".parse::<Ipv6Addr>().expect("parse expected IPv6")
            ))
        );
    }
}

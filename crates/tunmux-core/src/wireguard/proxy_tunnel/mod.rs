//! Userspace WireGuard proxy tunnel.
//!
//! Runs a WireGuard session backed by boringtun + smoltcp and exposes it as
//! SOCKS5 and HTTP proxies on loopback -- no TUN device, root, or netns needed.

mod bridge;
mod device;
mod dns;
mod http;
mod perf;
mod socks5;
mod udp_io;

pub(crate) mod connection;
pub(crate) mod queue;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU16;
use std::sync::{Arc, LazyLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::Socket as TcpSocket;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

use connection::{
    add_dns_udp_query, add_virtual_connection, expire_pending_connects, mark_conn_active,
    next_pending_deadline, process_dns_udp_entries, service_conn, top_up_active_conns, ConnEntry,
    ConnStep, DnsUdpEntry, VirtualTunnelIps,
};
use device::{Packet, VirtualDevice};
use dns::parse_dns_servers;
use perf::{DataplanePerf, IdleWakeReason};
use queue::{ConnRequest, DnsUdpRequest};
use udp_io::{UdpRx, UdpTx};

const UDP_BUF: usize = 65536;
/// Requested WireGuard socket buffers; the kernel caps them at rmem_max/wmem_max.
/// smoltcp advertises up to `TCP_SOCKET_BUF` per connection, so the receive side
/// must absorb a burst of that size or datagrams drop and senders back off.
const UDP_SOCKET_BUF: usize = 8 * 1024 * 1024;
const TCP_SOCKET_BUF: usize = 2097152;
const STREAM_BUF: usize = 65536;
const LOCAL_PORT_START: u16 = 40000;
const LOCAL_PORT_END: u16 = 65000;
const WG_TIMER_TICK_MAX: Duration = Duration::from_millis(100);
const CLIENT_CHANNEL_CAP: usize = 1024;
const REMOTE_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const CLIENT_PENDING_MAX_BYTES: usize = 2 * 1024 * 1024;
const UDP_RECV_BURST_MAX: usize = 192;
const ACTIVE_CONN_BATCH_MAX: usize = 384;
const ACTIVE_CONN_TOPUP_TARGET: usize = 768;
const ACTIVE_CONN_SWEEP_BATCH_MAX: usize = 384;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
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
pub(crate) struct TunnelDnsResolver {
    pub(crate) dns_servers: Arc<Vec<IpAddr>>,
    pub(crate) virtual_ipv4: Ipv4Addr,
    pub(crate) virtual_ipv6: Option<Ipv6Addr>,
    pub(crate) dns_req_tx: mpsc::Sender<DnsUdpRequest>,
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
    tune_udp_buffers(&udp);
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
                        if let Err(e) = socks5::socks5_serve(stream, tx, notify, dns_resolver).await
                        {
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
                        if let Err(e) =
                            http::http_connect_serve(stream, tx, notify, dns_resolver).await
                        {
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

    let mut udp_rx = UdpRx::new(udp.as_ref());
    let mut udp_tx = UdpTx::new();
    let mut conns: Vec<ConnEntry> = Vec::new();
    let mut dns_udp_entries: Vec<DnsUdpEntry> = Vec::new();
    let mut next_port: u16 = LOCAL_PORT_START;
    let mut active_conns: VecDeque<usize> = VecDeque::new();
    let mut scan_cursor: usize = 0;
    let mut wg_timer_deadline = Instant::now();
    let mut perf = DataplanePerf::new(perf_enabled);
    let mut startup_ready_written = startup_status_file.is_none();

    // Trigger an initial handshake proactively so the parent connect command
    // can report success only after an actual tunnel handshake.
    udp_tx.push_with(&mut perf, |dst| {
        network_len(tunn.format_handshake_initiation(dst, false))
    });
    udp_tx.flush(udp.as_ref(), &mut perf);

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
            udp_tx.push_with(&mut perf, |dst| network_len(tunn.update_timers(dst)));
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

        let mut received = 0usize;
        while received < UDP_RECV_BURST_MAX {
            match udp_rx.recv(udp.as_ref(), &mut perf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(error = ?e.to_string(), "udp_recv_error");
                    break;
                }
            }
            for datagram in udp_rx.datagrams() {
                received += 1;
                // Decrypt straight into a pooled buffer; boringtun writes the
                // plaintext from offset 0.
                let mut buf = device.rx_pool.take(datagram.len());
                match tunn.decapsulate(None, datagram, &mut buf) {
                    TunnResult::WriteToTunnelV4(plain, _)
                    | TunnResult::WriteToTunnelV6(plain, _) => {
                        let len = plain.len();
                        perf.udp_rx_packets = perf.udp_rx_packets.saturating_add(1);
                        perf.udp_rx_bytes = perf.udp_rx_bytes.saturating_add(datagram.len() as u64);
                        device.inbound.push_back(Packet::new(buf, len));
                    }
                    TunnResult::WriteToNetwork(out) => {
                        udp_tx.push(&mut perf, out);
                        device.rx_pool.put(buf);
                    }
                    _ => device.rx_pool.put(buf),
                }
            }
        }
        udp_tx.flush(udp.as_ref(), &mut perf);

        let poll_start = Instant::now();
        let _ = iface.poll(now, &mut device, &mut sockets);
        perf.iface_polls = perf.iface_polls.saturating_add(1);
        perf.iface_poll_ns = perf
            .iface_poll_ns
            .saturating_add(poll_start.elapsed().as_nanos() as u64);

        while let Some(packet) = device.outbound.pop_front() {
            udp_tx.push_with(&mut perf, |dst| {
                network_len(tunn.encapsulate(packet.as_slice(), dst))
            });
            device.tx_pool.put(packet.into_buf());
        }
        udp_tx.flush(udp.as_ref(), &mut perf);
        process_dns_udp_entries(&mut sockets, &mut dns_udp_entries, now_std);
        expire_pending_connects(&mut conns, &mut sockets, &mut active_conns, now_std);

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

            let entry = &mut conns[i];
            let sock = sockets.get_mut::<TcpSocket>(entry.handle);
            let requeue = match service_conn(entry, sock) {
                ConnStep::Remove => {
                    remove.push(i);
                    continue;
                }
                ConnStep::Requeue => true,
                ConnStep::Idle => false,
            };

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
                e.from_client_rx.close();
                e.to_client_tx.close();
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

        let has_pending_work =
            !device.inbound.is_empty() || !device.outbound.is_empty() || !active_conns.is_empty();
        perf.observe_loop(active_conns.len(), udp_tx.pending());
        perf.maybe_log_and_reset(conns.len());
        if has_pending_work {
            tokio::task::yield_now().await;
            continue;
        }

        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(WG_TIMER_TICK_MAX);

        let wake_at = next_pending_deadline(&conns, &dns_udp_entries)
            .map_or(wg_timer_deadline, |deadline| {
                deadline.min(wg_timer_deadline)
            });
        let wait_for = delay.min(wake_at.saturating_duration_since(Instant::now()));

        let wait_started = Instant::now();
        let wake_reason = tokio::select! {
            _ = udp.readable() => IdleWakeReason::Udp,
            _ = udp.writable(), if udp_tx.pending() > 0 => IdleWakeReason::Udp,
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

fn tune_udp_buffers(udp: &UdpSocket) {
    let sock = socket2::SockRef::from(udp);
    if let Err(error) = sock.set_recv_buffer_size(UDP_SOCKET_BUF) {
        warn!(error = %error, "udp_recv_buffer_resize_failed");
    }
    if let Err(error) = sock.set_send_buffer_size(UDP_SOCKET_BUF) {
        warn!(error = %error, "udp_send_buffer_resize_failed");
    }
    info!(
        requested = UDP_SOCKET_BUF,
        recv_buf = sock.recv_buffer_size().ok(),
        send_buf = sock.send_buffer_size().ok(),
        "local_proxy_udp_buffers"
    );
}

fn network_len(result: TunnResult<'_>) -> Option<usize> {
    match result {
        TunnResult::WriteToNetwork(out) => Some(out.len()),
        _ => None,
    }
}

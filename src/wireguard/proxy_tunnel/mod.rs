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
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::Socket as TcpSocket;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

use connection::{
    add_dns_udp_query, add_virtual_connection, conn_has_runnable_work, mark_conn_active,
    process_dns_udp_entries, top_up_active_conns, ConnEntry, DnsUdpEntry, VirtualTunnelIps,
};
use device::VirtualDevice;
use dns::parse_dns_servers;
use perf::{DataplanePerf, IdleWakeReason};
use queue::{ConnRequest, DnsUdpRequest, QueuePushError};

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

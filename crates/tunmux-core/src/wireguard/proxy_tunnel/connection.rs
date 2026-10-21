use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as SmolUdpSocket,
};
use smoltcp::wire::{IpAddress, IpListenEndpoint};
use tokio::sync::oneshot;

use super::queue::{ByteQueue, ConnRequest, DnsUdpRequest};
use super::{
    CLIENT_PENDING_MAX_BYTES, CONNECT_TIMEOUT, DNS_TUNNEL_QUERY_TTL, DNS_UDP_PACKET_CAP,
    LOCAL_PORT_END, LOCAL_PORT_START, REMOTE_PENDING_MAX_BYTES, TCP_SOCKET_BUF,
};

pub(crate) struct ConnEntry {
    pub(crate) handle: smoltcp::iface::SocketHandle,
    pub(crate) to_client_tx: Arc<ByteQueue>,
    pub(crate) from_client_rx: Arc<ByteQueue>,
    /// Present until the virtual TCP handshake completes.
    pub(crate) connected_tx: Option<oneshot::Sender<Result<(), String>>>,
    pub(crate) connect_deadline: Instant,
    pub(crate) pending_to_remote: VecDeque<Bytes>,
    pub(crate) pending_to_client: VecDeque<Bytes>,
    pub(crate) pending_remote_bytes: usize,
    pub(crate) pending_client_bytes: usize,
    pub(crate) active: bool,
}

pub(crate) struct DnsUdpEntry {
    pub(crate) handle: smoltcp::iface::SocketHandle,
    pub(crate) response_tx: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    pub(crate) deadline: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct VirtualTunnelIps {
    pub(crate) ipv4: std::net::Ipv4Addr,
    pub(crate) ipv6: Option<std::net::Ipv6Addr>,
}

/// A handshake still in flight needs no visit: its reply arrives over UDP and
/// wakes the loop, and its deadline bounds the idle wait.
fn connect_in_flight(sock: &TcpSocket<'_>) -> bool {
    matches!(sock.state(), TcpState::SynSent | TcpState::SynReceived)
}

pub(crate) fn conn_has_runnable_work(entry: &ConnEntry, sock: &TcpSocket<'_>) -> bool {
    (entry.connected_tx.is_some() && !connect_in_flight(sock))
        || (!entry.from_client_rx.is_empty()
            && entry.pending_remote_bytes < REMOTE_PENDING_MAX_BYTES)
        || (!entry.pending_to_remote.is_empty() && sock.can_send())
        || (!entry.pending_to_client.is_empty() && !entry.to_client_tx.is_full())
        || (sock.can_recv() && entry.pending_client_bytes < CLIENT_PENDING_MAX_BYTES)
}

pub(crate) fn mark_conn_active(
    conns: &mut [ConnEntry],
    active_conns: &mut VecDeque<usize>,
    idx: usize,
) {
    if idx >= conns.len() || conns[idx].active {
        return;
    }
    conns[idx].active = true;
    active_conns.push_back(idx);
}

pub(crate) fn top_up_active_conns(
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
    while scanned < scan_limit && active_conns.len() < super::ACTIVE_CONN_TOPUP_TARGET {
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

pub(crate) fn add_virtual_connection(
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
    let remote = smoltcp::wire::IpEndpoint::new(req.target_ip, req.target_port);
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
                connect_deadline: Instant::now() + CONNECT_TIMEOUT,
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

/// Fail connects whose handshake outlived `CONNECT_TIMEOUT` and queue them for
/// removal, so a silent destination cannot pin an entry forever.
pub(crate) fn expire_pending_connects(
    conns: &mut [ConnEntry],
    sockets: &mut SocketSet<'_>,
    active_conns: &mut VecDeque<usize>,
    now: Instant,
) {
    for idx in 0..conns.len() {
        let entry = &mut conns[idx];
        if entry.connected_tx.is_none() || now < entry.connect_deadline {
            continue;
        }
        let sock = sockets.get_mut::<TcpSocket>(entry.handle);
        if !connect_in_flight(sock) {
            continue;
        }
        if let Some(tx) = entry.connected_tx.take() {
            let _ = tx.send(Err("connection timed out".into()));
        }
        sock.abort();
        mark_conn_active(conns, active_conns, idx);
    }
}

/// Earliest connect or tunnel DNS deadline still pending, if any.
pub(crate) fn next_pending_deadline(
    conns: &[ConnEntry],
    dns_udp_entries: &[DnsUdpEntry],
) -> Option<Instant> {
    let connects = conns
        .iter()
        .filter(|entry| entry.connected_tx.is_some())
        .map(|entry| entry.connect_deadline);
    let dns = dns_udp_entries
        .iter()
        .filter(|entry| entry.response_tx.is_some())
        .map(|entry| entry.deadline);
    connects.chain(dns).min()
}

pub(crate) fn add_dns_udp_query(
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

    let remote = smoltcp::wire::IpEndpoint::new(req.dns_server, 53);
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

pub(crate) fn process_dns_udp_entries(
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use smoltcp::iface::Config;
    use tokio::sync::Notify;

    use super::super::device::VirtualDevice;
    use super::super::CLIENT_CHANNEL_CAP;
    use super::*;

    struct Harness {
        iface: Interface,
        sockets: SocketSet<'static>,
        conns: Vec<ConnEntry>,
        active_conns: VecDeque<usize>,
        next_port: u16,
    }

    impl Harness {
        fn new() -> Self {
            let mut device = VirtualDevice::new();
            let mut iface = Interface::new(
                Config::new(smoltcp::wire::HardwareAddress::Ip),
                &mut device,
                smoltcp::time::Instant::from_millis(0),
            );
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push("10.0.0.2/32".parse().expect("valid cidr"));
            });
            Self {
                iface,
                sockets: SocketSet::new(vec![]),
                conns: Vec::new(),
                active_conns: VecDeque::new(),
                next_port: LOCAL_PORT_START,
            }
        }

        fn connect(&mut self) -> oneshot::Receiver<Result<(), String>> {
            let notify = Arc::new(Notify::new());
            let (connected_tx, connected_rx) = oneshot::channel();
            let req = ConnRequest {
                target_ip: IpAddress::Ipv4(Ipv4Addr::new(10, 255, 255, 1)),
                target_port: 80,
                to_client_tx: Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, notify.clone())),
                from_client_rx: Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, notify)),
                connected_tx,
            };
            let ips = VirtualTunnelIps {
                ipv4: Ipv4Addr::new(10, 0, 0, 2),
                ipv6: None,
            };
            add_virtual_connection(
                req,
                &mut self.next_port,
                ips,
                &mut self.iface,
                &mut self.sockets,
                &mut self.conns,
                &mut self.active_conns,
            );
            self.active_conns.clear();
            for entry in &mut self.conns {
                entry.active = false;
            }
            connected_rx
        }

        fn sock(&self, idx: usize) -> &TcpSocket<'static> {
            self.sockets.get::<TcpSocket>(self.conns[idx].handle)
        }
    }

    #[test]
    fn test_connect_in_flight_is_not_runnable_work() {
        let mut h = Harness::new();
        let _rx = h.connect();
        assert_eq!(h.sock(0).state(), TcpState::SynSent);
        assert!(!conn_has_runnable_work(&h.conns[0], h.sock(0)));
    }

    #[test]
    fn test_expire_pending_connects_fails_stalled_handshake_at_deadline() {
        let mut h = Harness::new();
        let mut rx = h.connect();
        let past_deadline = h.conns[0].connect_deadline + Duration::from_millis(1);

        expire_pending_connects(
            &mut h.conns,
            &mut h.sockets,
            &mut h.active_conns,
            past_deadline,
        );

        assert_eq!(
            rx.try_recv().expect("connect result sent"),
            Err("connection timed out".to_string())
        );
        assert!(!h.sock(0).is_open());
        assert_eq!(h.active_conns, VecDeque::from([0]));
        assert_eq!(next_pending_deadline(&h.conns, &[]), None);
    }

    #[test]
    fn test_expire_pending_connects_keeps_handshake_before_deadline() {
        let mut h = Harness::new();
        let mut rx = h.connect();
        let before_deadline = h.conns[0].connect_deadline - Duration::from_millis(1);

        expire_pending_connects(
            &mut h.conns,
            &mut h.sockets,
            &mut h.active_conns,
            before_deadline,
        );

        assert!(rx.try_recv().is_err());
        assert_eq!(h.sock(0).state(), TcpState::SynSent);
        assert!(h.active_conns.is_empty());
    }

    #[test]
    fn test_next_pending_deadline_picks_earliest_connect_or_dns() {
        let mut h = Harness::new();
        let _rx = h.connect();
        let connect_deadline = h.conns[0].connect_deadline;
        let (dns_tx, _dns_rx) = oneshot::channel();
        let dns_deadline = connect_deadline - Duration::from_secs(1);
        let dns = DnsUdpEntry {
            handle: h.conns[0].handle,
            response_tx: Some(dns_tx),
            deadline: dns_deadline,
        };

        assert_eq!(next_pending_deadline(&h.conns, &[]), Some(connect_deadline));
        assert_eq!(
            next_pending_deadline(&h.conns, std::slice::from_ref(&dns)),
            Some(dns_deadline)
        );
    }
}

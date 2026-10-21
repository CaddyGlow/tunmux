use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as SmolUdpSocket,
};
use smoltcp::wire::{IpAddress, IpListenEndpoint};
use tokio::sync::oneshot;

use super::queue::{ByteQueue, ConnRequest, DnsUdpRequest};
use super::{
    CLIENT_PENDING_MAX_BYTES, DNS_TUNNEL_QUERY_TTL, DNS_UDP_PACKET_CAP, LOCAL_PORT_END,
    LOCAL_PORT_START, REMOTE_PENDING_MAX_BYTES, TCP_SOCKET_BUF,
};

pub(crate) struct ConnEntry {
    pub(crate) handle: smoltcp::iface::SocketHandle,
    pub(crate) to_client_tx: Arc<ByteQueue>,
    pub(crate) from_client_rx: Arc<ByteQueue>,
    /// Present until the virtual TCP handshake completes.
    pub(crate) connected_tx: Option<oneshot::Sender<Result<(), String>>>,
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

pub(crate) fn conn_has_runnable_work(entry: &ConnEntry, sock: &TcpSocket<'_>) -> bool {
    entry.connected_tx.is_some()
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

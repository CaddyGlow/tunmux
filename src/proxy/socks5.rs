use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::task::AbortHandle;
use tracing::{debug, warn};

// SOCKS5 constants
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub struct UdpAssociation {
    outbound: Arc<UdpSocket>,
    client_addr: Arc<Mutex<SocketAddr>>,
    abort_handle: AbortHandle,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

pub struct UdpAssociations {
    inner: RwLock<HashMap<SocketAddr, UdpAssociation>>,
}

impl UdpAssociations {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    async fn insert(&self, key: SocketAddr, assoc: UdpAssociation) {
        self.inner.write().await.insert(key, assoc);
    }

    async fn remove(&self, key: &SocketAddr) {
        self.inner.write().await.remove(key);
    }

    /// Look up an association by client address. If not found, try a sentinel
    /// key (same IP, port 0) and upgrade it to the actual address.
    async fn lookup(&self, from: &SocketAddr) -> Option<Arc<UdpSocket>> {
        // Fast path: exact match (read lock only)
        {
            let map = self.inner.read().await;
            if let Some(assoc) = map.get(from) {
                return Some(assoc.outbound.clone());
            }
        }
        // Slow path: check sentinel and re-key
        let sentinel = SocketAddr::new(from.ip(), 0);
        let mut map = self.inner.write().await;
        if let Some(assoc) = map.get(from) {
            return Some(assoc.outbound.clone());
        }
        if let Some(assoc) = map.remove(&sentinel) {
            *assoc.client_addr.lock().unwrap() = *from;
            let outbound = assoc.outbound.clone();
            map.insert(*from, assoc);
            return Some(outbound);
        }
        None
    }
}

pub async fn handle_socks5(
    mut client: TcpStream,
    associations: Arc<UdpAssociations>,
    udp_relay: Option<(Arc<UdpSocket>, SocketAddr)>,
) -> anyhow::Result<()> {
    // 1. Greeting: client sends version + method list
    let ver = client.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version: {}", ver);
    }
    let nmethods = client.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&AUTH_NONE) {
        client.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        anyhow::bail!("client does not support no-auth");
    }
    client.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;

    // 2. Request: VER CMD RSV ATYP ...
    let ver = client.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("unexpected version in request: {}", ver);
    }
    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    match cmd {
        CMD_CONNECT => handle_connect(client, atyp).await,
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(client, atyp, associations, udp_relay).await
        }
        _ => {
            send_reply(&mut client, REP_CMD_NOT_SUPPORTED, None).await?;
            anyhow::bail!("unsupported SOCKS command: {}", cmd);
        }
    }
}

/// Parse the address (ATYP-dependent) and port from the SOCKS5 request stream.
async fn parse_address(
    client: &mut TcpStream,
    atyp: u8,
) -> anyhow::Result<(String, u16)> {
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        ATYP_DOMAIN => {
            let len = client.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            client.read_exact(&mut buf).await?;
            String::from_utf8(buf)?
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            client.read_exact(&mut buf).await?;
            format!("[{}]", Ipv6Addr::from(buf))
        }
        _ => {
            send_reply(client, REP_ATYP_NOT_SUPPORTED, None).await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };
    let port = client.read_u16().await?;
    Ok((addr, port))
}

async fn handle_connect(mut client: TcpStream, atyp: u8) -> anyhow::Result<()> {
    let (addr, port) = parse_address(&mut client, atyp).await?;
    let target = format!("{}:{}", addr, port);
    debug!("SOCKS5 CONNECT to {}", target);

    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            send_reply(&mut client, REP_SUCCESS, None).await?;
            let result = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
            if let Err(e) = result {
                debug!("SOCKS5 tunnel closed: {}", e);
            }
        }
        Err(e) => {
            warn!("SOCKS5 connect to {} failed: {}", target, e);
            send_reply(&mut client, REP_GENERAL_FAILURE, None).await?;
        }
    }

    Ok(())
}

async fn handle_udp_associate(
    mut client: TcpStream,
    atyp: u8,
    associations: Arc<UdpAssociations>,
    udp_relay: Option<(Arc<UdpSocket>, SocketAddr)>,
) -> anyhow::Result<()> {
    let (addr_str, port) = parse_address(&mut client, atyp).await?;

    let Some((relay_socket, relay_addr)) = udp_relay else {
        send_reply(&mut client, REP_CMD_NOT_SUPPORTED, None).await?;
        anyhow::bail!("UDP ASSOCIATE not available (no relay socket)");
    };

    // Determine the association key. If the client declares 0.0.0.0:0 (or [::]:0),
    // use a sentinel key (TCP peer IP, port 0) that will be upgraded on first datagram.
    let declared: SocketAddr = format!("{}:{}", addr_str, port)
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    let peer_addr = client.peer_addr()?;
    let assoc_key = if declared.ip().is_unspecified() && declared.port() == 0 {
        SocketAddr::new(peer_addr.ip(), 0)
    } else {
        declared
    };

    debug!("SOCKS5 UDP ASSOCIATE (key={})", assoc_key);

    // Create outbound socket in VPN namespace (current namespace after setns)
    let outbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let client_addr = Arc::new(Mutex::new(assoc_key));

    // Spawn per-association VPN-to-client relay
    let relay_task = tokio::spawn(relay_vpn_to_client(
        outbound.clone(),
        relay_socket,
        client_addr.clone(),
    ));

    associations
        .insert(
            assoc_key,
            UdpAssociation {
                outbound,
                client_addr: client_addr.clone(),
                abort_handle: relay_task.abort_handle(),
            },
        )
        .await;

    // Reply with the relay socket's address so the client knows where to send datagrams
    send_reply(&mut client, REP_SUCCESS, Some(relay_addr)).await?;

    // Keep the TCP control connection open -- association lifetime is tied to it
    let mut buf = [0u8; 1];
    loop {
        match client.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }

    // Cleanup: read the (possibly upgraded) key and remove the association
    let key = *client_addr.lock().unwrap();
    debug!("SOCKS5 UDP ASSOCIATE closed (key={})", key);
    associations.remove(&key).await;

    Ok(())
}

async fn send_reply(
    client: &mut TcpStream,
    rep: u8,
    bind_addr: Option<SocketAddr>,
) -> anyhow::Result<()> {
    let mut reply = vec![SOCKS_VERSION, rep, 0x00];
    match bind_addr {
        Some(SocketAddr::V4(addr)) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    client.write_all(&reply).await?;
    Ok(())
}

/// Long-lived inbound relay: receives SOCKS5 UDP datagrams from clients on the
/// host-namespace relay socket and forwards the payload to the VPN via the
/// per-association outbound socket.
pub async fn run_udp_relay(relay_socket: Arc<UdpSocket>, associations: Arc<UdpAssociations>) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client_src) = match relay_socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("UDP relay recv_from error: {}", e);
                continue;
            }
        };

        let data = &buf[..n];
        let Some((dst_addr, payload)) = parse_udp_header(data) else {
            debug!("UDP relay: malformed SOCKS5 UDP header from {}", client_src);
            continue;
        };

        let Some(outbound) = associations.lookup(&client_src).await else {
            debug!("UDP relay: no association for {}", client_src);
            continue;
        };

        if let Err(e) = outbound.send_to(payload, dst_addr).await {
            debug!("UDP relay forward to {} failed: {}", dst_addr, e);
        }
    }
}

/// Per-association relay: receives reply datagrams from the VPN outbound socket,
/// wraps them in a SOCKS5 UDP header, and sends them back to the client.
async fn relay_vpn_to_client(
    outbound: Arc<UdpSocket>,
    relay_socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<SocketAddr>>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, remote_addr) = match outbound.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(_) => break,
        };

        let addr = *client_addr.lock().unwrap();
        if addr.port() == 0 {
            // Client address not yet known (still sentinel), drop the reply
            continue;
        }

        let header = build_udp_header(remote_addr);
        let mut packet = header;
        packet.extend_from_slice(&buf[..n]);

        if let Err(e) = relay_socket.send_to(&packet, addr).await {
            debug!("UDP relay send_to client {} failed: {}", addr, e);
            break;
        }
    }
}

/// Parse a SOCKS5 UDP request header, returning (destination, payload).
///
/// ```text
/// +------+------+------+----------+----------+----------+
/// | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// |  2   |  1   |  1   | Variable |    2     | Variable |
/// +------+------+------+----------+----------+----------+
/// ```
fn parse_udp_header(data: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    // RSV must be 0x0000
    if data[0] != 0 || data[1] != 0 {
        return None;
    }
    // FRAG != 0 means fragmented -- not supported
    if data[2] != 0 {
        return None;
    }

    let atyp = data[3];
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Some((SocketAddr::from((ip, port)), &data[10..]))
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            Some((SocketAddr::from((ip, port)), &data[22..]))
        }
        _ => None,
    }
}

/// Build a SOCKS5 UDP response header for a reply from the given remote address.
fn build_udp_header(addr: SocketAddr) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00]; // RSV(2) + FRAG(1)
    match addr {
        SocketAddr::V4(v4) => {
            header.push(ATYP_IPV4);
            header.extend_from_slice(&v4.ip().octets());
            header.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            header.push(ATYP_IPV6);
            header.extend_from_slice(&v6.ip().octets());
            header.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    header
}

/// Build a SOCKS5 CONNECT request for a given IPv4 address and port.
#[cfg(test)]
fn build_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut req = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());
    req
}

/// Build a SOCKS5 CONNECT request for a domain name and port.
#[cfg(test)]
fn build_connect_domain(domain: &[u8], port: u16) -> Vec<u8> {
    let mut req = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&port.to_be_bytes());
    req
}

/// Build a SOCKS5 UDP ASSOCIATE request for a given IPv4 address and port.
#[cfg(test)]
fn build_udp_associate_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut req = vec![SOCKS_VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// TCP echo server on a random port. Returns the port.
    async fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// UDP echo server on a random port. Returns the port.
    async fn udp_echo_server() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, addr) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let _ = socket.send_to(&buf[..n], addr).await;
            }
        });
        port
    }

    /// Spin up SOCKS5 infrastructure for testing: relay socket, associations, relay task.
    /// Returns (proxy_listener, associations, relay_socket, relay_addr).
    async fn setup_socks5() -> (
        TcpListener,
        Arc<UdpAssociations>,
        Arc<UdpSocket>,
        SocketAddr,
    ) {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let associations = Arc::new(UdpAssociations::new());

        // Spawn the inbound relay
        tokio::spawn(run_udp_relay(relay_socket.clone(), associations.clone()));

        (proxy_listener, associations, relay_socket, relay_addr)
    }

    /// Accept one SOCKS5 connection and handle it with UDP relay support.
    fn spawn_socks5_handler(
        proxy_listener: TcpListener,
        associations: Arc<UdpAssociations>,
        relay_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    ) {
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_socks5(
                stream,
                associations,
                Some((relay_socket, relay_addr)),
            )
            .await;
        });
    }

    /// Perform the SOCKS5 no-auth greeting handshake on a client stream.
    async fn socks5_greet(client: &mut TcpStream) {
        client.write_all(&[SOCKS_VERSION, 0x01, AUTH_NONE]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [SOCKS_VERSION, AUTH_NONE]);
    }

    /// Read the SOCKS5 reply and return the REP field.
    /// Handles both IPv4 (10 bytes) and IPv6 (22 bytes) replies.
    async fn socks5_read_reply(client: &mut TcpStream) -> (u8, SocketAddr) {
        let mut head = [0u8; 4];
        client.read_exact(&mut head).await.unwrap();
        let rep = head[1];
        let atyp = head[3];
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                client.read_exact(&mut buf).await.unwrap();
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                (rep, SocketAddr::from((ip, port)))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                client.read_exact(&mut buf).await.unwrap();
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[..16]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                (rep, SocketAddr::from((ip, port)))
            }
            _ => panic!("unexpected ATYP in reply: {}", atyp),
        }
    }

    #[tokio::test]
    async fn test_socks5_connect_ipv4() {
        let echo_port = echo_server().await;

        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations, relay_socket, relay_addr);

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut client).await;

        let request = build_connect_ipv4([127, 0, 0, 1], echo_port);
        client.write_all(&request).await.unwrap();
        let (rep, _) = socks5_read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);

        client.write_all(b"hello socks5").await.unwrap();
        let mut buf = [0u8; 12];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello socks5");
    }

    #[tokio::test]
    async fn test_socks5_connect_domain() {
        let echo_port = echo_server().await;

        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations, relay_socket, relay_addr);

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut client).await;

        let request = build_connect_domain(b"localhost", echo_port);
        client.write_all(&request).await.unwrap();
        let (rep, _) = socks5_read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);

        client.write_all(b"domain works").await.unwrap();
        let mut buf = [0u8; 12];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"domain works");
    }

    #[tokio::test]
    async fn test_socks5_connect_unreachable() {
        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations, relay_socket, relay_addr);

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut client).await;

        let request = build_connect_ipv4([127, 0, 0, 1], 1);
        client.write_all(&request).await.unwrap();
        let (rep, _) = socks5_read_reply(&mut client).await;
        assert_eq!(rep, REP_GENERAL_FAILURE);
    }

    #[tokio::test]
    async fn test_udp_associate_echo() {
        let udp_port = udp_echo_server().await;

        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations, relay_socket, relay_addr);

        let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut tcp).await;

        // Send UDP ASSOCIATE with 0.0.0.0:0 (unspecified)
        let request = build_udp_associate_ipv4([0, 0, 0, 0], 0);
        tcp.write_all(&request).await.unwrap();

        let (rep, bnd_addr) = socks5_read_reply(&mut tcp).await;
        assert_eq!(rep, REP_SUCCESS);
        assert_ne!(bnd_addr.port(), 0, "relay port must not be zero");

        // Send a SOCKS5 UDP datagram through the relay to the echo server
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut datagram = build_udp_header(SocketAddr::from(([127, 0, 0, 1], udp_port)));
        datagram.extend_from_slice(b"hello udp");

        client_udp.send_to(&datagram, bnd_addr).await.unwrap();

        // Read the echoed reply (wrapped in SOCKS5 UDP header)
        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_udp.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for UDP reply")
        .unwrap();

        let (src_addr, payload) = parse_udp_header(&buf[..n]).expect("bad UDP reply header");
        assert_eq!(src_addr.port(), udp_port);
        assert_eq!(payload, b"hello udp");
    }

    #[tokio::test]
    async fn test_udp_associate_cleanup() {
        let udp_port = udp_echo_server().await;

        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations.clone(), relay_socket, relay_addr);

        let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut tcp).await;

        let request = build_udp_associate_ipv4([0, 0, 0, 0], 0);
        tcp.write_all(&request).await.unwrap();

        let (rep, bnd_addr) = socks5_read_reply(&mut tcp).await;
        assert_eq!(rep, REP_SUCCESS);

        // Send one datagram to establish the association
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = build_udp_header(SocketAddr::from(([127, 0, 0, 1], udp_port)));
        datagram.extend_from_slice(b"ping");
        client_udp.send_to(&datagram, bnd_addr).await.unwrap();

        // Wait for echo reply to confirm association is active
        let mut buf = vec![0u8; 65535];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_udp.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for initial reply");

        // Close the TCP control connection
        drop(tcp);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify the associations map is empty
        let map = associations.inner.read().await;
        assert!(map.is_empty(), "associations should be cleaned up after TCP close");
    }

    #[tokio::test]
    async fn test_udp_associate_unreachable() {
        // UDP to unreachable destination should silently drop (no error to client)
        let (proxy_listener, associations, relay_socket, relay_addr) = setup_socks5().await;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        spawn_socks5_handler(proxy_listener, associations, relay_socket, relay_addr);

        let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
        socks5_greet(&mut tcp).await;

        let request = build_udp_associate_ipv4([0, 0, 0, 0], 0);
        tcp.write_all(&request).await.unwrap();

        let (rep, bnd_addr) = socks5_read_reply(&mut tcp).await;
        assert_eq!(rep, REP_SUCCESS);

        // Send datagram to a port that nothing is listening on
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = build_udp_header(SocketAddr::from(([127, 0, 0, 1], 1)));
        datagram.extend_from_slice(b"into the void");
        client_udp.send_to(&datagram, bnd_addr).await.unwrap();

        // No reply expected -- timeout is the success condition
        let mut buf = vec![0u8; 65535];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client_udp.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "should timeout with no reply");
    }
}

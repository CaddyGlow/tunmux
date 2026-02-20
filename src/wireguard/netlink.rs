//! WireGuard Generic Netlink interface (Linux kernel backend only).
//!
//! Implements the three operations previously done via the `wg` binary:
//! - `wg_set_device`  — configure private key + peer (replaces `wg set`)
//! - `wg_set_psk`     — set preshared key on existing peer
//! - `wg_get_uapi`    — read device state in UAPI text format

use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::OwnedFd;

use nix::sys::socket::{recv, send, socket, AddressFamily, MsgFlags, SockFlag, SockType};

use crate::error::{AppError, Result};

// ---------------------------------------------------------------------------
// WireGuard Generic Netlink constants (linux/wireguard.h)
// ---------------------------------------------------------------------------

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;

const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;

const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

// ---------------------------------------------------------------------------
// Generic Netlink control constants (linux/genetlink.h)
// ---------------------------------------------------------------------------

const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// ---------------------------------------------------------------------------
// Netlink flags / types
// ---------------------------------------------------------------------------

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_F_NESTED: u16 = 0x8000;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// ---------------------------------------------------------------------------
// Message builder
// ---------------------------------------------------------------------------

struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    /// Create a new netlink message with nlmsghdr.
    fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        // nlmsghdr: len(u32), type(u16), flags(u16), seq(u32), pid(u32)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len placeholder
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid = 0 (kernel fills it)
        Self { buf }
    }

    /// Append genlmsghdr.
    fn add_genl(&mut self, cmd: u8, version: u8) {
        self.buf.push(cmd);
        self.buf.push(version);
        self.buf.extend_from_slice(&[0u8; 2]); // reserved
    }

    /// Append a raw nlattr.
    fn add_attr(&mut self, ty: u16, data: &[u8]) {
        let nla_len = 4 + data.len(); // header (4 bytes) + data
        self.buf
            .extend_from_slice(&(nla_len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        // Pad to 4-byte alignment
        let pad = (4 - (data.len() % 4)) % 4;
        self.buf.extend(std::iter::repeat_n(0u8, pad));
    }

    fn add_attr_str(&mut self, ty: u16, s: &str) {
        // NLA strings are NUL-terminated
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.add_attr(ty, &data);
    }

    fn add_attr_u16(&mut self, ty: u16, v: u16) {
        self.add_attr(ty, &v.to_ne_bytes());
    }

    fn add_attr_u32(&mut self, ty: u16, v: u32) {
        self.add_attr(ty, &v.to_ne_bytes());
    }

    /// Begin a nested attribute; returns position of the length field for later patching.
    fn attr_start(&mut self, ty: u16) -> usize {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // len placeholder
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        pos
    }

    /// Finish a nested attribute started at `pos`.
    fn attr_end(&mut self, pos: usize) {
        let len = (self.buf.len() - pos) as u16;
        self.buf[pos..pos + 2].copy_from_slice(&len.to_ne_bytes());
        // Nested attrs are already 4-aligned by inner attrs; no extra pad needed
    }

    /// Fill in the nlmsghdr length and return the buffer.
    fn finalize(&mut self) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        &self.buf
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse a flat sequence of nlattrs from `data`.
/// Strips NLA_F_NESTED from the type field and advances by aligned lengths.
fn parse_attrs(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let nla_len =
            u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        if nla_len < 4 || offset + nla_len > data.len() {
            break;
        }
        let nla_type =
            u16::from_ne_bytes([data[offset + 2], data[offset + 3]]) & !NLA_F_NESTED;
        let payload = &data[offset + 4..offset + nla_len];
        out.push((nla_type, payload));
        // Advance by aligned length
        let aligned = (nla_len + 3) & !3;
        offset += aligned;
    }
    out
}

/// Encode "host:port" as a sockaddr_in or sockaddr_in6 byte sequence.
fn parse_endpoint(s: &str) -> Result<Vec<u8>> {
    let addr: SocketAddr = s
        .parse()
        .map_err(|e| AppError::WireGuard(format!("invalid endpoint '{}': {}", s, e)))?;
    Ok(sockaddr_bytes(&addr))
}

fn sockaddr_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut b = vec![0u8; 16];
            // sa_family (u16 LE)
            b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            // sin_port (u16 BE)
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            // sin_addr (4 bytes)
            b[4..8].copy_from_slice(&a.ip().octets());
            // padding zeros (8 bytes already zero)
            b
        }
        SocketAddr::V6(a) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            // flowinfo (u32 BE) — zero
            b[8..24].copy_from_slice(&a.ip().octets());
            // scope_id (u32 LE) — zero
            b
        }
    }
}

/// Parse a single CIDR string: returns (AF, ip_bytes, prefix_len).
fn parse_cidr(s: &str) -> Result<(u16, Vec<u8>, u8)> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| AppError::WireGuard(format!("invalid CIDR '{}': missing '/'", s)))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| AppError::WireGuard(format!("invalid prefix in '{}'", s)))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| AppError::WireGuard(format!("invalid IP in '{}': {}", s, e)))?;
    match ip {
        IpAddr::V4(a) => Ok((AF_INET, a.octets().to_vec(), prefix)),
        IpAddr::V6(a) => Ok((AF_INET6, a.octets().to_vec(), prefix)),
    }
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, byte| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", byte);
        s
    })
}

// ---------------------------------------------------------------------------
// Netlink socket I/O
// ---------------------------------------------------------------------------

fn open_netlink() -> Result<OwnedFd> {
    // NETLINK_GENERIC = 16
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        Some(nix::sys::socket::SockProtocol::NetlinkGeneric),
    )
    .map_err(|e| AppError::WireGuard(format!("netlink socket: {}", e)))?;
    Ok(fd)
}

fn nl_send(fd: &OwnedFd, data: &[u8]) -> Result<()> {
    send(fd.as_raw_fd(), data, MsgFlags::empty())
        .map_err(|e| AppError::WireGuard(format!("netlink send: {}", e)))?;
    Ok(())
}

fn nl_recv(fd: &OwnedFd, buf: &mut [u8]) -> Result<usize> {
    let n = recv(fd.as_raw_fd(), buf, MsgFlags::empty())
        .map_err(|e| AppError::WireGuard(format!("netlink recv: {}", e)))?;
    Ok(n)
}

/// Resolve the Generic Netlink family ID for "wireguard".
fn get_wg_family_id(fd: &OwnedFd, seq: u32) -> Result<u16> {
    let mut msg = NlMsg::new(GENL_ID_CTRL, NLM_F_REQUEST, seq);
    msg.add_genl(CTRL_CMD_GETFAMILY, 1);
    msg.add_attr_str(CTRL_ATTR_FAMILY_NAME, "wireguard");
    nl_send(fd, msg.finalize())?;

    let mut buf = vec![0u8; 4096];
    let n = nl_recv(fd, &mut buf)?;
    let data = &buf[..n];

    // Walk messages in the response
    let mut offset = 0usize;
    while offset + 16 <= data.len() {
        let msg_len = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let msg_type = u16::from_ne_bytes(data[offset + 4..offset + 6].try_into().unwrap());

        if msg_len < 16 || offset + msg_len > data.len() {
            break;
        }

        if msg_type == NLMSG_ERROR {
            let errno = i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().unwrap());
            if errno != 0 {
                return Err(AppError::WireGuard(format!(
                    "CTRL_CMD_GETFAMILY failed: errno {}",
                    errno
                )));
            }
            break;
        }

        // genlmsghdr is 4 bytes after nlmsghdr (16 bytes) = offset + 20 for attrs
        let attrs_start = offset + 20;
        let attrs_end = offset + msg_len;
        if attrs_start <= attrs_end {
            for (ty, val) in parse_attrs(&data[attrs_start..attrs_end]) {
                if ty == CTRL_ATTR_FAMILY_ID && val.len() >= 2 {
                    let family_id = u16::from_ne_bytes([val[0], val[1]]);
                    return Ok(family_id);
                }
            }
        }

        offset += (msg_len + 3) & !3;
    }

    Err(AppError::WireGuard(
        "wireguard genl family not found".into(),
    ))
}

// ---------------------------------------------------------------------------
// Base64 decode helpers
// ---------------------------------------------------------------------------

fn decode_key_b64(b64: &str, label: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AppError::WireGuard(format!("bad {} key base64: {}", label, e)))?;
    bytes
        .try_into()
        .map_err(|_| AppError::WireGuard(format!("{} key must be 32 bytes", label)))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

use std::os::unix::io::AsRawFd;

/// Configure a WireGuard device: private key + a single peer.
///
/// `allowed_ips` is a comma-separated list of CIDRs.
pub fn wg_set_device(
    interface: &str,
    private_key_b64: &str,
    peer_pubkey_b64: &str,
    endpoint: &str,
    allowed_ips: &str,
) -> Result<()> {
    let priv_key = decode_key_b64(private_key_b64, "private")?;
    let pub_key = decode_key_b64(peer_pubkey_b64, "peer public")?;
    let endpoint_bytes = parse_endpoint(endpoint)?;

    let fd = open_netlink()?;
    let seq: u32 = 1;
    let family_id = get_wg_family_id(&fd, seq)?;

    let mut msg = NlMsg::new(family_id, NLM_F_REQUEST | NLM_F_ACK, seq + 1);
    msg.add_genl(WG_CMD_SET_DEVICE, 1);
    msg.add_attr_str(WGDEVICE_A_IFNAME, interface);
    msg.add_attr(WGDEVICE_A_PRIVATE_KEY, &priv_key);
    msg.add_attr_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);

    let peers_pos = msg.attr_start(WGDEVICE_A_PEERS);
    let peer_pos = msg.attr_start(0); // peer index 0 (nested in peers)

    msg.add_attr(WGPEER_A_PUBLIC_KEY, &pub_key);
    msg.add_attr_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
    msg.add_attr(WGPEER_A_ENDPOINT, &endpoint_bytes);

    let allowedips_pos = msg.attr_start(WGPEER_A_ALLOWEDIPS);
    for (i, cidr) in allowed_ips.split(',').enumerate() {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        let (af, ip_bytes, prefix) = parse_cidr(cidr)?;
        let aip_pos = msg.attr_start(i as u16); // index within allowedips
        msg.add_attr_u16(WGALLOWEDIP_A_FAMILY, af);
        msg.add_attr(WGALLOWEDIP_A_IPADDR, &ip_bytes);
        msg.add_attr(WGALLOWEDIP_A_CIDR_MASK, &[prefix]);
        msg.attr_end(aip_pos);
    }
    msg.attr_end(allowedips_pos);

    msg.attr_end(peer_pos);
    msg.attr_end(peers_pos);

    nl_send(&fd, msg.finalize())?;
    wait_for_ack(&fd)
}

/// Set the preshared key for an existing peer without replacing peers or allowed IPs.
pub fn wg_set_psk(interface: &str, peer_pubkey_b64: &str, psk_b64: &str) -> Result<()> {
    let pub_key = decode_key_b64(peer_pubkey_b64, "peer public")?;
    let psk = decode_key_b64(psk_b64, "preshared")?;

    let fd = open_netlink()?;
    let seq: u32 = 1;
    let family_id = get_wg_family_id(&fd, seq)?;

    let mut msg = NlMsg::new(family_id, NLM_F_REQUEST | NLM_F_ACK, seq + 1);
    msg.add_genl(WG_CMD_SET_DEVICE, 1);
    msg.add_attr_str(WGDEVICE_A_IFNAME, interface);

    let peers_pos = msg.attr_start(WGDEVICE_A_PEERS);
    let peer_pos = msg.attr_start(0);
    msg.add_attr(WGPEER_A_PUBLIC_KEY, &pub_key);
    msg.add_attr(WGPEER_A_PRESHARED_KEY, &psk);
    msg.attr_end(peer_pos);
    msg.attr_end(peers_pos);

    nl_send(&fd, msg.finalize())?;
    wait_for_ack(&fd)
}

/// Read WireGuard device state and emit UAPI-compatible text.
///
/// The returned string is suitable for parsing by `format_wg_show()` in
/// `privileged.rs` (same format as the UAPI Unix socket protocol).
pub fn wg_get_uapi(interface: &str) -> Result<String> {
    let fd = open_netlink()?;
    let seq: u32 = 1;
    let family_id = get_wg_family_id(&fd, seq)?;

    let mut msg = NlMsg::new(family_id, NLM_F_REQUEST | NLM_F_DUMP, seq + 1);
    msg.add_genl(WG_CMD_GET_DEVICE, 1);
    msg.add_attr_str(WGDEVICE_A_IFNAME, interface);
    nl_send(&fd, msg.finalize())?;

    // Collect all multipart message payloads until NLMSG_DONE.
    let mut device_attrs: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 65536];
    'outer: loop {
        let n = nl_recv(&fd, &mut buf)?;
        let data = &buf[..n];
        let mut offset = 0usize;
        while offset + 16 <= data.len() {
            let msg_len =
                u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            let msg_type =
                u16::from_ne_bytes(data[offset + 4..offset + 6].try_into().unwrap());

            if msg_len < 16 || offset + msg_len > data.len() {
                break;
            }

            match msg_type {
                NLMSG_DONE => break 'outer,
                NLMSG_ERROR => {
                    let errno =
                        i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().unwrap());
                    if errno != 0 {
                        return Err(AppError::WireGuard(format!(
                            "WG_CMD_GET_DEVICE failed: errno {}",
                            errno
                        )));
                    }
                    break 'outer;
                }
                _ => {
                    // genlmsghdr (4 bytes) after nlmsghdr (16 bytes) = attrs at offset+20
                    let attrs_start = offset + 20;
                    let attrs_end = offset + msg_len;
                    if attrs_start < attrs_end {
                        device_attrs.extend_from_slice(&data[attrs_start..attrs_end]);
                    }
                }
            }

            offset += (msg_len + 3) & !3;
        }
    }

    build_uapi_text(&device_attrs)
}

// ---------------------------------------------------------------------------
// Wait for ACK from the kernel
// ---------------------------------------------------------------------------

fn wait_for_ack(fd: &OwnedFd) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = nl_recv(fd, &mut buf)?;
    let data = &buf[..n];

    let mut offset = 0usize;
    while offset + 16 <= data.len() {
        let msg_len = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let msg_type = u16::from_ne_bytes(data[offset + 4..offset + 6].try_into().unwrap());

        if msg_len < 16 || offset + msg_len > data.len() {
            break;
        }

        if msg_type == NLMSG_ERROR {
            if offset + 20 > data.len() {
                return Err(AppError::WireGuard("truncated NLMSG_ERROR".into()));
            }
            let errno = i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().unwrap());
            if errno != 0 {
                return Err(AppError::WireGuard(format!(
                    "WireGuard netlink set failed: errno {}",
                    errno
                )));
            }
            return Ok(());
        }

        offset += (msg_len + 3) & !3;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Build UAPI text from parsed device netlink attrs
// ---------------------------------------------------------------------------

fn build_uapi_text(device_attrs: &[u8]) -> Result<String> {
    let mut out = String::new();

    for (ty, val) in parse_attrs(device_attrs) {
        match ty {
            WGDEVICE_A_PRIVATE_KEY if val.len() == 32 => {
                out.push_str("private_key=");
                out.push_str(&bytes_to_hex(val));
                out.push('\n');
            }
            WGDEVICE_A_PUBLIC_KEY if val.len() == 32 => {
                // Not emitted — format_wg_show derives public key from private key
            }
            WGDEVICE_A_LISTEN_PORT if val.len() >= 2 => {
                let port = u16::from_ne_bytes([val[0], val[1]]);
                out.push_str(&format!("listen_port={}\n", port));
            }
            WGDEVICE_A_PEERS => {
                // Parse peer list (nested attrs, each peer is a nested attr)
                for (_, peer_val) in parse_attrs(val) {
                    out.push_str(&build_peer_uapi(peer_val));
                }
            }
            _ => {}
        }
    }

    out.push_str("errno=0\n");
    Ok(out)
}

fn build_peer_uapi(peer_data: &[u8]) -> String {
    let mut out = String::new();

    for (ty, val) in parse_attrs(peer_data) {
        match ty {
            WGPEER_A_PUBLIC_KEY if val.len() == 32 => {
                out.push_str("public_key=");
                out.push_str(&bytes_to_hex(val));
                out.push('\n');
            }
            WGPEER_A_ENDPOINT => {
                if let Some(s) = endpoint_bytes_to_str(val) {
                    out.push_str(&format!("endpoint={}\n", s));
                }
            }
            WGPEER_A_ALLOWEDIPS => {
                for (_, aip_val) in parse_attrs(val) {
                    if let Some(cidr) = parse_allowed_ip_attr(aip_val) {
                        out.push_str(&format!("allowed_ip={}\n", cidr));
                    }
                }
            }
            WGPEER_A_LAST_HANDSHAKE_TIME if val.len() >= 16 => {
                let sec = i64::from_ne_bytes(val[0..8].try_into().unwrap());
                let nsec = i64::from_ne_bytes(val[8..16].try_into().unwrap());
                out.push_str(&format!("last_handshake_time_sec={}\n", sec));
                out.push_str(&format!("last_handshake_time_nsec={}\n", nsec));
            }
            WGPEER_A_RX_BYTES if val.len() >= 8 => {
                let v = u64::from_ne_bytes(val[0..8].try_into().unwrap());
                out.push_str(&format!("rx_bytes={}\n", v));
            }
            WGPEER_A_TX_BYTES if val.len() >= 8 => {
                let v = u64::from_ne_bytes(val[0..8].try_into().unwrap());
                out.push_str(&format!("tx_bytes={}\n", v));
            }
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL if val.len() >= 2 => {
                let v = u16::from_ne_bytes([val[0], val[1]]);
                out.push_str(&format!("persistent_keepalive_interval={}\n", v));
            }
            _ => {}
        }
    }

    out
}

fn endpoint_bytes_to_str(b: &[u8]) -> Option<String> {
    if b.len() >= 16 {
        let family = u16::from_ne_bytes([b[0], b[1]]);
        if family == AF_INET && b.len() >= 8 {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            return Some(format!("{}:{}", ip, port));
        }
        if family == AF_INET6 && b.len() >= 28 {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            return Some(format!("[{}]:{}", ip, port));
        }
    }
    None
}

fn parse_allowed_ip_attr(data: &[u8]) -> Option<String> {
    let mut family: Option<u16> = None;
    let mut ip_bytes: Option<Vec<u8>> = None;
    let mut cidr: Option<u8> = None;

    for (ty, val) in parse_attrs(data) {
        match ty {
            WGALLOWEDIP_A_FAMILY if val.len() >= 2 => {
                family = Some(u16::from_ne_bytes([val[0], val[1]]));
            }
            WGALLOWEDIP_A_IPADDR => {
                ip_bytes = Some(val.to_vec());
            }
            WGALLOWEDIP_A_CIDR_MASK if !val.is_empty() => {
                cidr = Some(val[0]);
            }
            _ => {}
        }
    }

    let (family, ip_bytes, prefix) = (family?, ip_bytes?, cidr?);
    match family {
        f if f == AF_INET && ip_bytes.len() == 4 => {
            let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            Some(format!("{}/{}", ip, prefix))
        }
        f if f == AF_INET6 && ip_bytes.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip_bytes);
            let ip = std::net::Ipv6Addr::from(octets);
            Some(format!("{}/{}", ip, prefix))
        }
        _ => None,
    }
}

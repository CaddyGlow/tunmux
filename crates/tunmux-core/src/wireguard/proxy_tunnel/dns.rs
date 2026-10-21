use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use smoltcp::wire::IpAddress;
use tracing::warn;

use super::queue::DnsUdpRequest;
use super::{
    LocalProxyConfig, TunnelDnsResolver, DNS_CACHE, DNS_CACHE_TTL, DNS_QUERY_ID,
    DNS_TUNNEL_QUERY_TTL,
};

pub(crate) fn parse_dns_servers(cfg: &LocalProxyConfig) -> Vec<IpAddr> {
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

pub(crate) fn normalize_dns_server(value: &str) -> Option<&str> {
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
pub(crate) async fn resolve_ipv4_preferred(
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

pub(crate) async fn resolve_with_tunnel_dns(
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

pub(crate) async fn resolve_host_via_tunnel_dns(
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

pub(crate) fn dedup_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut unique = Vec::with_capacity(ips.len());
    for ip in ips {
        if seen.insert(ip) {
            unique.push(ip);
        }
    }
    unique
}

pub(crate) async fn dns_query_over_tunnel(
    resolver: &TunnelDnsResolver,
    dns_server: IpAddr,
    host: &str,
    qtype: u16,
) -> anyhow::Result<Vec<IpAddr>> {
    let query_id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_query(host, qtype, query_id)?;
    let source_ip = dns_source_ip_for_server(resolver, dns_server)
        .ok_or_else(|| anyhow!("no matching local source IP for DNS server {}", dns_server))?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

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

pub(crate) fn dns_source_ip_for_server(
    resolver: &TunnelDnsResolver,
    dns_server: IpAddr,
) -> Option<IpAddress> {
    match dns_server {
        IpAddr::V4(_) => Some(IpAddress::Ipv4(resolver.virtual_ipv4)),
        IpAddr::V6(_) => resolver.virtual_ipv6.map(IpAddress::Ipv6),
    }
}

pub(crate) fn build_dns_query(host: &str, qtype: u16, query_id: u16) -> anyhow::Result<Vec<u8>> {
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

pub(crate) fn parse_dns_response_ips(
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

pub(crate) fn skip_dns_name(packet: &[u8], mut offset: usize) -> anyhow::Result<usize> {
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

pub(crate) async fn resolve_with_system_dns(
    host: &str,
    port: u16,
) -> anyhow::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("DNS lookup failed: {}", host))?
        .collect())
}

pub(crate) fn select_ipv4_preferred(
    mut addrs: impl Iterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
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

pub(crate) fn dns_cache_get(key: &str) -> Option<Vec<SocketAddr>> {
    let map = DNS_CACHE.read().ok()?;
    let (inserted_at, addrs) = map.get(key)?;
    if inserted_at.elapsed() > DNS_CACHE_TTL {
        return None;
    }
    Some(addrs.clone())
}

pub(crate) fn dns_cache_put(key: String, addrs: Vec<SocketAddr>) {
    if let Ok(mut map) = DNS_CACHE.write() {
        map.retain(|_, (inserted_at, _)| inserted_at.elapsed() <= DNS_CACHE_TTL);
        map.insert(key, (Instant::now(), addrs));
    }
}

pub(crate) fn ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

#![cfg(all(feature = "proxy", target_os = "linux"))]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tracing::warn;

pub type DnsResolver = Arc<TokioAsyncResolver>;

pub fn build_dns_resolver_from_resolv_conf(content: &str) -> Option<DnsResolver> {
    let mut dns_ips: Vec<IpAddr> = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        if !matches!(parts.next(), Some("nameserver")) {
            continue;
        }

        let Some(raw_server) = parts.next() else {
            continue;
        };
        let Some(server) = normalize_dns_server(raw_server) else {
            continue;
        };

        match server.parse::<IpAddr>() {
            Ok(ip) => dns_ips.push(ip),
            Err(error) => {
                warn!(
                    dns_server = server,
                    error = %error,
                    "proxy_dns_server_parse_failed"
                );
            }
        }
    }

    if dns_ips.is_empty() {
        return None;
    }

    let nameservers = NameServerConfigGroup::from_ips_clear(&dns_ips, 53, true);
    let config = ResolverConfig::from_parts(None, vec![], nameservers);
    Some(Arc::new(TokioAsyncResolver::tokio(
        config,
        ResolverOpts::default(),
    )))
}

pub async fn resolve_host_port(
    host: &str,
    port: u16,
    dns_resolver: Option<&DnsResolver>,
) -> anyhow::Result<SocketAddr> {
    let normalized_host = host.trim().trim_matches('[').trim_matches(']');
    if normalized_host.is_empty() {
        anyhow::bail!("empty host");
    }

    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs: Vec<SocketAddr> = if let Some(resolver) = dns_resolver {
        resolver
            .lookup_ip(normalized_host)
            .await
            .with_context(|| format!("proxy DNS lookup failed: {}", normalized_host))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    } else {
        tokio::net::lookup_host(format!("{}:{}", normalized_host, port))
            .await
            .with_context(|| format!("DNS lookup failed: {}", normalized_host))?
            .collect()
    };

    select_ipv4_preferred(addrs.into_iter())
        .ok_or_else(|| anyhow!("DNS returned no addresses for {}", normalized_host))
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

fn select_ipv4_preferred(mut addrs: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut first = None;
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

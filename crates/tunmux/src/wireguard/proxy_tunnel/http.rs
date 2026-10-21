use std::sync::Arc;

use anyhow::anyhow;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

use super::bridge::bridge;
use super::dns::{ip_to_smoltcp, resolve_ipv4_preferred};
use super::queue::{ByteQueue, ConnRequest};
use super::{TunnelDnsResolver, CLIENT_CHANNEL_CAP};

pub(crate) async fn http_connect_serve(
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
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();

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
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();

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

pub(crate) fn parse_http_url(url: &str) -> anyhow::Result<(String, u16, String)> {
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

pub(crate) async fn read_crlf_line(stream: &mut TcpStream) -> anyhow::Result<String> {
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

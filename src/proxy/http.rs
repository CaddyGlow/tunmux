#![cfg(all(feature = "proxy", target_os = "linux"))]

use anyhow::Context;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::proxy::dns::{resolve_host_port, DnsResolver};

struct UpstreamConnection {
    addr: String,
    stream: BufReader<TcpStream>,
}

#[derive(Clone, Copy, Debug)]
enum BodyMode {
    None,
    ContentLength(usize),
    Chunked,
}

struct RequestMeta {
    body: BodyMode,
    connection_close: bool,
}

struct ResponseMeta {
    body: BodyMode,
    connection_close: bool,
    close_delimited: bool,
}

pub async fn handle_http(
    client: TcpStream,
    dns_resolver: Option<DnsResolver>,
    access_log: bool,
) -> anyhow::Result<()> {
    let peer_addr = client.peer_addr().ok().map(|addr| addr.to_string());
    let mut buf_client = BufReader::new(client);
    let mut upstream: Option<UpstreamConnection> = None;

    loop {
        let mut request_line = String::new();
        let read = buf_client.read_line(&mut request_line).await?;
        if read == 0 {
            return Ok(());
        }

        let request_line = request_line.trim_end().to_string();
        if request_line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            anyhow::bail!("malformed HTTP request line");
        }
        let method = parts[0];
        let target = parts[1];
        let version = parts[2];

        if access_log {
            info!(
                peer_addr = ?peer_addr,
                method = ?method,
                target = ?target,
                "proxy_http_access"
            );
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            return handle_connect(buf_client, target, dns_resolver).await;
        }

        let keep_client = handle_plain_request(
            &mut buf_client,
            &mut upstream,
            method,
            target,
            version,
            dns_resolver.as_ref(),
        )
        .await?;
        if !keep_client {
            return Ok(());
        }
    }
}

/// HTTP CONNECT tunneling (e.g., for HTTPS)
async fn handle_connect(
    mut buf_client: BufReader<TcpStream>,
    target: &str,
    dns_resolver: Option<DnsResolver>,
) -> anyhow::Result<()> {
    debug!(target = ?target, "http_connect_start");

    // Read and discard remaining headers
    loop {
        let mut line = String::new();
        let read = buf_client.read_line(&mut line).await?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
    }

    let (connect_host, connect_port) = split_host_port(target, 443);
    let resolved =
        match resolve_host_port(connect_host.as_str(), connect_port, dns_resolver.as_ref()).await {
            Ok(addr) => addr,
            Err(error) => {
                warn!(
                    target = ?target,
                    error = ?error.to_string(),
                    "http_connect_dns_resolve_failed"
                );
                buf_client
                    .get_mut()
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };

    match TcpStream::connect(resolved).await {
        Ok(mut remote) => {
            buf_client
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            let mut client = buf_client.into_inner();
            let result = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
            if let Err(e) = result {
                debug!(error = ?e.to_string(), "http_connect_tunnel_closed");
            }
        }
        Err(e) => {
            warn!(
                target = ?target,
                resolved = ?resolved.to_string(),
                error = ?e.to_string(),
                "http_connect_failed"
            );
            buf_client
                .get_mut()
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
        }
    }

    Ok(())
}

async fn handle_plain_request(
    client: &mut BufReader<TcpStream>,
    upstream: &mut Option<UpstreamConnection>,
    method: &str,
    target: &str,
    version: &str,
    dns_resolver: Option<&DnsResolver>,
) -> anyhow::Result<bool> {
    debug!(method = ?method, target = ?target, "http_plain_start");

    let request_headers = read_headers(client).await?;
    let request_meta = parse_request_meta(&request_headers);
    let host_header = first_header_value(&request_headers, "host");

    let (mut host, path) = parse_absolute_uri(target)?;
    if host.is_empty() {
        host = host_header
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow::anyhow!("missing Host header"))?;
    }

    let default_port = default_port_for_target(target);
    let (connect_host, connect_port) = split_host_port(host.as_str(), default_port);
    let upstream_addr = format!("{}:{}", connect_host, connect_port);

    let mut has_host = false;
    let mut forwarded_headers = Vec::new();
    for header in &request_headers {
        let lower = header.to_ascii_lowercase();
        if lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authorization:")
            || lower.starts_with("connection:")
            || lower.starts_with("keep-alive:")
        {
            continue;
        }
        if lower.starts_with("host:") {
            has_host = true;
        }
        forwarded_headers.push(header.as_str());
    }

    let upstream_stream = ensure_upstream(
        upstream,
        &upstream_addr,
        connect_host.as_str(),
        connect_port,
        dns_resolver,
    )
    .await?;

    let request_line = format!("{} {} {}\r\n", method, path, version);
    upstream_stream
        .get_mut()
        .write_all(request_line.as_bytes())
        .await?;

    if !has_host {
        upstream_stream
            .get_mut()
            .write_all(format!("Host: {}\r\n", host).as_bytes())
            .await?;
    }

    for header in &forwarded_headers {
        upstream_stream
            .get_mut()
            .write_all(header.as_bytes())
            .await?;
    }

    if request_meta.connection_close {
        upstream_stream
            .get_mut()
            .write_all(b"Connection: close\r\n")
            .await?;
    } else {
        upstream_stream
            .get_mut()
            .write_all(b"Connection: keep-alive\r\n")
            .await?;
    }
    upstream_stream.get_mut().write_all(b"\r\n").await?;

    match request_meta.body {
        BodyMode::None => {}
        BodyMode::ContentLength(len) => {
            copy_exact_bytes(client, upstream_stream.get_mut(), len).await?;
        }
        BodyMode::Chunked => {
            copy_chunked_body(client, upstream_stream.get_mut()).await?;
        }
    }
    upstream_stream.get_mut().flush().await?;

    let response_meta = forward_response(upstream_stream, client, method).await?;

    if response_meta.connection_close || response_meta.close_delimited {
        *upstream = None;
    }

    if request_meta.connection_close {
        return Ok(false);
    }

    Ok(true)
}

async fn ensure_upstream<'a>(
    upstream: &'a mut Option<UpstreamConnection>,
    addr: &str,
    host: &str,
    port: u16,
    dns_resolver: Option<&DnsResolver>,
) -> anyhow::Result<&'a mut BufReader<TcpStream>> {
    let needs_new = match upstream {
        Some(conn) => conn.addr != addr,
        None => true,
    };

    if needs_new {
        let resolved = resolve_host_port(host, port, dns_resolver)
            .await
            .with_context(|| format!("resolve upstream {}:{}", host, port))?;
        let stream = TcpStream::connect(resolved)
            .await
            .with_context(|| format!("connect upstream {} (resolved from {})", resolved, addr))?;
        *upstream = Some(UpstreamConnection {
            addr: addr.to_string(),
            stream: BufReader::new(stream),
        });
    }

    upstream
        .as_mut()
        .map(|conn| &mut conn.stream)
        .ok_or_else(|| anyhow::anyhow!("upstream connection missing"))
}

async fn forward_response(
    upstream: &mut BufReader<TcpStream>,
    client: &mut BufReader<TcpStream>,
    request_method: &str,
) -> anyhow::Result<ResponseMeta> {
    let mut status_line = String::new();
    let read = upstream.read_line(&mut status_line).await?;
    if read == 0 {
        anyhow::bail!("upstream closed while reading response status line");
    }

    let status_code = parse_status_code(&status_line);
    let response_headers = read_headers(upstream).await?;
    let response_meta = parse_response_meta(status_code, request_method, &response_headers);

    client.get_mut().write_all(status_line.as_bytes()).await?;
    for header in &response_headers {
        client.get_mut().write_all(header.as_bytes()).await?;
    }
    client.get_mut().write_all(b"\r\n").await?;

    match response_meta.body {
        BodyMode::None => {}
        BodyMode::ContentLength(len) => {
            copy_exact_bytes(upstream, client.get_mut(), len).await?;
        }
        BodyMode::Chunked => {
            copy_chunked_body(upstream, client.get_mut()).await?;
        }
    }

    if response_meta.close_delimited {
        tokio::io::copy(upstream, client.get_mut()).await?;
    }

    client.get_mut().flush().await?;
    Ok(response_meta)
}

async fn read_headers<R>(reader: &mut R) -> anyhow::Result<Vec<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading headers");
        }
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }
    Ok(headers)
}

fn parse_request_meta(headers: &[String]) -> RequestMeta {
    let chunked = header_contains_token(headers, "transfer-encoding", "chunked");
    let content_length = parse_content_length(headers);
    let connection_close = header_contains_token(headers, "connection", "close")
        || header_contains_token(headers, "proxy-connection", "close");

    let body = if chunked {
        BodyMode::Chunked
    } else if let Some(len) = content_length {
        BodyMode::ContentLength(len)
    } else {
        BodyMode::None
    };

    RequestMeta {
        body,
        connection_close,
    }
}

fn parse_response_meta(status_code: u16, method: &str, headers: &[String]) -> ResponseMeta {
    let chunked = header_contains_token(headers, "transfer-encoding", "chunked");
    let content_length = parse_content_length(headers);
    let connection_close = header_contains_token(headers, "connection", "close");

    let no_body = method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304;

    let close_delimited = !no_body && !chunked && content_length.is_none();
    let body = if no_body {
        BodyMode::None
    } else if chunked {
        BodyMode::Chunked
    } else if let Some(len) = content_length {
        BodyMode::ContentLength(len)
    } else {
        BodyMode::None
    };

    ResponseMeta {
        body,
        connection_close,
        close_delimited,
    }
}

fn parse_content_length(headers: &[String]) -> Option<usize> {
    headers
        .iter()
        .find_map(|line| header_value(line, "content-length"))
        .and_then(|value| value.parse::<usize>().ok())
}

fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    let trimmed = target.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((host, after_bracket)) = rest.split_once(']') {
            if let Some(port) = after_bracket.strip_prefix(':').and_then(|v| v.parse().ok()) {
                return (host.to_string(), port);
            }
            return (host.to_string(), default_port);
        }
    }

    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        if host.contains(':') {
            return (trimmed.to_string(), default_port);
        }
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }

    (trimmed.to_string(), default_port)
}

fn header_contains_token(headers: &[String], header_name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter_map(|line| header_value(line, header_name))
        .flat_map(|value| value.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn first_header_value<'a>(headers: &'a [String], header_name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|line| header_value(line, header_name))
}

fn header_value<'a>(line: &'a str, header_name: &str) -> Option<&'a str> {
    let (name, value) = line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case(header_name) {
        return None;
    }
    Some(value.trim())
}

fn parse_status_code(status_line: &str) -> u16 {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

fn default_port_for_target(target: &str) -> u16 {
    if target.starts_with("https://") {
        443
    } else {
        80
    }
}

async fn copy_exact_bytes<R, W>(reader: &mut R, writer: &mut W, len: usize) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut limited = reader.take(len as u64);
    let copied = tokio::io::copy(&mut limited, writer).await?;
    if copied != len as u64 {
        anyhow::bail!("incomplete body forwarding: expected {len} bytes, copied {copied}");
    }
    Ok(())
}

async fn copy_chunked_body<R, W>(reader: &mut R, writer: &mut W) -> anyhow::Result<()>
where
    R: AsyncBufRead + AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut size_line = String::new();
        let read = reader.read_line(&mut size_line).await?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading chunk size");
        }

        writer.write_all(size_line.as_bytes()).await?;
        let size_token = size_line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .with_context(|| format!("invalid chunk size '{size_token}'"))?;

        if chunk_size == 0 {
            loop {
                let mut trailer_line = String::new();
                let trailer_read = reader.read_line(&mut trailer_line).await?;
                if trailer_read == 0 {
                    anyhow::bail!("unexpected EOF while reading chunk trailers");
                }
                writer.write_all(trailer_line.as_bytes()).await?;
                if trailer_line.trim().is_empty() {
                    break;
                }
            }
            break;
        }

        copy_exact_bytes(reader, writer, chunk_size).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        writer.write_all(&crlf).await?;
    }

    Ok(())
}

/// Parse an absolute URI (http://host/path) into (host, path).
pub(crate) fn parse_absolute_uri(uri: &str) -> anyhow::Result<(String, String)> {
    let without_scheme = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);

    let (host, path) = match without_scheme.find('/') {
        Some(pos) => (
            without_scheme[..pos].to_string(),
            without_scheme[pos..].to_string(),
        ),
        None => (without_scheme.to_string(), "/".to_string()),
    };

    Ok((host, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_absolute_uri_with_path() {
        let (host, path) = parse_absolute_uri("http://example.com/foo/bar").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(path, "/foo/bar");
    }

    #[test]
    fn test_parse_absolute_uri_with_port() {
        let (host, path) = parse_absolute_uri("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com:8080");
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_absolute_uri_no_path() {
        let (host, path) = parse_absolute_uri("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_absolute_uri_no_scheme() {
        let (host, path) = parse_absolute_uri("example.com/foo").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(path, "/foo");
    }

    /// TCP echo server. Returns the port.
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

    /// Minimal keep-alive HTTP server that returns a fixed response. Returns the port.
    async fn http_server(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut request_line = String::new();
                        let Ok(read) = reader.read_line(&mut request_line).await else {
                            break;
                        };
                        if read == 0 {
                            break;
                        }
                        if request_line.trim().is_empty() {
                            continue;
                        }

                        let mut content_length = 0usize;
                        loop {
                            let mut line = String::new();
                            let Ok(header_read) = reader.read_line(&mut line).await else {
                                return;
                            };
                            if header_read == 0 {
                                return;
                            }
                            if let Some(v) = header_value(&line, "content-length") {
                                content_length = v.parse::<usize>().unwrap_or(0);
                            }
                            if line.trim().is_empty() {
                                break;
                            }
                        }

                        if content_length > 0 {
                            let mut discard = vec![0u8; content_length];
                            if reader.read_exact(&mut discard).await.is_err() {
                                return;
                            }
                        }

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                            body.len(),
                            body,
                        );
                        if reader
                            .get_mut()
                            .write_all(response.as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if reader.get_mut().flush().await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    async fn read_http_response(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream);

        let mut status = String::new();
        let _ = reader.read_line(&mut status).await.unwrap();

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
            if let Some(v) = header_value(&line, "content-length") {
                content_length = v.parse::<usize>().unwrap_or(0);
            }
            headers.push(line);
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await.unwrap();
        }

        let mut out = String::new();
        out.push_str(&status);
        for header in headers {
            out.push_str(&header);
        }
        out.push_str("\r\n");
        out.push_str(&String::from_utf8_lossy(&body));
        out
    }

    #[tokio::test]
    async fn test_http_connect_tunnel() {
        let echo_port = echo_server().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_http(stream, None, false).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Send CONNECT request
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            echo_port, echo_port
        );
        client.write_all(request.as_bytes()).await.unwrap();

        // Read 200 response
        let mut resp_buf = vec![0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "expected 200, got: {}",
            resp
        );

        // Tunnel is established -- echo test
        client.write_all(b"tunnel data").await.unwrap();
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tunnel data");
    }

    #[tokio::test]
    async fn test_http_connect_unreachable() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_http(stream, None, false).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let request = "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        client.write_all(request.as_bytes()).await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "expected 502, got: {}",
            resp
        );
    }

    #[tokio::test]
    async fn test_http_plain_get() {
        let http_port = http_server("hello from server").await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_http(stream, None, false).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let request = format!(
            "GET http://127.0.0.1:{}/test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            http_port, http_port
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let resp = read_http_response(&mut client).await;
        assert!(resp.contains("200 OK"), "expected 200, got: {}", resp);
        assert!(resp.contains("hello from server"), "body missing: {}", resp);
    }

    #[tokio::test]
    async fn test_http_plain_multiple_requests_same_client() {
        let http_port = http_server("ok").await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_http(stream, None, false).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let req1 = format!(
            "GET http://127.0.0.1:{}/one HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            http_port, http_port
        );
        client.write_all(req1.as_bytes()).await.unwrap();
        let resp1 = read_http_response(&mut client).await;
        assert!(resp1.contains("200 OK"));

        let req2 = format!(
            "GET http://127.0.0.1:{}/two HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            http_port, http_port
        );
        client.write_all(req2.as_bytes()).await.unwrap();
        let resp2 = read_http_response(&mut client).await;
        assert!(resp2.contains("200 OK"));
    }
}

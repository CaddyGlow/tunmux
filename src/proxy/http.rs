#![cfg(all(feature = "proxy", target_os = "linux"))]

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, warn};

pub async fn handle_http(client: TcpStream) -> anyhow::Result<()> {
    let mut buf_client = BufReader::new(client);

    // Read the request line
    let mut request_line = String::new();
    buf_client.read_line(&mut request_line).await?;
    let request_line = request_line.trim_end().to_string();

    if request_line.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        anyhow::bail!("malformed HTTP request line");
    }
    let method = parts[0];
    let target = parts[1];
    let version = parts[2];

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(buf_client, target).await
    } else {
        handle_plain(buf_client, method, target, version).await
    }
}

/// HTTP CONNECT tunneling (e.g., for HTTPS)
async fn handle_connect(mut buf_client: BufReader<TcpStream>, target: &str) -> anyhow::Result<()> {
    debug!("HTTP CONNECT to {}", target);

    // Read and discard remaining headers
    loop {
        let mut line = String::new();
        buf_client.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Parse host:port
    let addr = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:443", target)
    };

    match TcpStream::connect(&addr).await {
        Ok(mut remote) => {
            // Send 200 Connection Established
            buf_client
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            let mut client = buf_client.into_inner();
            let result = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
            if let Err(e) = result {
                debug!("HTTP CONNECT tunnel closed: {}", e);
            }
        }
        Err(e) => {
            warn!("HTTP CONNECT to {} failed: {}", addr, e);
            buf_client
                .get_mut()
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
        }
    }

    Ok(())
}

/// Plain HTTP forwarding (non-CONNECT methods with absolute URI)
async fn handle_plain(
    mut buf_client: BufReader<TcpStream>,
    method: &str,
    target: &str,
    version: &str,
) -> anyhow::Result<()> {
    debug!("HTTP {} {}", method, target);

    // Parse absolute URI to extract host and relative path
    let (host, path) = parse_absolute_uri(target)?;

    // Determine connection address
    let addr = if host.contains(':') {
        host.clone()
    } else {
        format!("{}:80", host)
    };

    // Read all request headers, filtering out proxy-specific and connection headers
    let mut headers = Vec::new();
    let mut has_host = false;
    loop {
        let mut line = String::new();
        buf_client.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        // Skip proxy-only and connection headers; we inject our own
        if lower.starts_with("proxy-connection:") || lower.starts_with("connection:") {
            continue;
        }
        if lower.starts_with("host:") {
            has_host = true;
        }
        headers.push(line);
    }

    // Find content-length if present
    let content_length: usize = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("content-length:"))
        .and_then(|h| h.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    // Read body if present
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        buf_client.read_exact(&mut body).await?;
    }

    // Connect to remote
    match TcpStream::connect(&addr).await {
        Ok(mut remote) => {
            // Rewrite request with relative path
            let request_line = format!("{} {} {}\r\n", method, path, version);
            remote.write_all(request_line.as_bytes()).await?;

            // Ensure Host header is present
            if !has_host {
                remote
                    .write_all(format!("Host: {}\r\n", host).as_bytes())
                    .await?;
            }

            // Forward original headers
            for header in &headers {
                remote.write_all(header.as_bytes()).await?;
            }

            // Force close so server does not keep-alive
            remote.write_all(b"Connection: close\r\n").await?;
            remote.write_all(b"\r\n").await?;

            // Forward body
            if content_length > 0 {
                remote.write_all(&body).await?;
            }

            // Bidirectional copy until both sides close
            let mut client = buf_client.into_inner();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        }
        Err(e) => {
            warn!("HTTP {} to {} failed: {}", method, addr, e);
            buf_client
                .get_mut()
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
        }
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

    /// Minimal HTTP server that returns a fixed response. Returns the port.
    async fn http_server(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Read until empty line (end of headers)
                    let mut buf = vec![0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_http_connect_tunnel() {
        let echo_port = echo_server().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let _ = handle_http(stream).await;
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
            let _ = handle_http(stream).await;
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
            let _ = handle_http(stream).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let request = format!(
            "GET http://127.0.0.1:{}/test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            http_port, http_port
        );
        client.write_all(request.as_bytes()).await.unwrap();

        // Read full response
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("200 OK"),
            "expected 200, got: {}",
            resp_str
        );
        assert!(
            resp_str.contains("hello from server"),
            "body missing: {}",
            resp_str
        );
    }
}

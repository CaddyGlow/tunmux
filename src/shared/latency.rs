use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Probe endpoint latency for a list of endpoints.
///
/// Returns one latency per input endpoint, preserving order. `None` means
/// timeout or no route.
///
/// This first tries ICMP ping (when available on the host), then falls back
/// to TCP connect latency. Connection-refused style TCP responses are treated
/// as a valid reachability signal and return a measured duration.
pub async fn probe_endpoints_tcp(
    targets: &[(String, u16)],
    timeout: Duration,
    concurrency: usize,
) -> Vec<Option<Duration>> {
    if targets.is_empty() {
        return Vec::new();
    }

    let mut results = vec![None; targets.len()];
    let limit = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = JoinSet::new();

    for (idx, (host, port)) in targets.iter().enumerate() {
        let host = host.clone();
        let port = *port;
        let limit = Arc::clone(&limit);
        set.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            let latency = probe_once(&host, port, timeout).await;
            (idx, latency)
        });
    }

    while let Some(joined) = set.join_next().await {
        if let Ok((idx, latency)) = joined {
            results[idx] = latency;
        }
    }

    results
}

async fn probe_once(host: &str, port: u16, timeout: Duration) -> Option<Duration> {
    if let Some(ping_latency) = probe_ping_once(host, timeout).await {
        return Some(ping_latency);
    }
    probe_tcp_once(host, port, timeout).await
}

async fn probe_ping_once(host: &str, timeout: Duration) -> Option<Duration> {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        let mut cmd = Command::new("ping");
        cmd.arg("-n").arg("-c").arg("1");

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let timeout_secs = ((timeout.as_millis().saturating_add(999)) / 1000).max(1);
            cmd.arg("-w").arg(timeout_secs.to_string());
        }

        #[cfg(target_os = "macos")]
        {
            let timeout_ms = timeout.as_millis().max(1);
            cmd.arg("-W").arg(timeout_ms.to_string());
        }

        cmd.arg(host);

        let output = cmd.output().await.ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(duration) = parse_ping_duration(&stdout) {
            return Some(duration);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        parse_ping_duration(&stderr)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = (host, timeout);
        None
    }
}

fn parse_ping_duration(output: &str) -> Option<Duration> {
    if let Some(idx) = output.find("time=") {
        let value = &output[idx + 5..];
        return parse_duration_ms_prefix(value);
    }
    if let Some(idx) = output.find("time<") {
        let value = &output[idx + 5..];
        return parse_duration_ms_prefix(value);
    }
    None
}

fn parse_duration_ms_prefix(input: &str) -> Option<Duration> {
    let mut token = String::new();
    for ch in input.chars() {
        if ch.is_ascii_digit() || ch == '.' || ch == ',' {
            token.push(ch);
            continue;
        }
        break;
    }

    if token.is_empty() {
        return None;
    }

    let normalized = token.replace(',', ".");
    let millis = normalized.parse::<f64>().ok()?;
    if !millis.is_finite() || millis <= 0.0 {
        return None;
    }

    let micros = (millis * 1000.0).round() as u64;
    Some(Duration::from_micros(micros.max(1)))
}

async fn probe_tcp_once(host: &str, port: u16, timeout: Duration) -> Option<Duration> {
    let started = tokio::time::Instant::now();
    let address = format!("{}:{}", host, port);
    match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => Some(started.elapsed()),
        Ok(Err(err)) if is_reachable_connect_error(&err) => Some(started.elapsed()),
        _ => None,
    }
}

fn is_reachable_connect_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_endpoints_tcp_preserves_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("listener local addr").port();

        tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await;
                if accepted.is_err() {
                    break;
                }
            }
        });

        let targets = vec![
            ("127.0.0.1".to_string(), port),
            ("no-such-host.invalid".to_string(), 9),
        ];
        let latencies = probe_endpoints_tcp(&targets, Duration::from_millis(300), 4).await;

        assert_eq!(latencies.len(), 2);
        assert!(latencies[0].is_some());
        assert!(latencies[1].is_none());
    }

    #[test]
    fn test_parse_ping_duration_linux_line() {
        let sample = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=23.6 ms";
        let parsed = parse_ping_duration(sample).expect("parse ping time");
        assert_eq!(parsed.as_millis(), 23);
    }

    #[test]
    fn test_parse_ping_duration_with_less_than() {
        let sample = "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time<1 ms";
        let parsed = parse_ping_duration(sample).expect("parse ping time");
        assert_eq!(parsed.as_micros(), 1000);
    }
}

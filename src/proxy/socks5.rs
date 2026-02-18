use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

// SOCKS5 constants
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub async fn handle_socks5(mut client: TcpStream) -> anyhow::Result<()> {
    // 1. Greeting: client sends version + method list
    let ver = client.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version: {}", ver);
    }
    let nmethods = client.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    // We only support no-auth
    if !methods.contains(&AUTH_NONE) {
        // No acceptable methods
        client.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        anyhow::bail!("client does not support no-auth");
    }
    client.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;

    // 2. Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let ver = client.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("unexpected version in request: {}", ver);
    }
    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    if cmd != CMD_CONNECT {
        send_reply(&mut client, REP_CMD_NOT_SUPPORTED).await?;
        anyhow::bail!("unsupported SOCKS command: {}", cmd);
    }

    let addr = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::from(buf);
            ip.to_string()
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
            let ip = Ipv6Addr::from(buf);
            format!("[{}]", ip)
        }
        _ => {
            send_reply(&mut client, REP_ATYP_NOT_SUPPORTED).await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };

    let port = client.read_u16().await?;
    let target = format!("{}:{}", addr, port);
    debug!("SOCKS5 CONNECT to {}", target);

    // 3. Connect to target (inside VPN namespace -- already set via setns)
    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            send_reply(&mut client, REP_SUCCESS).await?;
            let result = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
            if let Err(e) = result {
                debug!("SOCKS5 tunnel closed: {}", e);
            }
        }
        Err(e) => {
            warn!("SOCKS5 connect to {} failed: {}", target, e);
            send_reply(&mut client, REP_GENERAL_FAILURE).await?;
        }
    }

    Ok(())
}

async fn send_reply(client: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let reply = [
        SOCKS_VERSION,
        rep,
        0x00,     // RSV
        ATYP_IPV4,
        0, 0, 0, 0, // BND.ADDR (0.0.0.0)
        0, 0,     // BND.PORT (0)
    ];
    client.write_all(&reply).await?;
    Ok(())
}

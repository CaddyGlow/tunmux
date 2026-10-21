use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::anyhow;
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

use super::bridge::bridge;
use super::dns::{ip_to_smoltcp, resolve_ipv4_preferred};
use super::queue::{ByteQueue, ConnRequest};
use super::{TunnelDnsResolver, CLIENT_CHANNEL_CAP};

pub(crate) async fn socks5_serve(
    mut stream: TcpStream,
    conn_req_tx: mpsc::Sender<ConnRequest>,
    loop_notify: Arc<Notify>,
    dns_resolver: Option<TunnelDnsResolver>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    anyhow::ensure!(buf[0] == 0x05, "not SOCKS5");
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x01 {
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("only CONNECT supported");
    }

    let (target_ip, target_port) =
        read_socks5_addr(&mut stream, hdr[3], dns_resolver.as_ref()).await?;

    let to_client_tx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify.clone()));
    let from_client_rx = Arc::new(ByteQueue::new(CLIENT_CHANNEL_CAP, loop_notify));
    let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();

    conn_req_tx
        .send(ConnRequest {
            target_ip,
            target_port,
            to_client_tx: to_client_tx.clone(),
            from_client_rx: from_client_rx.clone(),
            connected_tx,
        })
        .await
        .map_err(|_| anyhow!("proxy tunnel exited"))?;

    match connected_rx.await {
        Ok(Ok(())) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
        Ok(Err(e)) => {
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            anyhow::bail!("virtual connect: {}", e);
        }
        Err(_) => anyhow::bail!("proxy tunnel dropped response"),
    }

    bridge(&mut stream, from_client_rx, to_client_tx).await;
    Ok(())
}

pub(crate) async fn read_socks5_addr(
    stream: &mut TcpStream,
    atyp: u8,
    dns_resolver: Option<&TunnelDnsResolver>,
) -> anyhow::Result<(IpAddress, u16)> {
    match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            Ok((IpAddress::Ipv4(Ipv4Addr::from(a)), u16::from_be_bytes(p)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; len[0] as usize];
            stream.read_exact(&mut dom).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let host = std::str::from_utf8(&dom)?;
            let sa = resolve_ipv4_preferred(host, port, dns_resolver).await?;
            Ok((ip_to_smoltcp(sa.ip()), sa.port()))
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            Ok((IpAddress::Ipv6(Ipv6Addr::from(a)), u16::from_be_bytes(p)))
        }
        other => anyhow::bail!("unsupported SOCKS5 atyp {}", other),
    }
}

use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::queue::ByteQueue;
use super::STREAM_BUF;

/// Copy between the client and the virtual connection. Each direction ends on
/// its own FIN, so a client that half-closes still receives the reply.
pub(crate) async fn bridge(
    stream: &mut TcpStream,
    from_client_tx: Arc<ByteQueue>,
    to_client_rx: Arc<ByteQueue>,
) {
    let (mut reader, mut writer) = stream.split();
    let mut read_buf = BytesMut::with_capacity(STREAM_BUF);
    let mut client_open = true;
    let mut remote_open = true;
    while client_open || remote_open {
        tokio::select! {
            result = reader.read_buf(&mut read_buf), if client_open => {
                match result {
                    Ok(0) => {
                        client_open = false;
                        from_client_tx.close();
                    }
                    Err(_) => break,
                    Ok(_) => {
                        let chunk = read_buf.split().freeze();
                        if from_client_tx.push(chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
            data = to_client_rx.pop(), if remote_open => {
                match data {
                    None => {
                        remote_open = false;
                        if writer.shutdown().await.is_err() {
                            break;
                        }
                    }
                    Some(d) => {
                        if writer.write_all(d.as_ref()).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // The connection was dropped while the client still had its side open.
            () = from_client_tx.closed(), if client_open && !remote_open => break,
        }
    }
    from_client_tx.close();
    to_client_rx.close();
}

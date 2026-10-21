use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::queue::ByteQueue;
use super::STREAM_BUF;

pub(crate) async fn bridge(
    stream: &mut TcpStream,
    from_client_tx: Arc<ByteQueue>,
    to_client_rx: Arc<ByteQueue>,
) {
    let (mut reader, mut writer) = stream.split();
    let mut read_buf = BytesMut::with_capacity(STREAM_BUF);
    loop {
        tokio::select! {
            result = reader.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let chunk = read_buf.split().freeze();
                        if from_client_tx.push(chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
            data = to_client_rx.pop() => {
                match data {
                    None => break,
                    Some(d) => {
                        if writer.write_all(d.as_ref()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    from_client_tx.close();
    to_client_rx.close();
}

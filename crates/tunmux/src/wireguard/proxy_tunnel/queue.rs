use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use tokio::sync::Notify;

pub(crate) enum QueuePushError {
    Full(Bytes),
    Closed,
}

pub(crate) struct ByteQueue {
    queue: ArrayQueue<Bytes>,
    has_data_notify: Notify,
    has_space_notify: Notify,
    loop_notify: Arc<Notify>,
    closed: AtomicBool,
}

impl ByteQueue {
    pub(crate) fn new(capacity: usize, loop_notify: Arc<Notify>) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            has_data_notify: Notify::new(),
            has_space_notify: Notify::new(),
            loop_notify,
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.has_data_notify.notify_waiters();
        self.has_space_notify.notify_waiters();
        self.loop_notify.notify_waiters();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    pub(crate) fn try_push(&self, chunk: Bytes) -> Result<(), QueuePushError> {
        if self.is_closed() {
            return Err(QueuePushError::Closed);
        }
        match self.queue.push(chunk) {
            Ok(()) => {
                self.has_data_notify.notify_one();
                self.loop_notify.notify_one();
                Ok(())
            }
            Err(chunk) => Err(QueuePushError::Full(chunk)),
        }
    }

    pub(crate) async fn push(&self, mut chunk: Bytes) -> Result<(), ()> {
        loop {
            match self.try_push(chunk) {
                Ok(()) => return Ok(()),
                Err(QueuePushError::Closed) => return Err(()),
                Err(QueuePushError::Full(returned)) => {
                    chunk = returned;
                    if self.is_closed() {
                        return Err(());
                    }
                    self.has_space_notify.notified().await;
                }
            }
        }
    }

    pub(crate) fn try_pop(&self) -> Option<Bytes> {
        let out = self.queue.pop();
        if out.is_some() {
            self.has_space_notify.notify_one();
            self.loop_notify.notify_one();
        }
        out
    }

    pub(crate) async fn pop(&self) -> Option<Bytes> {
        loop {
            if let Some(out) = self.try_pop() {
                return Some(out);
            }
            if self.is_closed() {
                return None;
            }
            self.has_data_notify.notified().await;
        }
    }
}

pub(crate) struct ConnRequest {
    pub(crate) target_ip: smoltcp::wire::IpAddress,
    pub(crate) target_port: u16,
    pub(crate) to_client_tx: Arc<ByteQueue>,
    pub(crate) from_client_rx: Arc<ByteQueue>,
    pub(crate) connected_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
}

pub(crate) struct DnsUdpRequest {
    pub(crate) dns_server: smoltcp::wire::IpAddress,
    pub(crate) source_ip: smoltcp::wire::IpAddress,
    pub(crate) payload: Vec<u8>,
    pub(crate) response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

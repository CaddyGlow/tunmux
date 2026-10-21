use std::collections::VecDeque;

use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};

/// Covers a 1420-byte MTU packet plus WireGuard framing; larger ones allocate.
const PACKET_BUF: usize = 2048;
/// Spare buffers kept per direction; the rest are freed.
const POOL_MAX: usize = 1024;

/// Recycled packet buffers, so the dataplane does not allocate per packet.
#[derive(Default)]
pub(crate) struct PacketPool {
    free: Vec<Vec<u8>>,
}

impl PacketPool {
    /// A buffer of at least `min_len` bytes; its contents are unspecified.
    pub(crate) fn take(&mut self, min_len: usize) -> Vec<u8> {
        if min_len > PACKET_BUF {
            return vec![0u8; min_len];
        }
        self.free.pop().unwrap_or_else(|| vec![0u8; PACKET_BUF])
    }

    pub(crate) fn put(&mut self, buf: Vec<u8>) {
        if buf.len() == PACKET_BUF && self.free.len() < POOL_MAX {
            self.free.push(buf);
        }
    }
}

/// One IP packet in the first `len` bytes of a pooled buffer.
pub(crate) struct Packet {
    buf: Vec<u8>,
    len: usize,
}

impl Packet {
    pub(crate) fn new(buf: Vec<u8>, len: usize) -> Self {
        debug_assert!(len <= buf.len());
        Self { buf, len }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub(crate) fn into_buf(self) -> Vec<u8> {
        self.buf
    }
}

pub(crate) struct VirtualDevice {
    pub(crate) inbound: VecDeque<Packet>,
    pub(crate) outbound: VecDeque<Packet>,
    pub(crate) rx_pool: PacketPool,
    pub(crate) tx_pool: PacketPool,
    caps: DeviceCapabilities,
}

impl VirtualDevice {
    pub(crate) fn new() -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420;
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            rx_pool: PacketPool::default(),
            tx_pool: PacketPool::default(),
            caps,
        }
    }
}

pub(crate) struct VirtRxToken<'a> {
    packet: Packet,
    pool: &'a mut PacketPool,
}

impl RxToken for VirtRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let r = f(self.packet.as_slice());
        self.pool.put(self.packet.into_buf());
        r
    }
}

pub(crate) struct VirtTxToken<'a> {
    outbound: &'a mut VecDeque<Packet>,
    pool: &'a mut PacketPool,
}

impl TxToken for VirtTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.pool.take(len);
        let r = f(&mut buf[..len]);
        self.outbound.push_back(Packet::new(buf, len));
        r
    }
}

impl smoltcp::phy::Device for VirtualDevice {
    type RxToken<'a> = VirtRxToken<'a>;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let Self {
            inbound,
            outbound,
            rx_pool,
            tx_pool,
            ..
        } = self;
        let packet = inbound.pop_front()?;
        Some((
            VirtRxToken {
                packet,
                pool: rx_pool,
            },
            VirtTxToken {
                outbound,
                pool: tx_pool,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken {
            outbound: &mut self.outbound,
            pool: &mut self.tx_pool,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_reuses_standard_buffers_and_skips_oversized_ones() {
        let mut pool = PacketPool::default();
        let mut buf = pool.take(100);
        assert_eq!(buf.len(), PACKET_BUF);
        buf[0] = 7;
        let ptr = buf.as_ptr();
        pool.put(buf);
        let reused = pool.take(1500);
        assert_eq!(reused.as_ptr(), ptr);

        let big = pool.take(PACKET_BUF + 1);
        assert_eq!(big.len(), PACKET_BUF + 1);
        pool.put(big);
        assert!(pool.free.is_empty());
    }

    #[test]
    fn test_pool_caps_spare_buffers() {
        let mut pool = PacketPool::default();
        for _ in 0..POOL_MAX + 10 {
            pool.put(vec![0u8; PACKET_BUF]);
        }
        assert_eq!(pool.free.len(), POOL_MAX);
    }
}

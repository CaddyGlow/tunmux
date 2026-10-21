//! WireGuard UDP I/O for the local proxy. On Linux, outgoing datagrams leave in
//! UDP GSO runs (one `sendmsg` for up to 64 equal-sized datagrams) and incoming
//! ones arrive through `recvmmsg` with UDP GRO. Elsewhere each datagram takes
//! its own syscall. Fragmentation settings are left at the kernel defaults.

use std::collections::VecDeque;
use std::io;

use tokio::net::UdpSocket;
use tracing::warn;

use super::perf::DataplanePerf;

/// Room `Tunn::encapsulate` may need for one datagram.
const DATAGRAM_MAX: usize = super::UDP_BUF + 32;
const TX_BUF_INITIAL: usize = 1024 * 1024;
/// Kernel limit on segments per GSO send (`UDP_MAX_SEGMENTS` before 6.1).
const GSO_SEGMENTS_MAX: usize = 64;
/// Keeps a GSO payload below the 64 KiB IP datagram limit.
const GSO_BYTES_MAX: usize = 60 * 1024;
#[cfg(target_os = "linux")]
const RX_SLOTS: usize = 32;
#[cfg(not(target_os = "linux"))]
const RX_SLOTS: usize = 1;
/// One GRO slot holds up to 64 coalesced datagrams.
const RX_SLOT_BYTES: usize = 64 * 1024;

/// Datagrams waiting to be sent, stored back to back in one buffer.
pub(crate) struct UdpTx {
    buf: Vec<u8>,
    head: usize,
    end: usize,
    lens: VecDeque<usize>,
    gso: bool,
}

impl UdpTx {
    pub(crate) fn new() -> Self {
        Self {
            buf: vec![0u8; TX_BUF_INITIAL],
            head: 0,
            end: 0,
            lens: VecDeque::new(),
            gso: cfg!(target_os = "linux"),
        }
    }

    pub(crate) fn pending(&self) -> usize {
        self.lens.len()
    }

    /// Lets `fill` write one datagram in place and queues the length it
    /// returns; `None` queues nothing.
    pub(crate) fn push_with(
        &mut self,
        perf: &mut DataplanePerf,
        fill: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) {
        self.reserve();
        let Some(len) = fill(&mut self.buf[self.end..self.end + DATAGRAM_MAX]) else {
            return;
        };
        self.end += len;
        self.lens.push_back(len);
        perf.tunn_net_writes = perf.tunn_net_writes.saturating_add(1);
    }

    pub(crate) fn push(&mut self, perf: &mut DataplanePerf, datagram: &[u8]) {
        self.push_with(perf, |dst| {
            dst[..datagram.len()].copy_from_slice(datagram);
            Some(datagram.len())
        });
    }

    fn reserve(&mut self) {
        if self.lens.is_empty() {
            self.head = 0;
            self.end = 0;
        }
        if self.end + DATAGRAM_MAX <= self.buf.len() {
            return;
        }
        if self.head > 0 {
            self.buf.copy_within(self.head..self.end, 0);
            self.end -= self.head;
            self.head = 0;
        }
        if self.end + DATAGRAM_MAX > self.buf.len() {
            self.buf.resize(self.buf.len() * 2, 0);
        }
    }

    fn advance(&mut self, count: usize, bytes: usize, perf: &mut DataplanePerf) {
        self.lens.drain(..count);
        self.head += bytes;
        perf.udp_tx_packets = perf.udp_tx_packets.saturating_add(count as u64);
        perf.udp_tx_bytes = perf.udp_tx_bytes.saturating_add(bytes as u64);
    }

    /// The longest prefix one GSO send may carry: datagrams of the first
    /// one's size, where only the last may be shorter.
    fn next_run(&self) -> (usize, usize) {
        let Some(&first) = self.lens.front() else {
            return (0, 0);
        };
        if !self.gso {
            return (1, first);
        }
        let (mut count, mut bytes) = (0, 0);
        for &len in &self.lens {
            if count == GSO_SEGMENTS_MAX || len > first || bytes + len > GSO_BYTES_MAX {
                break;
            }
            count += 1;
            bytes += len;
            if len < first {
                break;
            }
        }
        (count.max(1), bytes.max(first))
    }

    /// Sends what the socket accepts; the rest waits for writability.
    pub(crate) fn flush(&mut self, udp: &UdpSocket, perf: &mut DataplanePerf) {
        loop {
            let (count, bytes) = self.next_run();
            if count == 0 {
                return;
            }
            let segment = self.lens[0];
            let data = &self.buf[self.head..self.head + bytes];
            perf.udp_tx_syscalls = perf.udp_tx_syscalls.saturating_add(1);
            match send_run(udp, data, (count > 1).then_some(segment)) {
                Ok(()) => self.advance(count, bytes, perf),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if count > 1 && gso_refused(&error) => {
                    // EIO: no checksum offload, so GSO never works on this route.
                    // EINVAL: the path MTU is below the segment size; single sends
                    // let the kernel fragment as it would without GSO.
                    if gso_unsupported(&error) {
                        warn!(error = %error, "udp_gso_disabled");
                        self.gso = false;
                    }
                    if !self.flush_singly(count, udp, perf) {
                        return;
                    }
                }
                Err(error) => {
                    warn!(error = %error, datagrams = count, "udp_send_error");
                    self.advance(count, bytes, perf);
                }
            }
        }
    }

    /// Sends `count` queued datagrams one by one; false once the socket is full.
    fn flush_singly(&mut self, count: usize, udp: &UdpSocket, perf: &mut DataplanePerf) -> bool {
        for _ in 0..count {
            let len = self.lens[0];
            perf.udp_tx_syscalls = perf.udp_tx_syscalls.saturating_add(1);
            match udp.try_send(&self.buf[self.head..self.head + len]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                Err(error) => warn!(error = %error, "udp_send_error"),
            }
            self.advance(1, len, perf);
        }
        true
    }
}

#[cfg(target_os = "linux")]
fn gso_refused(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(nix::libc::EIO | nix::libc::EINVAL)
    )
}

#[cfg(not(target_os = "linux"))]
fn gso_refused(_error: &io::Error) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn gso_unsupported(error: &io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::EIO)
}

#[cfg(not(target_os = "linux"))]
fn gso_unsupported(_error: &io::Error) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn send_run(udp: &UdpSocket, data: &[u8], segment: Option<usize>) -> io::Result<()> {
    use std::io::IoSlice;
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};

    let Some(segment) = segment else {
        return udp.try_send(data).map(drop);
    };
    let segment =
        u16::try_from(segment).map_err(|_| io::Error::from_raw_os_error(nix::libc::EINVAL))?;
    udp.try_io(tokio::io::Interest::WRITABLE, || {
        sendmsg::<SockaddrStorage>(
            udp.as_raw_fd(),
            &[IoSlice::new(data)],
            &[ControlMessage::UdpGsoSegments(&segment)],
            MsgFlags::empty(),
            None,
        )
        .map(drop)
        .map_err(io::Error::from)
    })
}

#[cfg(not(target_os = "linux"))]
fn send_run(udp: &UdpSocket, data: &[u8], _segment: Option<usize>) -> io::Result<()> {
    udp.try_send(data).map(drop)
}

/// Receive slots filled by one syscall, with each slot's length and GRO stride.
pub(crate) struct UdpRx {
    slots: Vec<Vec<u8>>,
    filled: Vec<(usize, usize)>,
    #[cfg(target_os = "linux")]
    headers: nix::sys::socket::MultiHeaders<nix::sys::socket::SockaddrStorage>,
}

impl UdpRx {
    pub(crate) fn new(udp: &UdpSocket) -> Self {
        #[cfg(target_os = "linux")]
        if let Err(error) =
            nix::sys::socket::setsockopt(udp, nix::sys::socket::sockopt::UdpGroSegment, &true)
        {
            tracing::debug!(error = %error, "udp_gro_unavailable");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = udp;
        Self {
            slots: (0..RX_SLOTS).map(|_| vec![0u8; RX_SLOT_BYTES]).collect(),
            filled: Vec::with_capacity(RX_SLOTS),
            #[cfg(target_os = "linux")]
            headers: nix::sys::socket::MultiHeaders::preallocate(
                RX_SLOTS,
                Some(nix::cmsg_space!(i32)),
            ),
        }
    }

    /// Reads what is queued, up to one batch; WouldBlock when nothing is.
    pub(crate) fn recv(&mut self, udp: &UdpSocket, perf: &mut DataplanePerf) -> io::Result<()> {
        self.filled.clear();
        perf.udp_rx_syscalls = perf.udp_rx_syscalls.saturating_add(1);
        self.recv_batch(udp)
    }

    #[cfg(target_os = "linux")]
    fn recv_batch(&mut self, udp: &UdpSocket) -> io::Result<()> {
        use std::io::IoSliceMut;
        use std::os::fd::AsRawFd;

        use nix::sys::socket::{recvmmsg, ControlMessageOwned, MsgFlags};

        let Self {
            slots,
            filled,
            headers,
        } = self;
        udp.try_io(tokio::io::Interest::READABLE, || {
            let mut iovs: Vec<[IoSliceMut<'_>; 1]> = slots
                .iter_mut()
                .map(|slot| [IoSliceMut::new(slot)])
                .collect();
            let results = recvmmsg(
                udp.as_raw_fd(),
                headers,
                iovs.iter_mut(),
                MsgFlags::MSG_DONTWAIT,
                None,
            )
            .map_err(io::Error::from)?;
            for msg in results {
                let stride = msg
                    .cmsgs()
                    .ok()
                    .and_then(|mut cmsgs| {
                        cmsgs.find_map(|cmsg| match cmsg {
                            ControlMessageOwned::UdpGroSegments(size) => usize::try_from(size).ok(),
                            _ => None,
                        })
                    })
                    .filter(|&size| size > 0)
                    .unwrap_or(msg.bytes);
                filled.push((msg.bytes, stride));
            }
            Ok(())
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_batch(&mut self, udp: &UdpSocket) -> io::Result<()> {
        let n = udp.try_recv(&mut self.slots[0])?;
        self.filled.push((n, n));
        Ok(())
    }

    /// Datagrams from the last `recv`, with GRO buffers split by stride.
    pub(crate) fn datagrams(&self) -> impl Iterator<Item = &[u8]> {
        self.filled
            .iter()
            .zip(&self.slots)
            .flat_map(|(&(len, stride), slot)| slot[..len].chunks(stride.max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(lens: &[usize]) -> UdpTx {
        let mut tx = UdpTx::new();
        let mut perf = DataplanePerf::new(false);
        for &len in lens {
            tx.push(&mut perf, &vec![0xab; len]);
        }
        tx
    }

    #[test]
    fn test_next_run_groups_equal_sizes_and_ends_on_a_shorter_one() {
        assert_eq!(queued(&[100, 100, 60, 100]).next_run(), (3, 260));
        assert_eq!(queued(&[100, 120]).next_run(), (1, 100));
        assert_eq!(queued(&[]).next_run(), (0, 0));
    }

    #[test]
    fn test_next_run_respects_segment_and_byte_limits() {
        assert_eq!(
            queued(&[10; GSO_SEGMENTS_MAX + 5]).next_run(),
            (GSO_SEGMENTS_MAX, 10 * GSO_SEGMENTS_MAX)
        );
        let per_run = GSO_BYTES_MAX / 1500;
        assert_eq!(queued(&[1500; 50]).next_run(), (per_run, per_run * 1500));
    }

    #[test]
    fn test_next_run_sends_singly_without_gso() {
        let mut tx = queued(&[100, 100, 100]);
        tx.gso = false;
        assert_eq!(tx.next_run(), (1, 100));
    }

    #[test]
    fn test_push_compacts_and_grows_without_losing_queued_bytes() {
        let mut tx = UdpTx::new();
        let mut perf = DataplanePerf::new(false);
        let datagrams = TX_BUF_INITIAL / 1000 + 50;
        for i in 0..datagrams {
            tx.push(&mut perf, &[i as u8; 1000]);
            if i % 3 == 0 {
                tx.advance(1, tx.lens[0], &mut perf);
            }
        }
        let mut offset = tx.head;
        for (i, len) in tx.lens.iter().enumerate() {
            let expected = (datagrams - tx.lens.len() + i) as u8;
            assert!(tx.buf[offset..offset + len].iter().all(|&b| b == expected));
            offset += len;
        }
        assert_eq!(offset, tx.end);
    }
}

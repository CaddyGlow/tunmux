use std::collections::VecDeque;

use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};

pub(crate) struct VirtualDevice {
    pub(crate) inbound: VecDeque<Vec<u8>>,
    pub(crate) outbound: VecDeque<Vec<u8>>,
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
            caps,
        }
    }
}

pub(crate) struct VirtRxToken(Vec<u8>);
impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct VirtTxToken<'a>(pub(crate) &'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl smoltcp::phy::Device for VirtualDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound
            .pop_front()
            .map(|pkt| (VirtRxToken(pkt), VirtTxToken(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

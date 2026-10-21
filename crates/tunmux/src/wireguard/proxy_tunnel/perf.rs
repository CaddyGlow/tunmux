use std::time::{Duration, Instant};

use tracing::info;

use super::PERF_LOG_INTERVAL;

pub(crate) struct DataplanePerf {
    pub(crate) enabled: bool,
    last_log: Instant,
    pub(crate) loops: u64,
    pub(crate) iface_polls: u64,
    pub(crate) iface_poll_ns: u64,
    pub(crate) udp_rx_packets: u64,
    pub(crate) udp_rx_bytes: u64,
    pub(crate) udp_tx_packets: u64,
    pub(crate) udp_tx_bytes: u64,
    pub(crate) tunn_net_writes: u64,
    pub(crate) tunn_net_write_copies: u64,
    pub(crate) conn_visits: u64,
    pub(crate) conn_requeues: u64,
    pub(crate) active_q_peak: usize,
    pub(crate) udp_pending_peak: usize,
    pub(crate) idle_wakes: u64,
    pub(crate) idle_wait_ns: u64,
    pub(crate) idle_wake_udp: u64,
    pub(crate) idle_wake_conn_req: u64,
    pub(crate) idle_wake_loop_notify: u64,
    pub(crate) idle_wake_timeout: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum IdleWakeReason {
    Udp,
    ConnReq,
    LoopNotify,
    Timeout,
}

impl DataplanePerf {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_log: Instant::now(),
            loops: 0,
            iface_polls: 0,
            iface_poll_ns: 0,
            udp_rx_packets: 0,
            udp_rx_bytes: 0,
            udp_tx_packets: 0,
            udp_tx_bytes: 0,
            tunn_net_writes: 0,
            tunn_net_write_copies: 0,
            conn_visits: 0,
            conn_requeues: 0,
            active_q_peak: 0,
            udp_pending_peak: 0,
            idle_wakes: 0,
            idle_wait_ns: 0,
            idle_wake_udp: 0,
            idle_wake_conn_req: 0,
            idle_wake_loop_notify: 0,
            idle_wake_timeout: 0,
        }
    }

    pub(crate) fn observe_loop(&mut self, active_q_len: usize, udp_pending_len: usize) {
        if !self.enabled {
            return;
        }
        self.loops = self.loops.saturating_add(1);
        self.active_q_peak = self.active_q_peak.max(active_q_len);
        self.udp_pending_peak = self.udp_pending_peak.max(udp_pending_len);
    }

    pub(crate) fn maybe_log_and_reset(&mut self, conns: usize) {
        if !self.enabled || self.last_log.elapsed() < PERF_LOG_INTERVAL {
            return;
        }
        let elapsed = self.last_log.elapsed();
        let elapsed_s = elapsed.as_secs_f64();
        let idle_wake_hz = if elapsed_s > 0.0 {
            self.idle_wakes as f64 / elapsed_s
        } else {
            0.0
        };
        info!(
            interval_ms = elapsed.as_millis() as u64,
            conns = conns,
            loops = self.loops,
            iface_polls = self.iface_polls,
            iface_poll_ms = self.iface_poll_ns as f64 / 1_000_000.0,
            udp_rx_packets = self.udp_rx_packets,
            udp_rx_mib = self.udp_rx_bytes as f64 / (1024.0 * 1024.0),
            udp_tx_packets = self.udp_tx_packets,
            udp_tx_mib = self.udp_tx_bytes as f64 / (1024.0 * 1024.0),
            tunn_net_writes = self.tunn_net_writes,
            tunn_net_write_copies = self.tunn_net_write_copies,
            conn_visits = self.conn_visits,
            conn_requeues = self.conn_requeues,
            active_q_peak = self.active_q_peak,
            udp_pending_peak = self.udp_pending_peak,
            idle_wakes = self.idle_wakes,
            idle_wake_hz = idle_wake_hz,
            idle_wait_ms = self.idle_wait_ns as f64 / 1_000_000.0,
            idle_wake_udp = self.idle_wake_udp,
            idle_wake_conn_req = self.idle_wake_conn_req,
            idle_wake_loop_notify = self.idle_wake_loop_notify,
            idle_wake_timeout = self.idle_wake_timeout,
            "local_proxy_perf"
        );

        self.last_log = Instant::now();
        self.loops = 0;
        self.iface_polls = 0;
        self.iface_poll_ns = 0;
        self.udp_rx_packets = 0;
        self.udp_rx_bytes = 0;
        self.udp_tx_packets = 0;
        self.udp_tx_bytes = 0;
        self.tunn_net_writes = 0;
        self.tunn_net_write_copies = 0;
        self.conn_visits = 0;
        self.conn_requeues = 0;
        self.active_q_peak = 0;
        self.udp_pending_peak = 0;
        self.idle_wakes = 0;
        self.idle_wait_ns = 0;
        self.idle_wake_udp = 0;
        self.idle_wake_conn_req = 0;
        self.idle_wake_loop_notify = 0;
        self.idle_wake_timeout = 0;
    }

    pub(crate) fn observe_idle_wake(&mut self, wait_time: Duration, reason: IdleWakeReason) {
        if !self.enabled {
            return;
        }
        self.idle_wakes = self.idle_wakes.saturating_add(1);
        self.idle_wait_ns = self
            .idle_wait_ns
            .saturating_add(wait_time.as_nanos() as u64);
        match reason {
            IdleWakeReason::Udp => {
                self.idle_wake_udp = self.idle_wake_udp.saturating_add(1);
            }
            IdleWakeReason::ConnReq => {
                self.idle_wake_conn_req = self.idle_wake_conn_req.saturating_add(1);
            }
            IdleWakeReason::LoopNotify => {
                self.idle_wake_loop_notify = self.idle_wake_loop_notify.saturating_add(1);
            }
            IdleWakeReason::Timeout => {
                self.idle_wake_timeout = self.idle_wake_timeout.saturating_add(1);
            }
        }
    }
}

//! Opt-in worker-local diagnostics. Timers perturb the measured path; compare
//! diagnostic runs with uninstrumented runs, not as production benchmarks.
use serde::Serialize;
use std::cell::RefCell;
use std::sync::{Arc, OnceLock};

/// Histograms use upper bounds 1, 2, 4, 8, 16, 32, 64, infinity.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Metrics {
    pub worker_ns: u64,
    pub worker_iterations: u64,
    pub engine_poll_ns: u64,
    pub output_batches: [u64; 8],
    pub output_packets: u64,
    pub output_budget_exhausted: u64,
    pub queued_tx_skips: u64,
    pub pending_tx_peak: u64,
    pub packet_build_calls: u64,
    pub packet_build_failures: u64,
    pub packet_build_ns: u64,
    pub tx_calls: u64,
    pub tx_requested: u64,
    pub tx_accepted: u64,
    pub tx_partial_calls: u64,
    pub tx_zero_calls: u64,
    pub tx_batches: [u64; 8],
    pub tx_driver_ns: u64,
    pub checksum_calls: u64,
    pub checksum_bytes: u64,
    pub checksum_ns: u64,
    pub advancing_acks: u64,
    pub acked_bytes: u64,
    pub ack_segments: [u64; 8],
    pub acks_over_two_mss: u64,
    pub cwnd_peak_bytes: u64,
    pub peer_window_peak_bytes: u64,
    /// Connection-nanoseconds with queued application bytes and no room in
    /// the corresponding window. These overlap when both windows bind.
    pub cwnd_limited_ns: u64,
    pub peer_window_limited_ns: u64,
    pub retransmits: u64,
}

thread_local! { static LOCAL: RefCell<Metrics> = RefCell::new(Metrics::default()); }

pub fn record(f: impl FnOnce(&mut Metrics)) {
    LOCAL.with_borrow_mut(f);
}
/// Clear diagnostics on the calling thread, including directly driven engines.
/// Does not reset counters on a worker running on another thread.
pub fn reset() {
    LOCAL.with_borrow_mut(|m| *m = Metrics::default());
}
/// Copy diagnostics accumulated on the calling thread since its last reset.
pub fn snapshot() -> Metrics {
    LOCAL.with_borrow(Clone::clone)
}
pub fn bucket(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        ((usize::BITS - (n - 1).leading_zeros()) as usize).min(7)
    }
}

/// Does not keep a worker alive. Populated once the worker stops; read after
/// dropping its handles and waiting for its WorkerJoin.
#[derive(Clone, Default)]
pub struct Report(Arc<OnceLock<Metrics>>);
impl Report {
    pub fn get(&self) -> Option<&Metrics> {
        self.0.get()
    }
}

pub fn publish(report: &Report) {
    let _ = report.0.set(snapshot());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_boundaries() {
        for (n, expected) in [
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (32, 5),
            (33, 6),
            (64, 6),
            (65, 7),
        ] {
            assert_eq!(bucket(n), expected);
        }
    }
}

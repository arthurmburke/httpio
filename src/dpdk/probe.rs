//! Opt-in probe for latency benchmarks: when the worker next hands packets
//! to the driver.
//!
//! A benchmark that wants to know how long something takes to reach the
//! wire (a corked request's flush, say) [`arm`]s the probe just before
//! triggering it and reads [`fired`] afterwards. The worker stamps the
//! first transmit burst that follows, once before the driver call and once
//! after: the first is when the packet was ready to leave, the second
//! adds what the driver took (next to nothing for a poll-mode NIC, a
//! system call for `af_packet`).
//!
//! Process-wide and for one worker at a time: with several workers the
//! first to transmit anything fires it. Costs the worker one atomic load
//! per burst while compiled in, and nothing otherwise (`tx-probe` feature).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ARMED: AtomicBool = AtomicBool::new(false);
static READY_NS: AtomicU64 = AtomicU64::new(0);
static SENT_NS: AtomicU64 = AtomicU64::new(0);
static BURSTS: AtomicU64 = AtomicU64::new(0);
static PREBUILT: AtomicU64 = AtomicU64::new(0);

/// The monotonic clock in nanoseconds, the probe's time base.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec to write to, and CLOCK_MONOTONIC
    // always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Arms the probe for the next transmit burst, discarding an earlier
/// result.
pub fn arm() {
    SENT_NS.store(0, Ordering::SeqCst);
    READY_NS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
}

/// When the burst that fired the probe was handed to the driver and when
/// the driver returned, on [`now_ns`]'s clock; `None` until it has fired.
pub fn fired() -> Option<(u64, u64)> {
    let sent = SENT_NS.load(Ordering::SeqCst);
    (sent != 0).then(|| (READY_NS.load(Ordering::SeqCst), sent))
}

/// Transmit bursts since the process started, for telling when the worker
/// has gone quiet.
pub fn bursts() -> u64 {
    BURSTS.load(Ordering::Relaxed)
}

/// Corked tails sent, on their flush, as the packet built while they were
/// held (`TcpEngine::prebuilt_sent`, summed over the workers).
pub fn prebuilt_sent() -> u64 {
    PREBUILT.load(Ordering::Relaxed)
}

/// A flushed tail went out as its prebuilt packet.
pub(crate) fn sent_prebuilt() {
    PREBUILT.fetch_add(1, Ordering::Relaxed);
}

/// The worker is about to hand a burst to the driver. Returns whether the
/// probe was armed, to pass to [`after_transmit`].
pub(crate) fn before_transmit() -> bool {
    if !ARMED.load(Ordering::Relaxed) {
        return false;
    }
    READY_NS.store(now_ns(), Ordering::SeqCst);
    true
}

/// The driver returned, having accepted `sent` packets.
pub(crate) fn after_transmit(armed: bool, sent: usize) {
    if sent == 0 {
        return;
    }
    BURSTS.fetch_add(1, Ordering::Relaxed);
    if armed && ARMED.swap(false, Ordering::SeqCst) {
        SENT_NS.store(now_ns(), Ordering::SeqCst);
    }
}

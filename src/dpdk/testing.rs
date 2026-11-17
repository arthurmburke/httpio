//! One EAL and one mbuf pool for the whole unit-test process.
//!
//! Received data is only ever a view of a packet buffer ([`MbufSlice`]),
//! so a test that feeds the stack payload needs real mbufs, and so EAL --
//! which can be initialised once per process. Every unit test that needs
//! either goes through here; none calls `eal::init` or `eal::cleanup`
//! itself. EAL runs without hugepages or devices, and is left up until
//! the process exits.

use std::sync::OnceLock;

use super::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
use super::{MbufSlice, Mempool, eal};

/// Brings EAL up on first use.
pub(crate) fn init() {
    static EAL: OnceLock<()> = OnceLock::new();
    EAL.get_or_init(|| {
        // SAFETY: no preconditions.
        let cpu = unsafe { libc::sched_getcpu() };
        eal::init(&[
            "unit-tests",
            "--no-huge",
            "--no-pci",
            "--no-shconf",
            "--no-telemetry",
            "--lcores",
            &format!("0@{cpu}"),
        ])
        .expect("EAL must start for the unit tests");
    });
}

/// The pool [`slice`] takes its mbufs from. Tests that count pool
/// objects create their own, after [`init`].
pub(crate) fn pool() -> &'static Mempool {
    static POOL: OnceLock<Mempool> = OnceLock::new();
    POOL.get_or_init(|| {
        init();
        // No per-lcore cache: test threads are not EAL lcores.
        Mempool::create("unit-tests", 8191, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1)
            .expect("the unit-test mbuf pool")
    })
}

/// Most bytes one packet buffer from [`pool`] holds: as on the wire, a
/// received chunk is never larger than one mbuf segment.
pub(crate) const MAX_SLICE: usize = 2048;

/// `data` as it would arrive: in a packet buffer of its own.
///
/// # Panics
/// If `data` is longer than [`MAX_SLICE`], or the pool is exhausted. A
/// test that queues buffers without bound should use [`try_slice`] and
/// treat `None` as backpressure.
pub(crate) fn slice(data: &[u8]) -> MbufSlice {
    assert!(data.len() <= MAX_SLICE, "test payload must fit one mbuf");
    try_slice(data).expect("the unit-test mbuf pool is exhausted")
}

/// [`slice`], or `None` while the pool has no buffer free (tests run in
/// parallel and share it).
pub(crate) fn try_slice(data: &[u8]) -> Option<MbufSlice> {
    assert!(data.len() <= MAX_SLICE, "test payload must fit one mbuf");
    MbufSlice::copy_from_slice(pool(), data)
}

//! Safe wrapper around an `rte_mempool` used as a packet (mbuf) pool.

use std::ffi::CString;
use std::ptr;

use super::ffi;

/// `RTE_MBUF_DEFAULT_DATAROOM (2048) + RTE_PKTMBUF_HEADROOM (128)`, i.e.
/// `RTE_MBUF_DEFAULT_BUF_SIZE` -- the conventional per-mbuf buffer size used
/// throughout the DPDK examples, large enough for a standard 1500-byte MTU
/// frame plus headroom for prepending headers.
pub const DEFAULT_MBUF_DATA_ROOM_SIZE: u16 = 2048 + 128;

/// Largest per-lcore cache a pool can have (`RTE_MEMPOOL_CACHE_MAX_SIZE`),
/// and the suggested one for a pool a worker transmits from: the mbufs it
/// frees come straight back to it, still warm.
pub const MAX_CACHE_SIZE: u32 = 512;

/// The suggested size of the pool one worker builds its outgoing packets
/// from, for a queue with `tx_descriptors` transmit descriptors: four
/// mbufs per descriptor (at least 4095) -- what the device has not yet
/// released, the engine's own batch, and the extra mbuf each attached (not
/// copied) payload needs. If such a pool does run dry the engine holds
/// packets back until mbufs return.
pub fn transmit_mbufs(tx_descriptors: u16) -> u32 {
    // A power of two minus one is the size DPDK's ring stores exactly.
    (4 * u32::from(tx_descriptors))
        .max(4096)
        .next_power_of_two()
        - 1
}

pub struct Mempool {
    raw: *mut ffi::rte_mempool,
    data_room_size: u16,
}

// The pool is a thread-safe DPDK object (ring_mp_mc by default); the raw
// pointer itself has no Rust-side interior state we're racing on.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

#[derive(Debug)]
pub struct MempoolCreateError;

impl std::fmt::Display for MempoolCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rte_pktmbuf_pool_create returned NULL (see rte_errno)")
    }
}
impl std::error::Error for MempoolCreateError {}

impl Mempool {
    /// Creates a pool of `mbufs` mbufs, each with `data_room_size` bytes
    /// of packet buffer and a per-lcore cache of `cache_size` (at most
    /// [`MAX_CACHE_SIZE`]), on the given NUMA socket (`-1` for "any
    /// socket" / `SOCKET_ID_ANY`).
    ///
    /// Suggested values: [`DEFAULT_MBUF_DATA_ROOM_SIZE`] for
    /// `data_room_size`; a power of two minus one for `mbufs`, the size
    /// DPDK's ring stores exactly.
    ///
    /// Give a worker a pool of its own to build outgoing packets from,
    /// rather than the one its queue receives into, with
    /// [`transmit_mbufs`] mbufs and a cache of [`MAX_CACHE_SIZE`]. A
    /// pool's per-lcore cache hands back the mbuf freed last, which is
    /// still in the CPU's cache; but mbufs freed by other threads, or more
    /// of them than the per-lcore cache holds, come back through the
    /// pool's ring, oldest first. Received data is held for as long as the
    /// application keeps it and freed on its threads, so a pool that
    /// receives is always cycling through all of its mbufs, and a packet
    /// built from it is written into memory the CPU has not touched for a
    /// long time. Outgoing packets, by contrast, are freed by the driver
    /// on the worker's own lcore as soon as they are sent: kept apart, the
    /// same few stay in circulation, and stay warm.
    pub fn new(
        name: &str,
        mbufs: u32,
        cache_size: u32,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Self, MempoolCreateError> {
        let c_name = CString::new(name).map_err(|_| MempoolCreateError)?;
        // SAFETY: c_name lives for the duration of the call; DPDK copies
        // the name internally. priv_size=0 -- no per-mbuf private data.
        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                c_name.as_ptr(),
                mbufs,
                cache_size,
                0,
                data_room_size,
                socket_id,
            )
        };
        if raw.is_null() {
            return Err(MempoolCreateError);
        }
        Ok(Self {
            raw,
            data_room_size,
        })
    }

    pub fn as_raw(&self) -> *mut ffi::rte_mempool {
        self.raw
    }

    /// Bytes available after the headroom of a freshly reset mbuf.
    pub fn packet_capacity(&self) -> u16 {
        self.data_room_size
            .saturating_sub(ffi::RTE_PKTMBUF_HEADROOM as u16)
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        // DPDK has no general-purpose exported "destroy this mempool"
        // primitive that's safe to call from a hand-written shim without
        // tracking every outstanding mbuf; in practice EAL-managed
        // mempools live for the process lifetime, so intentionally leak
        // rather than risk a use-after-free of in-flight mbufs.
        self.raw = ptr::null_mut();
    }
}

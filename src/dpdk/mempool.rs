//! Safe wrapper around an `rte_mempool` used as a packet (mbuf) pool.

use std::ffi::CString;
use std::ptr;

use super::ffi;

/// `RTE_MBUF_DEFAULT_DATAROOM (2048) + RTE_PKTMBUF_HEADROOM (128)`, i.e.
/// `RTE_MBUF_DEFAULT_BUF_SIZE` -- the conventional per-mbuf buffer size used
/// throughout the DPDK examples, large enough for a standard 1500-byte MTU
/// frame plus headroom for prepending headers.
pub const DEFAULT_MBUF_DATA_ROOM_SIZE: u16 = 2048 + 128;

pub struct PktMbufPool {
    pub(super) raw: *mut ffi::rte_mempool,
}

// The pool is a thread-safe DPDK object (ring_mp_mc by default); the raw
// pointer itself has no Rust-side interior state we're racing on.
unsafe impl Send for PktMbufPool {}
unsafe impl Sync for PktMbufPool {}

#[derive(Debug)]
pub struct MempoolCreateError;

impl std::fmt::Display for MempoolCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rte_pktmbuf_pool_create returned NULL (see rte_errno)")
    }
}
impl std::error::Error for MempoolCreateError {}

impl PktMbufPool {
    /// Creates a pool of `n` mbufs, each with `data_room_size` bytes of
    /// packet buffer, on the given NUMA socket (`-1` for "any socket" /
    /// `SOCKET_ID_ANY`).
    pub fn create(
        name: &str,
        n: u32,
        cache_size: u32,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Self, MempoolCreateError> {
        let c_name = CString::new(name).expect("mempool name contained a NUL byte");
        // SAFETY: c_name lives for the duration of the call; DPDK copies
        // the name internally. priv_size=0 -- no per-mbuf private data.
        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                c_name.as_ptr(),
                n,
                cache_size,
                0,
                data_room_size,
                socket_id,
            )
        };
        if raw.is_null() {
            return Err(MempoolCreateError);
        }
        Ok(Self { raw })
    }

    pub fn as_raw(&self) -> *mut ffi::rte_mempool {
        self.raw
    }
}

impl Drop for PktMbufPool {
    fn drop(&mut self) {
        // DPDK has no general-purpose exported "destroy this mempool"
        // primitive that's safe to call from a hand-written shim without
        // tracking every outstanding mbuf; in practice EAL-managed
        // mempools live for the process lifetime, so intentionally leak
        // rather than risk a use-after-free of in-flight mbufs.
        self.raw = ptr::null_mut();
    }
}

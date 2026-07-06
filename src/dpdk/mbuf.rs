//! Safe wrapper around `*mut rte_mbuf`. All field access goes through the
//! `dpdk_shim_pktmbuf_*` accessors in `csrc/shim.c` -- see the note atop
//! `ffi.rs` for why `rte_mbuf` is treated as opaque here rather than a
//! hand-replicated `#[repr(C)]` struct.

use std::slice;

use super::ffi;
use super::mempool::PktMbufPool;

/// Owning handle to a single `rte_mbuf`. Freed via `rte_pktmbuf_free` on
/// drop unless ownership is explicitly handed off (e.g. to `tx_burst`,
/// which frees transmitted mbufs itself once the NIC is done with them).
pub struct Mbuf {
    raw: *mut ffi::rte_mbuf,
}

// An mbuf pointer is not aliased by other Rust code while this handle is
// alive (single-owner discipline enforced by this wrapper's API), so it's
// safe to move between threads.
unsafe impl Send for Mbuf {}

impl Mbuf {
    /// Takes ownership of a raw mbuf pointer received from DPDK (e.g. via
    /// `rx_burst` or `alloc`). Caller must not free/reuse the pointer
    /// afterward.
    ///
    /// # Safety
    /// `raw` must be a valid, uniquely-owned `rte_mbuf*` from this
    /// process's DPDK instance.
    pub unsafe fn from_raw(raw: *mut ffi::rte_mbuf) -> Self {
        debug_assert!(!raw.is_null());
        Self { raw }
    }

    pub fn alloc(pool: &PktMbufPool) -> Option<Self> {
        // SAFETY: pool.as_raw() is a valid, live mempool for the process
        // lifetime (see PktMbufPool::drop).
        let raw = unsafe { ffi::dpdk_shim_pktmbuf_alloc(pool.as_raw()) };
        if raw.is_null() {
            return None;
        }
        Some(Self { raw })
    }

    /// Consumes the handle and returns the raw pointer without freeing it,
    /// for handing off to `rte_eth_tx_burst` (which takes ownership and
    /// frees the mbuf once transmitted).
    pub fn into_raw(self) -> *mut ffi::rte_mbuf {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }

    pub fn as_raw(&self) -> *mut ffi::rte_mbuf {
        self.raw
    }

    pub fn pkt_len(&self) -> u32 {
        unsafe { ffi::dpdk_shim_pktmbuf_pkt_len(self.raw) }
    }

    pub fn data_len(&self) -> u16 {
        unsafe { ffi::dpdk_shim_pktmbuf_data_len(self.raw) }
    }

    /// Which port this mbuf was received on (meaningful for rx mbufs only).
    pub fn port(&self) -> u16 {
        unsafe { ffi::dpdk_shim_pktmbuf_port(self.raw) }
    }

    pub fn headroom(&self) -> u16 {
        unsafe { ffi::dpdk_shim_pktmbuf_headroom(self.raw) }
    }

    pub fn tailroom(&self) -> u16 {
        unsafe { ffi::dpdk_shim_pktmbuf_tailroom(self.raw) }
    }

    /// Read-only view of the single-segment packet data.
    ///
    /// Multi-segment (chained) mbufs are out of scope for this stack: rx
    /// mbuf pools are sized so a full frame fits in one segment, and this
    /// stack never receives jumbo frames that would force segmentation.
    pub fn data(&self) -> &[u8] {
        let ptr = unsafe { ffi::dpdk_shim_pktmbuf_data(self.raw) };
        let len = self.data_len() as usize;
        if ptr.is_null() || len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let ptr = unsafe { ffi::dpdk_shim_pktmbuf_data(self.raw) };
        let len = self.data_len() as usize;
        if ptr.is_null() || len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts_mut(ptr, len) }
    }

    /// Grows the packet by `len` bytes at the tail and returns a mutable
    /// view of the newly appended region. `None` if there isn't enough
    /// tailroom.
    pub fn append(&mut self, len: u16) -> Option<&mut [u8]> {
        let ptr = unsafe { ffi::dpdk_shim_pktmbuf_append(self.raw, len) };
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Grows the packet by `len` bytes at the head (for prepending a
    /// header) and returns a mutable view of the new region. `None` if
    /// there isn't enough headroom.
    pub fn prepend(&mut self, len: u16) -> Option<&mut [u8]> {
        let ptr = unsafe { ffi::dpdk_shim_pktmbuf_prepend(self.raw, len) };
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Resets the mbuf to an empty packet (data_off = headroom, len = 0)
    /// so a freshly allocated mbuf can be built up with `prepend`/`append`.
    pub fn reset(&mut self) {
        unsafe { ffi::dpdk_shim_pktmbuf_reset(self.raw) }
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe { ffi::dpdk_shim_pktmbuf_free(self.raw) }
    }
}

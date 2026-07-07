//! Safe wrapper around `*mut rte_mbuf`. Reads/writes the mbuf's real
//! `#[repr(C)]` fields (`data_off`, `data_len`, `pkt_len`, `buf_addr`, ...)
//! from the generated bindings, and calls DPDK's `static inline` pktmbuf
//! helpers (`rte_pktmbuf_alloc`/`free`/`append`/`prepend`/`reset`) directly.

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
        let raw = unsafe { ffi::rte_pktmbuf_alloc(pool.as_raw()) };
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
        // SAFETY: `raw` is a valid mbuf; `pkt_len` is a plain field.
        unsafe { (*self.raw).pkt_len }
    }

    pub fn data_len(&self) -> u16 {
        // SAFETY: as above.
        unsafe { (*self.raw).data_len }
    }

    /// Which port this mbuf was received on (meaningful for rx mbufs only).
    pub fn port(&self) -> u16 {
        // SAFETY: as above.
        unsafe { (*self.raw).port }
    }

    pub fn headroom(&self) -> u16 {
        // SAFETY: `raw` is valid; `rte_pktmbuf_headroom` only reads fields.
        unsafe { ffi::rte_pktmbuf_headroom(self.raw) }
    }

    pub fn tailroom(&self) -> u16 {
        // SAFETY: as above.
        unsafe { ffi::rte_pktmbuf_tailroom(self.raw) }
    }

    /// Pointer to the start of this segment's data (`rte_pktmbuf_mtod`,
    /// which is a C macro and so isn't wrapped: `buf_addr + data_off`).
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `raw` is a valid mbuf; the data region lives within the
        // mbuf's buffer.
        unsafe {
            (*self.raw)
                .buf_addr
                .cast::<u8>()
                .add((*self.raw).data_off as usize)
        }
    }

    /// Read-only view of the single-segment packet data.
    ///
    /// Multi-segment (chained) mbufs are out of scope for this stack: rx
    /// mbuf pools are sized so a full frame fits in one segment, and this
    /// stack never receives jumbo frames that would force segmentation.
    pub fn data(&self) -> &[u8] {
        let ptr = self.data_ptr();
        let len = self.data_len() as usize;
        if ptr.is_null() || len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let ptr = self.data_ptr();
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
        // SAFETY: `raw` is valid; `rte_pktmbuf_append` returns a pointer
        // into the mbuf's tail (or null if it doesn't fit).
        let ptr = unsafe { ffi::rte_pktmbuf_append(self.raw, len) }.cast::<u8>();
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Grows the packet by `len` bytes at the head (for prepending a
    /// header) and returns a mutable view of the new region. `None` if
    /// there isn't enough headroom.
    pub fn prepend(&mut self, len: u16) -> Option<&mut [u8]> {
        // SAFETY: as above, into the mbuf's headroom.
        let ptr = unsafe { ffi::rte_pktmbuf_prepend(self.raw, len) }.cast::<u8>();
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Resets the mbuf to an empty packet (data_off = headroom, len = 0)
    /// so a freshly allocated mbuf can be built up with `prepend`/`append`.
    pub fn reset(&mut self) {
        // SAFETY: `raw` is a valid, singly-owned mbuf.
        unsafe { ffi::rte_pktmbuf_reset(self.raw) }
    }

    /// The mbuf's offload flags (`ol_flags`), e.g. the RX checksum-result
    /// bits the NIC sets.
    pub fn ol_flags(&self) -> u64 {
        // SAFETY: `raw` is a valid mbuf; `ol_flags` is a plain field.
        unsafe { (*self.raw).ol_flags }
    }

    /// The NIC checked the IPv4 header checksum and it was wrong. (False
    /// when RX offload is off -- the flag reads UNKNOWN.)
    pub fn rx_ip_cksum_bad(&self) -> bool {
        self.ol_flags() & ffi::RTE_MBUF_F_RX_IP_CKSUM_MASK as u64
            == ffi::RTE_MBUF_F_RX_IP_CKSUM_BAD as u64
    }

    /// The NIC verified the IPv4 header checksum as correct, so software
    /// verification can be skipped.
    pub fn rx_ip_cksum_good(&self) -> bool {
        self.ol_flags() & ffi::RTE_MBUF_F_RX_IP_CKSUM_MASK as u64
            == ffi::RTE_MBUF_F_RX_IP_CKSUM_GOOD as u64
    }

    /// The NIC checked the L4 (TCP) checksum and it was wrong.
    pub fn rx_l4_cksum_bad(&self) -> bool {
        self.ol_flags() & ffi::RTE_MBUF_F_RX_L4_CKSUM_MASK as u64
            == ffi::RTE_MBUF_F_RX_L4_CKSUM_BAD as u64
    }

    /// The NIC verified the L4 (TCP) checksum as correct.
    pub fn rx_l4_cksum_good(&self) -> bool {
        self.ol_flags() & ffi::RTE_MBUF_F_RX_L4_CKSUM_MASK as u64
            == ffi::RTE_MBUF_F_RX_L4_CKSUM_GOOD as u64
    }

    /// Requests NIC TX checksum offload for an IPv4 + TCP packet: the
    /// device fills in the IPv4 header checksum and completes the TCP
    /// checksum. The caller must leave the IPv4 checksum field zero and put
    /// the TCP *pseudo-header* checksum in the TCP checksum field.
    ///
    /// `l2_len`/`l3_len` are the Ethernet and IPv4 header lengths, telling
    /// the NIC where each header starts.
    pub fn set_tx_ipv4_tcp_cksum(&mut self, l2_len: u16, l3_len: u16) {
        // SAFETY: `raw` is a valid, singly-owned mbuf; `ol_flags` is a
        // plain field and `tx_offload` is the u64 view of the offload
        // union (writing a `Copy` union field is sound).
        unsafe {
            (*self.raw).ol_flags |= ffi::RTE_MBUF_F_TX_IPV4
                | ffi::RTE_MBUF_F_TX_IP_CKSUM
                | ffi::RTE_MBUF_F_TX_TCP_CKSUM;
            // tx_offload bitfield: l2_len in bits [0,7), l3_len in [7,16).
            (*self.raw).__bindgen_anon_3.tx_offload =
                (l2_len as u64 & 0x7f) | ((l3_len as u64 & 0x1ff) << 7);
        }
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // SAFETY: `raw` is a valid, singly-owned mbuf; this is the sole
        // owner releasing it.
        unsafe { ffi::rte_pktmbuf_free(self.raw) }
    }
}

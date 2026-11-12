//! Safe wrapper around `*mut rte_mbuf`. Reads/writes the mbuf's real
//! `#[repr(C)]` fields (`data_off`, `data_len`, `pkt_len`, `buf_addr`, ...)
//! from the generated bindings, and calls DPDK's `static inline` pktmbuf
//! helpers (`rte_pktmbuf_alloc`/`free`/`append`/`prepend`/`reset`) directly.

use std::slice;

use bytes::Bytes;

use super::ffi;
use super::mempool::Mempool;

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

// A separate pool mbuf holds the shared owner record until the final external
// reference drops, including any indirect clones made by a driver.
#[repr(C)]
struct ExternalOwner {
    shared: ffi::rte_mbuf_ext_shared_info,
    bytes: Bytes,
    record_mbuf: *mut ffi::rte_mbuf,
}

unsafe extern "C" fn release_external(_addr: *mut std::ffi::c_void, opaque: *mut std::ffi::c_void) {
    // SAFETY: the final DPDK external-buffer reference invokes this once,
    // while the separately reserved record mbuf is still live.
    unsafe {
        let record = opaque.cast::<ExternalOwner>();
        let raw = (*record).record_mbuf;
        std::ptr::drop_in_place(record);
        ffi::rte_pktmbuf_free(raw);
    }
}

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

    pub fn alloc(pool: &Mempool) -> Option<Self> {
        // SAFETY: pool.as_raw() is a valid, live mempool for the process
        // lifetime (see PktMbufPool::drop).
        let raw = unsafe { ffi::rte_pktmbuf_alloc(pool.as_raw()) };
        if raw.is_null() {
            return None;
        }
        Some(Self { raw })
    }

    /// DMA-contiguous prefix of EAL-managed memory, capped by mbuf buf_len.
    /// Ordinary Rust heap memory is deliberately not treated as DMA mapped.
    pub(crate) fn dma_prefix(data: &[u8]) -> Option<(usize, u64)> {
        if data.is_empty() || !eal_memory_span().contains(&(data.as_ptr() as usize)) {
            return None;
        }
        unsafe {
            let ms = ffi::rte_mem_virt2memseg(data.as_ptr().cast(), std::ptr::null());
            if ms.is_null() || (*ms).iova == u64::MAX {
                return None;
            }
            let offset =
                (data.as_ptr() as usize).checked_sub((*ms).__bindgen_anon_1.addr as usize)?;
            let n = data
                .len()
                .min((*ms).len.checked_sub(offset)?)
                .min(u16::MAX as usize);
            if n == 0 {
                return None;
            }
            Some((n, (*ms).iova.checked_add(offset as u64)?))
        }
    }

    /// Attaches an immutable DMA-capable Bytes range without copying it.
    /// Returns None for heap memory or a range spanning DMA segments.
    /// Writable mbuf methods reject external storage to preserve Bytes immutability.
    pub fn from_external_bytes(pool: &Mempool, bytes: Bytes) -> Option<Self> {
        let (n, iova) = Self::dma_prefix(&bytes)?;
        if n != bytes.len() {
            return None;
        }
        let packet = Self::alloc(pool)?;
        let record = Self::alloc(pool)?;
        unsafe {
            let raw = packet.raw;
            let storage = (*record.raw).buf_addr.cast::<u8>();
            let padding = storage.align_offset(std::mem::align_of::<ExternalOwner>());
            if padding + std::mem::size_of::<ExternalOwner>() > (*record.raw).buf_len as usize {
                return None;
            }
            let owner = storage.add(padding).cast::<ExternalOwner>();
            let addr = bytes.as_ptr() as *mut std::ffi::c_void;
            owner.write(ExternalOwner {
                shared: ffi::rte_mbuf_ext_shared_info {
                    free_cb: Some(release_external),
                    fcb_opaque: owner.cast(),
                    refcnt: 1,
                },
                bytes,
                record_mbuf: record.into_raw(),
            });
            ffi::rte_pktmbuf_attach_extbuf(raw, addr, iova, n as u16, &mut (*owner).shared);
            (*raw).data_len = n as u16;
            (*raw).pkt_len = n as u32;
        }
        Some(packet)
    }

    fn is_external(&self) -> bool {
        self.ol_flags() & ffi::RTE_MBUF_F_EXTERNAL != 0
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

    /// First segment's data. Use `segments()` to visit a complete chained packet.
    pub fn data(&self) -> &[u8] {
        let ptr = self.data_ptr();
        let len = self.data_len() as usize;
        if ptr.is_null() || len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    /// Borrow every segment without flattening the packet.
    pub fn segments(&self) -> impl Iterator<Item = &[u8]> {
        let mut next = self.raw;
        std::iter::from_fn(move || {
            if next.is_null() {
                return None;
            }
            // SAFETY: each linked segment belongs to this live packet.
            unsafe {
                let segment = &*next;
                next = segment.next;
                Some(slice::from_raw_parts(
                    segment.buf_addr.cast::<u8>().add(segment.data_off as usize),
                    segment.data_len as usize,
                ))
            }
        })
    }

    /// Internet checksum sum over a byte range, carrying odd bytes across segments.
    pub(crate) fn checksum_sum(&self, start: usize, len: usize, mut sum: u32) -> u32 {
        let mut skip = start;
        let mut remaining = len;
        let mut high = None;
        for segment in self.segments() {
            if skip >= segment.len() {
                skip -= segment.len();
                continue;
            }
            let n = remaining.min(segment.len() - skip);
            for &byte in &segment[skip..skip + n] {
                if let Some(first) = high.take() {
                    sum += u16::from_be_bytes([first, byte]) as u32;
                } else {
                    high = Some(byte);
                }
            }
            remaining -= n;
            skip = 0;
            if remaining == 0 {
                break;
            }
        }
        if let Some(first) = high {
            sum += (first as u32) << 8;
        }
        sum
    }

    /// Transfers a tail chain into this packet. Failure returns ownership.
    pub fn chain(&mut self, tail: Mbuf) -> Result<(), Mbuf> {
        // SAFETY: the two owned, disjoint chains are live. DPDK only links on success.
        if unsafe { ffi::rte_pktmbuf_chain(self.raw, tail.raw) } != 0 {
            return Err(tail);
        }
        std::mem::forget(tail);
        Ok(())
    }

    /// Detaches each segment, yielding independently owned zero-copy views.
    pub fn into_segments(self) -> impl Iterator<Item = Mbuf> {
        let mut remaining = Some(self);
        std::iter::from_fn(move || {
            let packet = remaining.take()?;
            unsafe {
                let raw = packet.raw;
                let next = (*raw).next;
                (*raw).next = std::ptr::null_mut();
                (*raw).nb_segs = 1;
                (*raw).pkt_len = u32::from((*raw).data_len);
                if !next.is_null() {
                    remaining = Some(Mbuf::from_raw(next));
                }
            }
            Some(packet)
        })
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        assert!(!self.is_external(), "external Bytes payload is immutable");
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
        if self.is_external() {
            return None;
        }
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
        if self.is_external() {
            return None;
        }
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
        unsafe {
            let tail = (*self.raw).next;
            (*self.raw).next = std::ptr::null_mut();
            if !tail.is_null() {
                ffi::rte_pktmbuf_free(tail);
            }
            if self.is_external() {
                ffi::rte_pktmbuf_detach(self.raw);
            }
            ffi::rte_pktmbuf_reset(self.raw);
        }
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

    /// Converts this mbuf into a [`Bytes`] that *owns* it: the returned
    /// `Bytes` views the packet data in place (zero-copy) and
    /// `rte_pktmbuf_free`s the mbuf when the last reference drops. Slices of
    /// it (`slice`/`slice_ref`/`split_to`) share the refcount, so a payload
    /// carved out of a frame keeps the mbuf alive without ever copying.
    ///
    /// Cross-thread notes: the last reference may drop on a different thread
    /// than the RX lcore (e.g. the application thread). That's safe -- the
    /// pool is created with `rte_pktmbuf_pool_create`, whose default mempool
    /// ops (`ring_mp_mc`) are multi-producer/multi-consumer, and per-lcore
    /// caches are only touched by registered EAL lcores.
    ///
    /// Trade-off: the whole mbuf (data room ~2KB) stays pinned until the
    /// last `Bytes` reference drops, so long-held small payloads hold more
    /// pool memory than a copy would.
    pub fn into_bytes(self) -> Bytes {
        assert_eq!(
            self.pkt_len(),
            self.data_len() as u32,
            "use into_segments() to convert chained packets without truncation"
        );
        Bytes::from_owner(self)
    }

    /// Marks an IPv4/TCP super-packet for segmentation by the device.
    pub fn set_tx_tso(&mut self, tcp_len: u16, mss: u16) {
        self.set_tx_ipv4_tcp_cksum(14, 20);
        unsafe {
            (*self.raw).ol_flags |= ffi::RTE_MBUF_F_TX_TCP_SEG;
            (*self.raw).__bindgen_anon_3.tx_offload |=
                ((tcp_len as u64) << 16) | ((mss as u64) << 24);
        }
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

/// Address span covering every EAL memory segment list, read once.
///
/// `rte_mem_virt2memseg` walks the segment lists on every call, which is
/// wasted work for the common transmit payload: ordinary heap memory that
/// is in none of them. The lists' address ranges are reserved when EAL
/// starts, so one span check rejects heap pointers without the walk.
/// Memory registered with EAL later falls outside the span and is copied
/// instead of attached, which is slower but correct.
fn eal_memory_span() -> &'static std::ops::Range<usize> {
    static SPAN: std::sync::OnceLock<std::ops::Range<usize>> = std::sync::OnceLock::new();
    unsafe extern "C" fn widen(
        list: *const ffi::rte_memseg_list,
        arg: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        // SAFETY: EAL passes a live list, and `arg` is the `Range` below.
        unsafe {
            let span = &mut *arg.cast::<std::ops::Range<usize>>();
            let start = (*list).__bindgen_anon_1.base_va as usize;
            let end = start.saturating_add((*list).len);
            if start != 0 {
                span.start = span.start.min(start);
                span.end = span.end.max(end);
            }
        }
        0
    }
    SPAN.get_or_init(|| {
        let mut span = usize::MAX..0;
        // SAFETY: the walk holds EAL's memory lock and only reads.
        unsafe { ffi::rte_memseg_list_walk(Some(widen), (&raw mut span).cast()) };
        span
    })
}

/// The view [`Mbuf::into_bytes`] hands to `Bytes::from_owner`: the packet
/// data region. The pointer is into DPDK memory and doesn't move when the
/// `Mbuf` handle itself is moved.
impl AsRef<[u8]> for Mbuf {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // SAFETY: `raw` is a valid, singly-owned mbuf; this is the sole
        // owner releasing it.
        unsafe { ffi::rte_pktmbuf_free(self.raw) }
    }
}

//! Receive-side reassembly: buffers out-of-order segments and delivers
//! in-order bytes to the application as gaps get filled.
//!
//! Zero-copy: received payloads arrive as refcounted slices of the RX mbuf
//! (see [`Mbuf::into_bytes`](crate::dpdk::Mbuf::into_bytes)) and move through
//! the ready queue and out to the application by refcount -- the payload is
//! never copied. The flip side is that a buffered or application-held chunk
//! pins its whole mbuf (data room ~2KB) until dropped, so pool sizing must
//! cover the receive window plus whatever the application retains.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use super::seq::Seq;

#[derive(Default)]
pub struct ReassemblyBuffer {
    /// Out-of-order segments, keyed by starting sequence number.
    out_of_order: BTreeMap<u32, Bytes>,
    /// In-order chunks ready for the application to `recv()`.
    ready: VecDeque<Bytes>,
    /// Total bytes across `ready` (kept incrementally to avoid summing).
    ready_len: usize,
}

impl ReassemblyBuffer {
    pub fn readable_len(&self) -> usize {
        self.ready_len
    }

    /// Removes up to `max_len` in-order bytes. Returns a `Bytes` sharing
    /// the reassembly buffer's storage (zero-copy slice of the front
    /// chunk); callers loop to drain more.
    pub fn read(&mut self, max_len: usize) -> Bytes {
        let Some(front) = self.ready.front_mut() else {
            return Bytes::new();
        };
        let n = max_len.min(front.len());
        let out = front.split_to(n);
        if front.is_empty() {
            self.ready.pop_front();
        }
        self.ready_len -= n;
        out
    }

    /// Inserts a received segment `[seq, seq+data.len())` given the
    /// connection's current `rcv_nxt`. Returns the new `rcv_nxt` after
    /// accounting for this segment and any out-of-order segments it makes
    /// contiguous.
    ///
    /// Segments (or portions of them) at or before `rcv_nxt` are
    /// duplicates and dropped; segments strictly after `rcv_nxt` are
    /// buffered until the gap closes. `data` is an owned, mbuf-backed
    /// `Bytes` and is stored (or prefix-trimmed via an O(1) slice) by
    /// refcount -- no copy.
    pub fn insert(&mut self, seq: Seq, data: Bytes, rcv_nxt: Seq) -> Seq {
        if data.is_empty() {
            return rcv_nxt;
        }
        let end = seq + data.len() as u32;
        if end.leq(rcv_nxt) {
            return rcv_nxt; // entirely duplicate
        }

        let (seq, data): (Seq, Bytes) = if seq.lt(rcv_nxt) {
            // Partially duplicate: trim the already-delivered prefix.
            let skip = rcv_nxt.distance(seq).unsigned_abs() as usize;
            (rcv_nxt, data.slice(skip..))
        } else {
            (seq, data)
        };

        let mut rcv_nxt = rcv_nxt;
        if seq == rcv_nxt {
            let len = data.len() as u32;
            self.push_ready(data);
            rcv_nxt = rcv_nxt + len;
            rcv_nxt = self.drain_contiguous(rcv_nxt);
        } else {
            // A duplicate out-of-order retransmit keeps the copy already
            // buffered; the incoming duplicate is dropped (freeing its mbuf).
            self.out_of_order.entry(seq.0).or_insert(data);
        }
        rcv_nxt
    }

    fn push_ready(&mut self, chunk: Bytes) {
        self.ready_len += chunk.len();
        self.ready.push_back(chunk);
    }

    /// After advancing `rcv_nxt`, pulls any now-contiguous buffered
    /// segments into `ready`, repeating until the next gap. Buffered
    /// chunks move into `ready` by refcount (only a possible prefix trim,
    /// which is an O(1) slice).
    fn drain_contiguous(&mut self, mut rcv_nxt: Seq) -> Seq {
        while let Some((&start, _)) = self.out_of_order.first_key_value() {
            let start_seq = Seq::new(start);
            if start_seq.gt(rcv_nxt) {
                break; // still a gap
            }
            let data = self.out_of_order.remove(&start).unwrap();
            let end = start_seq + data.len() as u32;
            if end.leq(rcv_nxt) {
                continue; // fully-duplicate leftover, drop
            }
            let skip = rcv_nxt.distance(start_seq).unsigned_abs() as usize;
            self.push_ready(data.slice(skip..));
            rcv_nxt = end;
        }
        rcv_nxt
    }

    pub fn has_out_of_order(&self) -> bool {
        !self.out_of_order.is_empty()
    }
}

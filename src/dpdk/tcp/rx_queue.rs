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
use crate::dpdk::net::tcp::{MAX_SACK_BLOCKS, SackBlocks};

#[derive(Default)]
pub struct ReassemblyBuffer {
    /// TCP sequence order, including wraparound. Accepted segments are
    /// within one receive window (less than half the sequence space).
    out_of_order: BTreeMap<Seq, Bytes>,
    /// In-order chunks ready for the application to `recv()`.
    ready: VecDeque<Bytes>,
    /// Total bytes across `ready` (kept incrementally to avoid summing).
    ready_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_across_wrap_with_a_future_low_key() {
        let mut buffer = ReassemblyBuffer::default();
        let start = Seq::new(u32::MAX - 9);
        buffer.insert(start + 5, Bytes::from_static(b"fghij"), start);
        buffer.insert(Seq::new(5), Bytes::from_static(b"pqrst"), start);
        let next = buffer.insert(start, Bytes::from_static(b"abcde"), start);
        assert_eq!(next, Seq::new(0));
        let next = buffer.insert(next, Bytes::from_static(b"klmno"), next);
        assert_eq!(next, Seq::new(10));
        assert!(!buffer.has_out_of_order());
        let mut data = Vec::new();
        while buffer.readable_len() != 0 {
            data.extend_from_slice(&buffer.read(100));
        }
        assert_eq!(data, b"abcdefghijklmnopqrst");
    }

    #[test]
    fn sack_blocks_merge_ranges_and_lead_with_the_latest_arrival() {
        let mut buffer = ReassemblyBuffer::default();
        let next = Seq::new(u32::MAX - 99);
        assert!(buffer.sack_blocks(None).is_empty());
        // Six islands of 100 bytes, 200 apart, starting 100 past rcv_nxt;
        // the second is two abutting segments and one overlapping them.
        for island in 0..6u32 {
            let start = next + 100 + island * 200;
            buffer.insert(start, Bytes::from(vec![0; 50]), next);
            buffer.insert(start + 50, Bytes::from(vec![0; 50]), next);
            buffer.insert(start + 25, Bytes::from(vec![0; 50]), next);
        }
        let block = |island: u32| {
            let start = next + 100 + island * 200;
            (start.0, (start + 100).0)
        };
        // No latest arrival known: the lowest ranges.
        assert_eq!(
            buffer.sack_blocks(None).as_slice(),
            [block(0), block(1), block(2), block(3)]
        );
        // The latest arrival's range leads, wherever it lies.
        assert_eq!(
            buffer.sack_blocks(Some(next + 100 + 5 * 200 + 60)).as_slice(),
            [block(5), block(0), block(1), block(2)]
        );
        assert_eq!(
            buffer.sack_blocks(Some(next + 100 + 200)).as_slice(),
            [block(1), block(0), block(2), block(3)]
        );
        // Filling the first gap delivers the first island; it is no
        // longer reported.
        let advanced = buffer.insert(next, Bytes::from(vec![0; 100]), next);
        assert_eq!(advanced, next + 200);
        assert_eq!(
            buffer.sack_blocks(None).as_slice(),
            [block(1), block(2), block(3), block(4)]
        );
    }

    #[test]
    fn trims_overlapping_segments_across_wrap() {
        let mut buffer = ReassemblyBuffer::default();
        let start = Seq::new(u32::MAX - 3);
        buffer.insert(start + 2, Bytes::from_static(b"cdefgh"), start);
        buffer.insert(Seq::new(3), Bytes::from_static(b"hijk"), start);
        let next = buffer.insert(start, Bytes::from_static(b"abcde"), start);
        assert_eq!(next, Seq::new(7));
        assert!(!buffer.has_out_of_order());
        let mut data = Vec::new();
        while buffer.readable_len() != 0 {
            data.extend_from_slice(&buffer.read(100));
        }
        assert_eq!(data, b"abcdefghijk");
    }
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
            self.out_of_order.entry(seq).or_insert(data);
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
            let start_seq = start;
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

    /// The buffered out-of-order ranges as SACK blocks (RFC 2018 §4): the
    /// block containing `recent`, the segment that triggered this ACK,
    /// first; then the others, lowest first, as many as fit.
    pub fn sack_blocks(&self, recent: Option<Seq>) -> SackBlocks {
        let mut first: Option<(Seq, Seq)> = None;
        let mut rest = [(Seq::new(0), Seq::new(0)); MAX_SACK_BLOCKS];
        let mut rest_len = 0;
        let mut current: Option<(Seq, Seq)> = None;
        let mut entries = self.out_of_order.iter();
        loop {
            let next = entries
                .next()
                .map(|(&start, data)| (start, start + data.len() as u32));
            // Buffered segments can abut or overlap: report their union.
            if let (Some((start, end)), Some((_, current_end))) = (next, current.as_mut())
                && start.leq(*current_end)
            {
                if end.gt(*current_end) {
                    *current_end = end;
                }
                continue;
            }
            if let Some(block) = current {
                let holds_recent = recent.is_some_and(|seq| seq.in_range(block.0, block.1));
                if holds_recent && first.is_none() {
                    first = Some(block);
                } else if rest_len < rest.len() {
                    rest[rest_len] = block;
                    rest_len += 1;
                }
            }
            current = next;
            let searching = recent.is_some() && first.is_none();
            if next.is_none() || (rest_len == rest.len() && !searching) {
                break;
            }
        }
        let mut blocks = SackBlocks::default();
        for (left, right) in first.into_iter().chain(rest[..rest_len].iter().copied()) {
            blocks.push(left.0, right.0);
        }
        blocks
    }
}

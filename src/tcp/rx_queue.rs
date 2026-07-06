//! Receive-side reassembly: buffers out-of-order segments and delivers
//! in-order bytes to the application as gaps get filled.

use std::collections::{BTreeMap, VecDeque};

use super::seq::Seq;

#[derive(Default)]
pub struct ReassemblyBuffer {
    /// Out-of-order segments, keyed by starting sequence number.
    out_of_order: BTreeMap<u32, Vec<u8>>,
    /// In-order bytes ready for the application to `recv()`.
    ready: VecDeque<u8>,
}

impl ReassemblyBuffer {
    pub fn readable_len(&self) -> usize {
        self.ready.len()
    }

    pub fn read(&mut self, max_len: usize) -> Vec<u8> {
        let n = max_len.min(self.ready.len());
        self.ready.drain(..n).collect()
    }

    /// Inserts a received segment `[seq, seq+data.len())` given the
    /// connection's current `rcv_nxt`. Returns the new `rcv_nxt` after
    /// accounting for this segment and any out-of-order segments it makes
    /// contiguous.
    ///
    /// Segments (or portions of them) at or before `rcv_nxt` are
    /// duplicates and dropped; segments strictly after `rcv_nxt` are
    /// buffered until the gap closes.
    pub fn insert(&mut self, seq: Seq, data: &[u8], rcv_nxt: Seq) -> Seq {
        if data.is_empty() {
            return rcv_nxt;
        }
        let end = seq + data.len() as u32;
        if end.leq(rcv_nxt) {
            return rcv_nxt; // entirely duplicate
        }

        let (seq, data): (Seq, &[u8]) = if seq.lt(rcv_nxt) {
            // Partially duplicate: trim the already-delivered prefix.
            let skip = rcv_nxt.distance(seq).unsigned_abs() as usize;
            (rcv_nxt, &data[skip..])
        } else {
            (seq, data)
        };

        let mut rcv_nxt = rcv_nxt;
        if seq == rcv_nxt {
            self.ready.extend(data.iter().copied());
            rcv_nxt = rcv_nxt + data.len() as u32;
            rcv_nxt = self.drain_contiguous(rcv_nxt);
        } else {
            self.out_of_order
                .entry(seq.0)
                .or_insert_with(|| data.to_vec());
        }
        rcv_nxt
    }

    /// After advancing `rcv_nxt`, pulls any now-contiguous buffered
    /// segments into `ready`, repeating until the next gap.
    fn drain_contiguous(&mut self, mut rcv_nxt: Seq) -> Seq {
        loop {
            let Some((&start, _)) = self.out_of_order.first_key_value() else {
                break;
            };
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
            self.ready.extend(data[skip..].iter().copied());
            rcv_nxt = end;
        }
        rcv_nxt
    }

    pub fn has_out_of_order(&self) -> bool {
        !self.out_of_order.is_empty()
    }
}

//! Outgoing application data waiting to be segmented and sent. Distinct
//! from `rto::RetransmitQueue`, which holds data that has already been
//! sent once and is waiting to be acked.
//!
//! Data is held as a queue of `Bytes` chunks (one per application write)
//! rather than a `VecDeque<u8>`, so buffering a write is a move and
//! forming a segment is usually an O(1) refcounted split rather than a
//! byte-by-byte copy.

use std::collections::VecDeque;

use bytes::{Buf, Bytes, BytesMut};

#[derive(Default)]
pub struct SendBuffer {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl SendBuffer {
    pub fn push(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        self.len += data.len();
        self.chunks.push_back(data);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Removes up to `max_len` bytes from the front of the buffer to form
    /// the next outgoing segment. The common case (the front chunk alone
    /// covers the segment) is a zero-copy `Bytes::split_to`; only when a
    /// segment must span multiple queued writes is a coalescing copy
    /// taken, which keeps segments packed toward the MSS.
    pub fn take(&mut self, max_len: usize) -> Bytes {
        let n = max_len.min(self.len);
        if n == 0 {
            return Bytes::new();
        }
        self.len -= n;

        // Fast path: the entire segment comes from the front chunk.
        let front = self.chunks.front_mut().expect("len > 0 implies a chunk");
        if front.len() > n {
            return front.split_to(n);
        }
        if front.len() == n {
            return self.chunks.pop_front().unwrap();
        }

        // Slow path: coalesce successive chunks up to `n` bytes.
        let mut out = BytesMut::with_capacity(n);
        while out.len() < n {
            let need = n - out.len();
            let chunk = self.chunks.front_mut().expect("accounting keeps chunks in sync");
            if chunk.len() <= need {
                out.extend_from_slice(chunk);
                self.chunks.pop_front();
            } else {
                out.extend_from_slice(&chunk[..need]);
                chunk.advance(need);
            }
        }
        out.freeze()
    }
}

//! Outgoing application data waiting to be segmented and sent. Distinct
//! from `rto::RetransmitQueue`, which holds data that has already been
//! sent once and is waiting to be acked.
//!
//! Data is held as a queue of `Bytes` chunks (one per application write)
//! rather than a `VecDeque<u8>`, so buffering a write is a move and
//! forming a segment retains shared slices rather than copying payloads.

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;

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

    /// Removes up to max_len bytes as shared slices, without coalescing.
    /// Common fragment lists fit inline; overflow stores only shared metadata.
    pub fn take(&mut self, max_len: usize) -> Payload {
        let mut out = Payload::default();
        let mut remaining = max_len.min(self.len);
        let mut overflow = Vec::new();
        while remaining > 0 {
            let front = self.chunks.front_mut().unwrap();
            let n = remaining.min(front.len());
            let chunk = if n == front.len() {
                self.chunks.pop_front().unwrap()
            } else {
                front.split_to(n)
            };
            if out.count < INLINE_FRAGMENTS {
                out.chunks[out.count] = chunk;
                out.count += 1;
            } else {
                overflow.push(chunk);
            }
            out.len += n;
            self.len -= n;
            remaining -= n;
        }
        if !overflow.is_empty() {
            out.overflow = Some(overflow.into());
        }
        out
    }
}

const INLINE_FRAGMENTS: usize = 8;

/// Shared payload slices retained for transmission and retransmission.
/// Eight fragments fit inline; unusually fragmented segments share a
/// metadata allocation without copying payload bytes or shortening packets.
#[derive(Clone, Debug)]
pub struct Payload {
    chunks: [Bytes; INLINE_FRAGMENTS],
    count: usize,
    overflow: Option<Arc<[Bytes]>>,
    len: usize,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            chunks: std::array::from_fn(|_| Bytes::new()),
            count: 0,
            overflow: None,
            len: 0,
        }
    }
}

impl From<Bytes> for Payload {
    fn from(bytes: Bytes) -> Self {
        let mut out = Self::default();
        if !bytes.is_empty() {
            out.len = bytes.len();
            out.count = 1;
            out.chunks[0] = bytes;
        }
        out
    }
}

impl Payload {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn chunks(&self) -> impl Iterator<Item = &Bytes> {
        self.chunks[..self.count]
            .iter()
            .chain(self.overflow.as_deref().unwrap_or(&[]).iter())
    }
    pub fn copy_to(&self, out: &mut [u8]) {
        assert_eq!(out.len(), self.len);
        let mut offset = 0;
        for chunk in self.chunks() {
            out[offset..offset + chunk.len()].copy_from_slice(chunk);
            offset += chunk.len();
        }
    }
}

impl PartialEq<[u8]> for Payload {
    fn eq(&self, other: &[u8]) -> bool {
        self.len == other.len() && self.chunks().flat_map(|b| b.iter()).eq(other.iter())
    }
}

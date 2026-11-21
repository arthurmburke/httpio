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

    /// The first `max_len` bytes as shared slices, left in the buffer:
    /// what [`take`](Self::take) would remove, fragment for fragment.
    pub fn peek(&self, max_len: usize) -> Payload {
        let len = max_len.min(self.len);
        // (chunk, bytes of it within the first `len`), front to back.
        let parts = || {
            let mut remaining = len;
            self.chunks.iter().map_while(move |chunk| {
                if remaining == 0 {
                    return None;
                }
                let n = remaining.min(chunk.len());
                remaining -= n;
                Some((chunk, n))
            })
        };
        let count = parts().count();
        let mut out = Payload::default();
        if count > INLINE_FRAGMENTS {
            let rest: Vec<Bytes> = parts()
                .skip(INLINE_FRAGMENTS)
                .map(|(chunk, n)| chunk.slice(..n))
                .collect();
            out.overflow = Some(Arc::from(rest));
        }
        for (i, (chunk, n)) in parts().take(INLINE_FRAGMENTS).enumerate() {
            out.chunks[i] = chunk.slice(..n);
            out.count = i + 1;
        }
        out.len = len;
        out
    }

    /// Removes up to max_len bytes as shared slices, without coalescing.
    /// Common fragment lists fit inline; overflow stores only shared metadata.
    pub fn take(&mut self, max_len: usize) -> Payload {
        let mut out = Payload::default();
        let mut remaining = max_len.min(self.len);
        let mut overflow_index = 0;
        while remaining > 0 {
            if out.count == INLINE_FRAGMENTS && out.overflow.is_none() {
                let mut bytes_left = remaining;
                let count = self
                    .chunks
                    .iter()
                    .take_while(|chunk| {
                        if bytes_left == 0 {
                            return false;
                        }
                        bytes_left = bytes_left.saturating_sub(chunk.len());
                        true
                    })
                    .count();
                let mut storage = Arc::<[Bytes]>::new_uninit_slice(count);
                for slot in Arc::get_mut(&mut storage).unwrap() {
                    slot.write(Bytes::new());
                }
                // SAFETY: every element was initialized above. Filling the
                // slots below uses ordinary assignments with normal drop semantics.
                out.overflow = Some(unsafe { storage.assume_init() });
            }
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
                Arc::get_mut(out.overflow.as_mut().unwrap()).unwrap()[overflow_index] = chunk;
                overflow_index += 1;
            }
            out.len += n;
            self.len -= n;
            remaining -= n;
        }
        out
    }
}

const INLINE_FRAGMENTS: usize = 2;

/// Shared payload slices retained for transmission and retransmission.
/// Two fragments fit inline, which covers a segment cut from one write or
/// straddling two; more fragmented segments share a metadata allocation
/// without copying payload bytes or shortening packets. The inline count
/// is kept small because every segment's `Payload` is moved several times
/// on its way to the port and cloned into the retransmission queue.
#[derive(Debug)]
pub struct Payload {
    chunks: [Bytes; INLINE_FRAGMENTS],
    count: usize,
    overflow: Option<Arc<[Bytes]>>,
    len: usize,
}

impl Clone for Payload {
    /// Clones only the fragments in use. Every segment is cloned once into
    /// the retransmission queue, and the derived impl would make an
    /// indirect call for each of the unused inline slots too.
    fn clone(&self) -> Self {
        Self {
            chunks: std::array::from_fn(|i| {
                if i < self.count {
                    self.chunks[i].clone()
                } else {
                    Bytes::new()
                }
            }),
            count: self.count,
            overflow: self.overflow.clone(),
            len: self.len,
        }
    }
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
    /// A payload of no bytes, to borrow where a segment carries none.
    pub fn empty() -> &'static Self {
        static EMPTY: Payload = Payload {
            chunks: [Bytes::new(), Bytes::new()],
            count: 0,
            overflow: None,
            len: 0,
        };
        &EMPTY
    }

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
    /// Shares only the requested byte range, preserving fragment boundaries.
    pub fn slice(&self, start: usize, len: usize) -> Self {
        assert!(start <= self.len && len <= self.len - start);
        let selected = || {
            let mut skip = start;
            let mut remaining = len;
            self.chunks().filter_map(move |chunk| {
                if skip >= chunk.len() {
                    skip -= chunk.len();
                    return None;
                }
                let n = remaining.min(chunk.len() - skip);
                if n == 0 {
                    return None;
                }
                let part = chunk.slice(skip..skip + n);
                skip = 0;
                remaining -= n;
                Some(part)
            })
        };
        let count = selected().count();
        let mut out = Self::default();
        if count > INLINE_FRAGMENTS {
            let mut storage = Arc::<[Bytes]>::new_uninit_slice(count - INLINE_FRAGMENTS);
            for slot in Arc::get_mut(&mut storage).unwrap() {
                slot.write(Bytes::new());
            }
            // SAFETY: all elements initialized above before normal assignments below.
            out.overflow = Some(unsafe { storage.assume_init() });
        }
        for (i, chunk) in selected().enumerate() {
            if i < INLINE_FRAGMENTS {
                out.chunks[i] = chunk;
                out.count += 1;
            } else {
                Arc::get_mut(out.overflow.as_mut().unwrap()).unwrap()[i - INLINE_FRAGMENTS] = chunk;
            }
        }
        out.len = len;
        out
    }

    /// Checksum over fragmented payload, preserving odd-byte boundaries.
    pub fn checksum_sum(&self, mut sum: u32) -> u16 {
        // A fragment of odd length leaves its last byte as the high half
        // of a word that the next fragment's first byte completes.
        let mut high: Option<u8> = None;
        for chunk in self.chunks() {
            let mut data = &chunk[..];
            if let Some(first) = high
                && let Some((&second, rest)) = data.split_first()
            {
                sum += u16::from_be_bytes([first, second]) as u32;
                high = None;
                data = rest;
            }
            let even = data.len() & !1;
            sum = crate::dpdk::net::checksum::sum16(&data[..even], sum);
            if let Some(&last) = data.get(even) {
                high = Some(last);
            }
        }
        if let Some(first) = high {
            sum += (first as u32) << 8;
        }
        crate::dpdk::net::checksum::fold(sum)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_shares_what_take_would_remove() {
        for fragments in [1usize, 2, 3, 6] {
            let chunks: Vec<Bytes> = (0..fragments)
                .map(|i| Bytes::from(vec![i as u8 + 1; 10 + i]))
                .collect();
            let total: usize = chunks.iter().map(Bytes::len).sum();
            for len in [0, 1, 10, 11, total - 1, total, total + 5] {
                let mut buffer = SendBuffer::default();
                for chunk in &chunks {
                    buffer.push(chunk.clone());
                }
                let peeked = buffer.peek(len);
                assert_eq!(buffer.len(), total, "peeking removes nothing");
                let taken = buffer.take(len);
                assert_eq!(peeked.len(), taken.len());
                assert_eq!(peeked.len(), len.min(total));
                // The same fragments of the same memory, in the same order.
                let fragments = |payload: &Payload| -> Vec<(*const u8, usize)> {
                    payload.chunks().map(|b| (b.as_ptr(), b.len())).collect()
                };
                assert_eq!(fragments(&peeked), fragments(&taken));
                assert_eq!(buffer.len(), total - taken.len());
            }
        }
    }
}

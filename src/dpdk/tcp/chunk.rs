use std::ops::RangeBounds;

use bytes::{Buf, Bytes};

use crate::dpdk::mbuf::{Mbuf, MbufSlice, resolve};

/// One contiguous run of received bytes: a view into the packet buffer it
/// arrived in, or `Bytes` for data that was never in one (TLS plaintext,
/// bytes from a caller driving TCP directly).
///
/// Cloning, slicing and splitting share the backing storage and never
/// allocate for a packet buffer, whose own reference count is the shared
/// one (see [`MbufSlice`]). Holding a chunk, or any part of one, keeps its
/// packet buffer out of the pool.
#[derive(Clone)]
pub enum Chunk {
    Packet(MbufSlice),
    Bytes(Bytes),
}

impl Chunk {
    /// An empty chunk, backed by nothing.
    pub const fn new() -> Self {
        Self::Bytes(Bytes::new())
    }

    /// `len` bytes at `start` in the data of `mbuf`, a single segment.
    pub fn packet(mbuf: Mbuf, start: usize, len: usize) -> Self {
        Self::Packet(MbufSlice::new(mbuf, start, len))
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Packet(packet) => packet.len(),
            Self::Bytes(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Packet(packet) => packet.as_slice(),
            Self::Bytes(bytes) => bytes,
        }
    }

    /// Drops the first `n` bytes from the view.
    ///
    /// # Panics
    /// If `n > self.len()`.
    pub fn advance(&mut self, n: usize) {
        match self {
            Self::Packet(packet) => packet.advance(n),
            Self::Bytes(bytes) => bytes.advance(n),
        }
    }

    /// Keeps the first `len` bytes; no effect if the chunk is shorter.
    pub fn truncate(&mut self, len: usize) {
        match self {
            Self::Packet(packet) => packet.truncate(len),
            Self::Bytes(bytes) => bytes.truncate(len),
        }
    }

    /// Empties the chunk, letting go of its backing storage.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Splits off and returns the first `at` bytes, leaving the rest. The
    /// two share the backing storage; taking everything or nothing moves
    /// it without touching the reference count.
    ///
    /// # Panics
    /// If `at > self.len()`.
    pub fn split_to(&mut self, at: usize) -> Self {
        if at == self.len() {
            return std::mem::take(self);
        }
        if at == 0 {
            return Self::new();
        }
        match self {
            Self::Packet(packet) => Self::Packet(packet.split_to(at)),
            Self::Bytes(bytes) => Self::Bytes(bytes.split_to(at)),
        }
    }

    /// The part of the chunk in `range`, sharing the backing storage.
    ///
    /// # Panics
    /// If `range` is out of bounds.
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        let (start, end) = resolve(range, self.len());
        if start == end {
            return Self::new();
        }
        match self {
            Self::Packet(packet) => Self::Packet(packet.slice(start..end)),
            Self::Bytes(bytes) => Self::Bytes(bytes.slice(start..end)),
        }
    }

    /// Converts to shared [`Bytes`]. For a packet buffer this allocates the
    /// `Bytes` owner (once; slices of the result share it), so it belongs
    /// where data is handed to code that needs `Bytes`, not on the way
    /// there.
    pub fn into_bytes(self) -> Bytes {
        match self {
            Self::Packet(packet) => packet.into_bytes(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

impl Default for Chunk {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Bytes> for Chunk {
    fn from(bytes: Bytes) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<MbufSlice> for Chunk {
    fn from(packet: MbufSlice) -> Self {
        Self::Packet(packet)
    }
}

impl std::ops::Deref for Chunk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backing = match self {
            Self::Packet(_) => "Packet",
            Self::Bytes(_) => "Bytes",
        };
        f.debug_struct("Chunk")
            .field("backing", &backing)
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_and_slicing_share_the_backing_bytes() {
        let whole = Bytes::from_static(b"head\r\nbody-bytes");
        let mut chunk = Chunk::from(whole.clone());
        let head = chunk.split_to(6);
        assert_eq!(&head[..], b"head\r\n");
        assert_eq!(&chunk[..], b"body-bytes");
        assert_eq!(chunk.as_ptr(), whole[6..].as_ptr());
        let part = chunk.slice(5..);
        assert_eq!(&part[..], b"bytes");
        assert_eq!(part.as_ptr(), whole[11..].as_ptr());
        assert!(chunk.slice(3..3).is_empty());

        // Taking everything moves the chunk and leaves an empty one.
        let all = chunk.split_to(chunk.len());
        assert_eq!(all.as_ptr(), whole[6..].as_ptr());
        assert!(chunk.is_empty());
        assert!(chunk.split_to(0).is_empty());

        let mut rest = all.clone();
        rest.advance(5);
        rest.truncate(3);
        assert_eq!(&rest[..], b"byt");
        assert_eq!(rest.into_bytes().as_ptr(), whole[11..].as_ptr());
    }
}

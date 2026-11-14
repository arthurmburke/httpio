use bytes::{Buf, Bytes};

use crate::dpdk::mbuf::Mbuf;

/// An owned chunk from one packet segment, or bytes from a caller driving
/// TCP directly. Trimming the view keeps the same backing storage.
pub enum Chunk {
    Packet { mbuf: Mbuf, start: u16, end: u16 },
    Bytes(Bytes),
}

impl Chunk {
    pub fn packet(mbuf: Mbuf, start: usize, len: usize) -> Self {
        debug_assert!(start + len <= usize::from(mbuf.data_len()));
        Self::Packet {
            mbuf,
            start: start as u16,
            end: (start + len) as u16,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Packet { start, end, .. } => usize::from(end - start),
            Self::Bytes(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Packet { mbuf, start, end } => {
                &mbuf.data()[usize::from(*start)..usize::from(*end)]
            }
            Self::Bytes(bytes) => bytes,
        }
    }

    pub fn advance(&mut self, n: usize) {
        debug_assert!(n <= self.len());
        match self {
            Self::Packet { start, .. } => *start += n as u16,
            Self::Bytes(bytes) => bytes.advance(n),
        }
    }

    pub fn truncate(&mut self, len: usize) {
        debug_assert!(len <= self.len());
        match self {
            Self::Packet { start, end, .. } => *end = *start + len as u16,
            Self::Bytes(bytes) => bytes.truncate(len),
        }
    }

    pub fn into_bytes(self) -> Bytes {
        match self {
            Self::Packet { mbuf, start, end } => mbuf
                .into_bytes()
                .slice(usize::from(start)..usize::from(end)),
            Self::Bytes(bytes) => bytes,
        }
    }
}

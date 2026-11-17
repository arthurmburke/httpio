//! What the codecs here read received data out of.

use std::ops::Deref;

use bytes::{Buf, Bytes};

use crate::dpdk::MbufSlice;

/// A contiguous run of received bytes that a codec can take apart without
/// copying: parts split off it share its storage.
///
/// Over plain TCP that is a view of the packet buffer the bytes arrived in
/// ([`MbufSlice`]); over TLS, decrypted plaintext ([`Bytes`]). A codec
/// written against this trait runs on either, and never needs a packet
/// buffer wrapped in `Bytes` (a heap allocation per packet) just to have
/// one type for both.
///
/// `Send + Unpin + 'static`, as both are: a body holding one is moved
/// across tasks and polled by `&mut`.
pub trait RecvBuf: Deref<Target = [u8]> + Default + Send + Unpin + 'static {
    /// Drops the first `n` bytes.
    ///
    /// # Panics
    /// If `n` is more than the buffer holds.
    fn advance(&mut self, n: usize);

    /// Splits off and returns the first `at` bytes, leaving the rest.
    ///
    /// # Panics
    /// If `at` is more than the buffer holds.
    fn split_to(&mut self, at: usize) -> Self;

    /// Converts to [`Bytes`], for handing to code that needs it. Free for
    /// `Bytes`; a packet buffer gets its `Bytes` owner here, which is a
    /// heap allocation.
    fn into_bytes(self) -> Bytes;
}

impl RecvBuf for Bytes {
    fn advance(&mut self, n: usize) {
        Buf::advance(self, n);
    }

    fn split_to(&mut self, at: usize) -> Self {
        Bytes::split_to(self, at)
    }

    fn into_bytes(self) -> Bytes {
        self
    }
}

impl RecvBuf for MbufSlice {
    fn advance(&mut self, n: usize) {
        MbufSlice::advance(self, n);
    }

    fn split_to(&mut self, at: usize) -> Self {
        MbufSlice::split_to(self, at)
    }

    fn into_bytes(self) -> Bytes {
        MbufSlice::into_bytes(self)
    }
}

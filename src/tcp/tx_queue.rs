//! Outgoing application data waiting to be segmented and sent. Distinct
//! from `rto::RetransmitQueue`, which holds data that has already been
//! sent once and is waiting to be acked.

use std::collections::VecDeque;

#[derive(Default)]
pub struct SendBuffer {
    bytes: VecDeque<u8>,
}

impl SendBuffer {
    pub fn push(&mut self, data: &[u8]) {
        self.bytes.extend(data.iter().copied());
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Removes and returns up to `max_len` bytes from the front of the
    /// buffer to form the next outgoing segment.
    pub fn take(&mut self, max_len: usize) -> Vec<u8> {
        let n = max_len.min(self.bytes.len());
        self.bytes.drain(..n).collect()
    }
}

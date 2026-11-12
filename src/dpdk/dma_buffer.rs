//! Application-writable EAL memory that freezes into immutable, DMA-capable Bytes.
use super::ffi;
use bytes::Bytes;
use std::{ptr::NonNull, slice};

pub struct DmaBuffer {
    ptr: NonNull<u8>,
    len: usize,
}
// The allocation is uniquely owned; shared access only exposes immutable bytes.
unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

impl DmaBuffer {
    /// Allocates zero-initialized EAL memory. EAL must be initialized and
    /// remain alive until this buffer and every frozen Bytes reference drops.
    pub fn new(len: usize) -> Option<Self> {
        if len == 0 || len > isize::MAX as usize {
            return None;
        }
        let ptr =
            NonNull::new(unsafe { ffi::rte_zmalloc(std::ptr::null(), len, 64) }.cast::<u8>())?;
        Some(Self { ptr, len })
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
    /// Transfers ownership, with no payload copy, to the normal send APIs.
    pub fn freeze(self) -> Bytes {
        Bytes::from_owner(self)
    }
}
impl AsRef<[u8]> for DmaBuffer {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}
impl Drop for DmaBuffer {
    fn drop(&mut self) {
        unsafe { ffi::rte_free(self.ptr.as_ptr().cast()) }
    }
}

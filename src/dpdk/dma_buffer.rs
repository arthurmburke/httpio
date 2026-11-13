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

/// Smallest and largest block a [`DmaWriter`] allocates.
const MIN_BLOCK: usize = 4 * 1024;
const MAX_BLOCK: usize = 64 * 1024;
/// Blocks a writer keeps for reuse once their data has been acknowledged.
const MAX_SPARES: usize = 8;

/// Copies borrowed bytes into DMA-capable memory, once, and hands them back
/// as [`Bytes`] the stack can attach to packets without another copy.
///
/// A write through `AsyncWrite` arrives as a borrowed slice, so it has to be
/// copied somewhere that outlives the call. Copying it onto the ordinary
/// heap means the worker copies it a second time, into an mbuf, on a
/// different core. Copying it here instead makes that first copy the only
/// one on ports that can transmit multi-segment packets.
///
/// Blocks are filled front to back; each call returns the next slice of the
/// current block. A block goes back to the writer when the last slice of it
/// is dropped (its data acknowledged) and is then reused, so a steady
/// stream of writes allocates nothing.
pub struct DmaWriter {
    current: Option<Block>,
    /// Blocks whose slices have all been dropped, pushed from whichever
    /// thread dropped the last one.
    spares: std::sync::Arc<crate::core::spinlock::SpinLock<Vec<DmaBuffer>>>,
}

struct Block {
    /// The whole block; slices of it are what callers receive.
    whole: Bytes,
    /// Start of the block, for writing the part not handed out yet.
    base: NonNull<u8>,
    used: usize,
}
// SAFETY: `base` points into the allocation `whole` keeps alive, and the
// bytes past `used` are reachable only through this `Block`.
unsafe impl Send for Block {}
unsafe impl Sync for Block {}

/// Owns a block while slices of it are alive, then returns it for reuse.
struct Lease {
    buffer: Option<DmaBuffer>,
    home: std::sync::Arc<crate::core::spinlock::SpinLock<Vec<DmaBuffer>>>,
}

impl AsRef<[u8]> for Lease {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref().map_or(&[], |buffer| buffer.as_ref())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Some(buffer) = self.buffer.take() else {
            return;
        };
        // Kept only while a writer still exists to use it (it holds the
        // other reference to `home`) and has room; otherwise freed here.
        if std::sync::Arc::strong_count(&self.home) > 1 {
            self.home.with(|spares| {
                if spares.len() < MAX_SPARES {
                    spares.push(buffer);
                }
            });
        }
    }
}

impl Default for DmaWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaWriter {
    pub fn new() -> Self {
        Self {
            current: None,
            spares: std::sync::Arc::new(crate::core::spinlock::SpinLock::new(Vec::new())),
        }
    }

    /// Copies a prefix of `data` and returns it. The prefix is all of
    /// `data` unless the current block has less room than that; callers
    /// loop, as with any short write. `None` if `data` is empty or no DMA
    /// memory could be allocated.
    ///
    /// EAL must be initialised.
    pub fn copy(&mut self, data: &[u8]) -> Option<Bytes> {
        if data.is_empty() {
            return None;
        }
        if self.current.is_none() {
            self.current = Some(self.next_block(data.len())?);
        }
        let block = self.current.as_mut()?;
        let n = data.len().min(block.whole.len() - block.used);
        // SAFETY: `used + n` is within the block, and no slice covering
        // these bytes has been handed out, so nothing else can read or
        // write them.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), block.base.as_ptr().add(block.used), n);
        }
        let out = block.whole.slice(block.used..block.used + n);
        block.used += n;
        if block.used == block.whole.len() {
            // Full: let go of it now, so it comes back for reuse as soon
            // as the slices handed out are dropped.
            self.current = None;
        }
        Some(out)
    }

    /// Takes back the bytes the last [`copy`](Self::copy) returned, when
    /// they turned out not to be needed, so the space is used again.
    pub fn undo(&mut self, bytes: Bytes) {
        if let Some(block) = &mut self.current
            && bytes.len() <= block.used
            && bytes.as_ptr() == unsafe { block.base.as_ptr().add(block.used - bytes.len()) }
        {
            block.used -= bytes.len();
        }
    }

    /// A reusable block if one fits, else a new one sized for `wanted`.
    fn next_block(&mut self, wanted: usize) -> Option<Block> {
        let size = wanted.clamp(MIN_BLOCK, MAX_BLOCK).next_power_of_two();
        let spare = self.spares.with(|spares| {
            let fits = spares.iter().position(|spare| spare.len >= size)?;
            Some(spares.swap_remove(fits))
        });
        let buffer = match spare {
            Some(buffer) => buffer,
            None => {
                // Nothing reusable is big enough: smaller spares would
                // only cut the data into more pieces, so let them go.
                self.spares.with(|spares| spares.clear());
                DmaBuffer::new(size)?
            }
        };
        let base = buffer.ptr;
        let whole = Bytes::from_owner(Lease {
            buffer: Some(buffer),
            home: self.spares.clone(),
        });
        Some(Block {
            whole,
            base,
            used: 0,
        })
    }
}

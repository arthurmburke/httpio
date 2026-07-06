//! A free-list allocator for dynamic memory, intended to circumvent `malloc`
//! calls that would interrupt DPDK threads.
//!
//! [`FreeList`] is the algorithm: a fixed region carved on demand into
//! variable-size blocks. Free blocks are linked through an intrusive
//! `{ size, next }` header stored in their own bytes (address-sorted), so
//! allocation is first-fit with splitting and freeing coalesces neighbours.
//! There is no side table — all metadata lives inside free space.
//!
//! [`Alloc`] wraps a [`FreeList`] over a static arena behind a spinlock so it
//! can serve as a process `#[global_allocator]`:
//!
//! ```ignore
//! #[global_allocator]
//! static GLOBAL: quicktcp::mem::alloc::Alloc = quicktcp::mem::alloc::Alloc;
//! ```
//!
//! INVARIANT (relied on by the unchecked pointer math below): every free-list
//! offset is a multiple of [`ALIGN`] and lies within the arena, and every block
//! is at least [`MIN_BLOCK`] bytes — large enough to hold an [`Entry`] once
//! freed.

use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use std::alloc::{GlobalAlloc, Layout};

use crate::core::spinlock::SpinLock;

/// Alignment of every block and free-list node (a free node is a `{u64, u64}`).
const ALIGN: usize = align_of::<Entry>();
/// Smallest block we ever hand out or leave behind: a freed block must be able
/// to hold an [`Entry`], so smaller splits are never created.
const MIN_BLOCK: usize = size_of::<Entry>();
/// Sentinel offset meaning "no next free block".
const NIL: u64 = u64::MAX;

/// Intrusive free-list node, written into the first bytes of a free block.
/// `size` is the whole block's size in bytes; `next` is the offset of the next
/// free block (ascending by offset), or [`NIL`].
#[repr(C)]
struct Entry {
    size: u64,
    next: u64,
}

#[inline]
fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

/// The size/alignment a request occupies once normalised: at least
/// [`MIN_BLOCK`], rounded up to [`ALIGN`].
#[inline]
fn block_size_for(layout: &Layout) -> u64 {
    align_up(layout.size().max(MIN_BLOCK) as u64, ALIGN as u64)
}

/// A first-fit free-list allocator over a single contiguous region.
pub struct FreeList {
    base: *mut u8,
    size: u64,
    /// Offset of the first free block, or [`NIL`] when full.
    head: u64,
}

impl FreeList {
    /// Take ownership of `[base, base + size)` as the backing region.
    ///
    /// # Safety
    /// `base` must point to `size` writable bytes that outlive this `FreeList`
    /// and are not aliased elsewhere. The region is aligned/trimmed internally.
    pub unsafe fn new(base: *mut u8, size: usize) -> Self {
        let raw = base as u64;
        let aligned = align_up(raw, ALIGN as u64);
        let pad = (aligned - raw) as usize;
        let usable = (size - pad) & !(ALIGN - 1);
        assert!(
            usable >= MIN_BLOCK,
            "arena too small for the free-list header"
        );

        // SAFETY: `pad < size`, so this stays within the caller's region.
        let base = unsafe { base.add(pad) };
        let list = FreeList {
            base,
            size: usable as u64,
            head: 0,
        };
        // One big free block spanning the whole region.
        list.write_entry(0, usable as u64, NIL);
        list
    }

    /// Allocate `layout.size()` bytes aligned to `layout.align()`, or null.
    ///
    /// # Safety
    /// Standard [`GlobalAlloc`] contract: the returned memory is uninitialised
    /// and must be released with [`FreeList::dealloc`] using the same `layout`.
    pub unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(ALIGN) as u64;
        let need = block_size_for(&layout);
        let base_addr = self.base as u64;

        let mut prev = NIL;
        let mut cur = self.head;
        while cur != NIL {
            let hole_size = self.entry_size(cur);
            let next = self.entry_next(cur);
            let hole_end = cur + hole_size;

            // Align the absolute address, not just the offset.
            let mut aligned = align_up(base_addr + cur, align) - base_addr;
            let mut front = aligned - cur;
            // Front padding must be 0 or a usable block; otherwise push the
            // start to the next alignment that leaves a full block in front.
            if front != 0 && (front as usize) < MIN_BLOCK {
                aligned = align_up(base_addr + cur + MIN_BLOCK as u64, align) - base_addr;
                front = aligned - cur;
            }

            let alloc_end = aligned + need;
            if alloc_end <= hole_end {
                let back = hole_end - alloc_end;
                // Reject holes that would leave an unusable back sliver.
                if back == 0 || back >= MIN_BLOCK as u64 {
                    // Replace `cur` in the list with its (optional) front and
                    // back remnants.
                    let back_off = if back >= MIN_BLOCK as u64 {
                        self.write_entry(alloc_end, back, next);
                        alloc_end
                    } else {
                        next
                    };
                    let seg_head = if front >= MIN_BLOCK as u64 {
                        self.write_entry(cur, front, back_off);
                        cur
                    } else {
                        back_off
                    };
                    if prev == NIL {
                        self.head = seg_head;
                    } else {
                        self.set_next(prev, seg_head);
                    }
                    // SAFETY: `aligned < self.size`, so this is inside the arena.
                    return unsafe { self.base.add(aligned as usize) };
                }
            }

            prev = cur;
            cur = next;
        }
        core::ptr::null_mut()
    }

    /// Return a block to the free list, coalescing with adjacent free blocks.
    ///
    /// # Safety
    /// `ptr`/`layout` must come from a prior [`FreeList::alloc`] on this list,
    /// and the block must not already be free.
    pub unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let off = ptr as u64 - self.base as u64;
        debug_assert!(off < self.size, "dealloc pointer is outside this arena");
        let size = block_size_for(&layout);
        self.insert_free(off, size);
    }

    /// Total free bytes (sum of all hole sizes). O(number of holes).
    pub fn free_bytes(&self) -> u64 {
        let mut total = 0;
        let mut cur = self.head;
        while cur != NIL {
            total += self.entry_size(cur);
            cur = self.entry_next(cur);
        }
        total
    }

    /// Insert a free block at `off` of `size` bytes into the address-sorted
    /// list, merging with the previous and/or next block when contiguous.
    fn insert_free(&mut self, off: u64, size: u64) {
        let mut prev = NIL;
        let mut cur = self.head;
        while cur != NIL && cur < off {
            prev = cur;
            cur = self.entry_next(cur);
        }

        if prev != NIL && prev + self.entry_size(prev) == off {
            // Merge into the previous block.
            self.set_size(prev, self.entry_size(prev) + size);
            // And possibly into the following block too.
            if cur != NIL && prev + self.entry_size(prev) == cur {
                self.set_size(prev, self.entry_size(prev) + self.entry_size(cur));
                self.set_next(prev, self.entry_next(cur));
            }
        } else {
            let mut new_size = size;
            let mut new_next = cur;
            if cur != NIL && off + size == cur {
                new_size += self.entry_size(cur);
                new_next = self.entry_next(cur);
            }
            self.write_entry(off, new_size, new_next);
            if prev == NIL {
                self.head = off;
            } else {
                self.set_next(prev, off);
            }
        }
    }

    // --- intrusive-node accessors -----------------------------------------
    // These are safe to *call*: the free-list invariant guarantees `off` is a
    // valid, ALIGN-aligned, in-arena offset for every offset they receive.

    #[inline]
    fn entry(&self, off: u64) -> *mut Entry {
        // SAFETY: `off` is an in-arena, ALIGN-aligned offset (invariant).
        unsafe { self.base.add(off as usize) as *mut Entry }
    }
    #[inline]
    fn entry_size(&self, off: u64) -> u64 {
        unsafe { (*self.entry(off)).size }
    }
    #[inline]
    fn entry_next(&self, off: u64) -> u64 {
        unsafe { (*self.entry(off)).next }
    }
    #[inline]
    fn set_size(&self, off: u64, size: u64) {
        unsafe { (*self.entry(off)).size = size }
    }
    #[inline]
    fn set_next(&self, off: u64, next: u64) {
        unsafe { (*self.entry(off)).next = next }
    }
    #[inline]
    fn write_entry(&self, off: u64, size: u64, next: u64) {
        unsafe { self.entry(off).write(Entry { size, next }) }
    }
}

/// The static arena. `align(64)` keeps the base cache-line aligned so common
/// alignment requests need no front padding. Wrapped in `UnsafeCell` so it is a
/// plain `static` (no `static mut`), accessed only via the spinlock-guarded
/// `FreeList`.
#[repr(C, align(64))]
pub struct Arena<const N: usize> {
    data: UnsafeCell<[u8; N]>,
    heap: SpinLock<Option<FreeList>>,
}
impl<const N: usize> Arena<N> {
    pub const fn new() -> Self {
        Arena {
            data: UnsafeCell::new([0; N]),
            heap: SpinLock::new(None),
        }
    }
}
impl<const N: usize> Default for Arena<N> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: the arena is reached only through `HEAP`, which serialises access.
unsafe impl<const N: usize> Sync for Arena<N> {}
// SAFETY: the arena is reached only through `HEAP`, which serialises access.
unsafe impl<const N: usize> Send for Arena<N> {}

unsafe impl<const N: usize> GlobalAlloc for Arena<N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut slot = self.heap.lock();
        let heap = slot
            .as_mut()
            .get_or_insert_with(|| unsafe { FreeList::new(self.data.get() as *mut u8, N) });
        unsafe { heap.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut slot = self.heap.lock();
        if let Some(heap) = slot.as_mut() {
            unsafe { heap.dealloc(ptr, layout) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `FreeList` over a heap-allocated buffer, for exercising the algorithm
    /// without touching the 100 MiB global arena.
    struct TestHeap {
        _buf: Box<[u8]>,
        list: FreeList,
    }

    fn make(size: usize) -> TestHeap {
        let mut buf = vec![0u8; size].into_boxed_slice();
        let base = buf.as_mut_ptr();
        // SAFETY: `buf` outlives the `FreeList` and isn't aliased.
        let list = unsafe { FreeList::new(base, size) };
        TestHeap { _buf: buf, list }
    }

    #[test]
    fn alloc_is_within_arena_and_aligned() {
        let mut th = make(4096);
        let layout = Layout::from_size_align(100, 8).unwrap();
        let p = unsafe { th.list.alloc(layout) };
        assert!(!p.is_null());
        assert_eq!(p as usize % 8, 0);
    }

    #[test]
    fn honours_large_alignment() {
        let mut th = make(4096);
        let layout = Layout::from_size_align(200, 64).unwrap();
        let p = unsafe { th.list.alloc(layout) };
        assert!(!p.is_null());
        assert_eq!(p as usize % 64, 0);
    }

    #[test]
    fn distinct_blocks_do_not_overlap() {
        let mut th = make(4096);
        let layout = Layout::from_size_align(128, 8).unwrap();
        let a = unsafe { th.list.alloc(layout) } as *mut u64;
        let b = unsafe { th.list.alloc(layout) } as *mut u64;
        assert!(!a.is_null() && !b.is_null());
        unsafe {
            a.write(0x1111);
            b.write(0x2222);
            assert_eq!(a.read(), 0x1111);
            assert_eq!(b.read(), 0x2222);
        }
        assert!((a as usize).abs_diff(b as usize) >= 128);
    }

    #[test]
    fn free_then_alloc_coalesces_back_to_full() {
        let mut th = make(4096);
        let init = th.list.free_bytes();
        let layout = Layout::from_size_align(64, 8).unwrap();
        let p = unsafe { th.list.alloc(layout) };
        assert!(!p.is_null());
        assert!(th.list.free_bytes() < init);
        unsafe { th.list.dealloc(p, layout) };
        assert_eq!(th.list.free_bytes(), init);
    }

    #[test]
    fn coalesces_three_freed_blocks() {
        let mut th = make(4096);
        let init = th.list.free_bytes();
        let layout = Layout::from_size_align(64, 8).unwrap();
        let a = unsafe { th.list.alloc(layout) };
        let b = unsafe { th.list.alloc(layout) };
        let c = unsafe { th.list.alloc(layout) };
        assert!(!a.is_null() && !b.is_null() && !c.is_null());

        // Free out of order; the middle free should merge both neighbours.
        unsafe { th.list.dealloc(a, layout) };
        unsafe { th.list.dealloc(c, layout) };
        unsafe { th.list.dealloc(b, layout) };
        assert_eq!(th.list.free_bytes(), init);

        // The whole region is usable again in one allocation.
        let big = Layout::from_size_align(init as usize - MIN_BLOCK, 8).unwrap();
        let p = unsafe { th.list.alloc(big) };
        assert!(!p.is_null());
    }

    #[test]
    fn exhaustion_returns_null() {
        let mut th = make(256);
        let layout = Layout::from_size_align(64, 8).unwrap();
        let mut handed_out = Vec::new();
        loop {
            let p = unsafe { th.list.alloc(layout) };
            if p.is_null() {
                break;
            }
            handed_out.push(p);
        }
        assert!(!handed_out.is_empty());
        assert!(unsafe { th.list.alloc(layout) }.is_null());
    }
}

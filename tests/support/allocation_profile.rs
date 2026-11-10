//! Thread-local Rust allocator instrumentation. Reporting stays outside windows.
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::Instant;

#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct Stats {
    pub alloc_calls: u64,
    pub zeroed_calls: u64,
    pub realloc_calls: u64,
    pub free_calls: u64,
    pub failed_calls: u64,
    /// Sum of requested sizes, including the new size on each realloc.
    pub requested_bytes: u64,
    /// Layout sizes passed to dealloc and successful realloc (old size).
    pub released_bytes: u64,
    pub allocation_ns: u64,
    pub free_ns: u64,
}
impl Stats {
    pub fn allocations(self) -> u64 {
        self.alloc_calls + self.zeroed_calls + self.realloc_calls
    }
    pub fn add(&mut self, other: Self) {
        self.alloc_calls += other.alloc_calls;
        self.zeroed_calls += other.zeroed_calls;
        self.realloc_calls += other.realloc_calls;
        self.free_calls += other.free_calls;
        self.failed_calls += other.failed_calls;
        self.requested_bytes += other.requested_bytes;
        self.released_bytes += other.released_bytes;
        self.allocation_ns += other.allocation_ns;
        self.free_ns += other.free_ns;
    }
}
thread_local! { static ACTIVE: Cell<Option<Stats>> = const { Cell::new(None) }; }
fn enabled() -> bool {
    ACTIVE.try_with(|s| s.get().is_some()).unwrap_or(false)
}
fn update(f: impl FnOnce(&mut Stats)) {
    let _ = ACTIVE.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            f(&mut stats);
            cell.set(Some(stats));
        }
    });
}

pub struct ProfileAllocator;
unsafe impl GlobalAlloc for ProfileAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !enabled() {
            return unsafe { System.alloc(layout) };
        }
        let start = Instant::now();
        let ptr = unsafe { System.alloc(layout) };
        let ns = start.elapsed().as_nanos() as u64;
        update(|s| {
            s.alloc_calls += 1;
            s.requested_bytes += layout.size() as u64;
            s.failed_calls += u64::from(ptr.is_null());
            s.allocation_ns += ns;
        });
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !enabled() {
            return unsafe { System.alloc_zeroed(layout) };
        }
        let start = Instant::now();
        let ptr = unsafe { System.alloc_zeroed(layout) };
        let ns = start.elapsed().as_nanos() as u64;
        update(|s| {
            s.zeroed_calls += 1;
            s.requested_bytes += layout.size() as u64;
            s.failed_calls += u64::from(ptr.is_null());
            s.allocation_ns += ns;
        });
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if !enabled() {
            return unsafe { System.realloc(ptr, layout, size) };
        }
        let start = Instant::now();
        let out = unsafe { System.realloc(ptr, layout, size) };
        let ns = start.elapsed().as_nanos() as u64;
        update(|s| {
            s.realloc_calls += 1;
            s.requested_bytes += size as u64;
            if !out.is_null() {
                s.released_bytes += layout.size() as u64;
            }
            s.failed_calls += u64::from(out.is_null());
            s.allocation_ns += ns;
        });
        out
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !enabled() {
            unsafe { System.dealloc(ptr, layout) };
            return;
        }
        let start = Instant::now();
        unsafe { System.dealloc(ptr, layout) };
        let ns = start.elapsed().as_nanos() as u64;
        update(|s| {
            s.free_calls += 1;
            s.released_bytes += layout.size() as u64;
            s.free_ns += ns;
        });
    }
}

pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Stats) {
    // An RAII guard disables instrumentation on panic as well.
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|s| s.set(None));
        }
    }
    ACTIVE.with(|s| {
        assert!(s.get().is_none(), "nested allocation profile");
        s.set(Some(Stats::default()));
    });
    let guard = Reset;
    let value = f();
    let stats = ACTIVE.with(|s| s.get().unwrap());
    drop(guard);
    (value, stats)
}

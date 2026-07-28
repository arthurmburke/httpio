//! Bounded, lock-free ring buffer.
//!
//! [`channel`] — MPSC (multi-producer, single-consumer), used for
//! the worker's connection-open control ring so any number of
//! application threads can share one `WorkerHandle` and open
//! connections concurrently.
//!
//! Both are cache-line padded to keep the producer and consumer indices
//! on separate lines (avoiding false sharing).

use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// One slot of the MPSC ring. `seq` sequences access so producers/consumer
/// never touch `data` concurrently; the winner of the index CAS owns the
/// slot until it publishes the matching `seq`.
struct MpmcCell<T> {
    seq: AtomicUsize,
    data: UnsafeCell<Option<T>>,
}

/// Bounded MPSC queue (Dmitry Vyukov's bounded MPMC algorithm, used here
/// with a single consumer). Multiple producers enqueue concurrently by
/// CAS-ing a shared enqueue index; the lone consumer dequeues by advancing
/// a separate index. Lock-free and allocation-free on the hot path.
#[repr(C)]
struct MpscRing<T, const N: usize> {
    enqueue_pos: AtomicUsize,
    _pad0: [u8; 56],
    dequeue_pos: AtomicUsize,
    _pad1: [u8; 56],
    /// Live producer (`MpscTx`) count, for consumer-side close detection.
    producers: AtomicUsize,
    /// Whether the consumer (`MpscRx`) is still alive, for producer-side
    /// close detection.
    consumer_alive: AtomicBool,
    buffer: [MpmcCell<T>; N],
}

// SAFETY: every access to `data` is gated by the per-slot `seq` protocol,
// so no two threads touch the same slot's `Option<T>` at once; all other
// state is atomic. Moving `T` across threads only requires `T: Send`.
unsafe impl<T: Send, const N: usize> Send for MpscRing<T, N> {}
// SAFETY: the whole point of the MPMC algorithm is concurrent access
// through a shared `&self` -- many producers `push` and the lone consumer
// `pop` at once, each owning only the slot it won the index CAS for until
// it republishes `seq`. So sharing `&MpscRing` across threads is sound;
// like `Send`, it only moves `T` between threads, hence `T: Send`.
unsafe impl<T: Send, const N: usize> Sync for MpscRing<T, N> {}

impl<T, const N: usize> MpscRing<T, N> {
    fn new() -> Self {
        assert!(N >= 2, "MPSC ring needs capacity >= 2");
        assert!(N.is_power_of_two(), "N must be a power of 2");
        Self {
            enqueue_pos: AtomicUsize::new(0),
            _pad0: [0u8; 56],
            dequeue_pos: AtomicUsize::new(0),
            _pad1: [0u8; 56],
            producers: AtomicUsize::new(1),
            consumer_alive: AtomicBool::new(true),
            // Slot i starts with sequence i: "ready to be filled at pos i".
            buffer: core::array::from_fn(|i| MpmcCell {
                seq: AtomicUsize::new(i),
                data: UnsafeCell::new(None),
            }),
        }
    }

    /// Enqueue from any producer thread. Returns `Err(item)` if full.
    #[inline]
    fn push(&self, item: T) -> Result<(), T> {
        let mut pos = self.enqueue_pos.load(Ordering::Relaxed);
        loop {
            let cell = &self.buffer[pos & (N - 1)];
            let seq = cell.seq.load(Ordering::Acquire);
            // Signed distance, computed via wrapping so it stays correct
            // even as `pos` wraps the usize range.
            let diff = seq.wrapping_sub(pos) as isize;
            if diff == 0 {
                // Slot is free and it's our turn: claim this index.
                match self.enqueue_pos.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we won the CAS for this slot at this pos;
                        // no other thread writes it until we publish `seq`.
                        unsafe { *cell.data.get() = Some(item) };
                        cell.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => pos = actual,
                }
            } else if diff < 0 {
                return Err(item); // producer lapped the consumer: full
            } else {
                pos = self.enqueue_pos.load(Ordering::Relaxed);
            }
        }
    }

    /// Dequeue from the single consumer thread. Returns `None` if empty.
    #[inline]
    fn pop(&self) -> Option<T> {
        let mut pos = self.dequeue_pos.load(Ordering::Relaxed);
        loop {
            let cell = &self.buffer[pos & (N - 1)];
            let seq = cell.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos.wrapping_add(1)) as isize;
            if diff == 0 {
                match self.dequeue_pos.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we own this slot until we publish `seq`.
                        let item = unsafe { (*cell.data.get()).take() };
                        // Reopen the slot for the producer N positions ahead.
                        cell.seq.store(pos.wrapping_add(N), Ordering::Release);
                        return item;
                    }
                    Err(actual) => pos = actual,
                }
            } else if diff < 0 {
                return None; // empty
            } else {
                pos = self.dequeue_pos.load(Ordering::Relaxed);
            }
        }
    }
}

/// Producer end of an MPSC channel. `Clone` to hand additional producers
/// to other threads; `Send + Sync`, so a single `MpscTx` can also be
/// shared behind a reference and pushed to concurrently.
pub struct MpscTx<T, const N: usize> {
    ring: Arc<MpscRing<T, N>>,
}

impl<T, const N: usize> Clone for MpscTx<T, N> {
    fn clone(&self) -> Self {
        self.ring.producers.fetch_add(1, Ordering::AcqRel);
        Self {
            ring: self.ring.clone(),
        }
    }
}

impl<T, const N: usize> Drop for MpscTx<T, N> {
    fn drop(&mut self) {
        self.ring.producers.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<T, const N: usize> MpscTx<T, N> {
    /// Enqueue an item. Safe to call concurrently from multiple threads.
    /// Returns `Err(item)` if the ring is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        self.ring.push(item)
    }

    /// Whether the consumer end has been dropped.
    pub fn is_closed(&self) -> bool {
        !self.ring.consumer_alive.load(Ordering::Acquire)
    }
}

/// Consumer end of an MPSC channel. Single consumer: `Send` (can be moved
/// to the worker lcore) but intentionally used from one thread only.
pub struct MpscRx<T, const N: usize> {
    ring: Arc<MpscRing<T, N>>,
}

impl<T, const N: usize> Drop for MpscRx<T, N> {
    fn drop(&mut self) {
        self.ring.consumer_alive.store(false, Ordering::Release);
    }
}

impl<T, const N: usize> MpscRx<T, N> {
    /// Dequeue an item. Call from the single consumer thread only.
    pub fn pop(&self) -> Option<T> {
        self.ring.pop()
    }

    /// Whether every producer has been dropped.
    pub fn is_closed(&self) -> bool {
        self.ring.producers.load(Ordering::Acquire) == 0
    }
}

unsafe impl<T: Send, const N: usize> Send for MpscRx<T, N> {}
unsafe impl<T: Send, const N: usize> Send for MpscTx<T, N> {}

/// Creates a bounded MPSC channel. The `MpscTx` may be cloned/shared
/// across producer threads; the `MpscRx` must be used by a single
/// consumer. `N` is the slot count (usable capacity is `N`).
pub fn channel<T, const N: usize>() -> (MpscTx<T, N>, MpscRx<T, N>) {
    let ring = Arc::new(MpscRing::<T, N>::new());
    (MpscTx { ring: ring.clone() }, MpscRx { ring })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpsc_push_pop_single() {
        let (tx, rx) = channel::<u64, 4>();
        assert!(rx.pop().is_none());
        tx.push(1).unwrap();
        tx.push(2).unwrap();
        assert_eq!(rx.pop(), Some(1));
        assert_eq!(rx.pop(), Some(2));
        assert!(rx.pop().is_none());
    }

    #[test]
    fn mpsc_close_detection() {
        let (tx, rx) = channel::<u64, 4>();
        let tx2 = tx.clone();
        assert!(!rx.is_closed());
        drop(tx);
        assert!(!rx.is_closed()); // tx2 still alive
        drop(tx2);
        assert!(rx.is_closed());

        let (tx, rx) = channel::<u64, 4>();
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    #[test]
    #[should_panic(expected = "N must be a power of 2")]
    fn rejects_non_power_of_two_capacity() {
        let _ = channel::<u32, 3>();
    }

    #[test]
    fn mpsc_many_producers() {
        use std::thread;

        const PRODUCERS: u64 = 4;
        const PER: u64 = 5_000;
        let (tx, rx) = channel::<u64, 1024>();

        let producers: Vec<_> = (0..PRODUCERS)
            .map(|p| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for i in 0..PER {
                        let val = p * PER + i;
                        while tx.push(val).is_err() {
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();
        drop(tx); // only the producer threads' clones remain

        let total = (PRODUCERS * PER) as usize;
        let mut seen = vec![false; total];
        let mut count = 0;
        while count < total {
            match rx.pop() {
                Some(v) => {
                    assert!(!seen[v as usize], "duplicate value {v}");
                    seen[v as usize] = true;
                    count += 1;
                }
                None => std::hint::spin_loop(),
            }
        }
        for p in producers {
            p.join().unwrap();
        }
        // Every value from every producer arrived exactly once.
        assert!(seen.into_iter().all(|s| s));
    }
}

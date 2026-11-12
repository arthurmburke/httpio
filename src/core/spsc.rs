//! Bounded, lock-free ring buffer.
//!
//! [`channel`] — SPSC (single-producer, single-consumer), the
//! lightest option, used for per-connection command/inbound rings
//! where exactly one thread owns each end.
//!
//! Both are cache-line padded to keep the producer and consumer indices
//! on separate lines (avoiding false sharing).

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// Liveness bits in [`SpscRing::flags`]. Each endpoint clears its own bit
/// when dropped, so the ring is in one of four states: both alive
/// (`OPEN`), only one side alive, or neither.
const PRODUCER_ALIVE: u8 = 0b01;
const CONSUMER_ALIVE: u8 = 0b10;
/// Both endpoints alive; anything else reads as closed.
const OPEN: u8 = PRODUCER_ALIVE | CONSUMER_ALIVE;

#[repr(C)]
struct SpscRing<T, const N: usize> {
    head: AtomicUsize,
    _pad0: [u8; 56], // pad to 64-byte cache line
    tail: AtomicUsize,
    _pad1: [u8; 56], // pad to 64-byte cache line
    /// Slots in `tail..head` (wrapping) hold a value; the rest are
    /// uninitialised, so creating a ring never touches the slot memory.
    buffer: [UnsafeCell<MaybeUninit<T>>; N],
    flags: AtomicU8,
}

// SAFETY: SpscRing is designed for single-producer, single-consumer use.
// The producer only writes head and buffer[head], the consumer only writes
// tail and reads buffer[tail]. Atomic ordering ensures visibility.
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}

impl<T, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> SpscRing<T, N> {
    /// Create a new empty ring buffer.
    fn new() -> Self {
        assert!(N > 0 && N.is_power_of_two(), "N must be a power of 2");
        Self {
            head: AtomicUsize::new(0),
            _pad0: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad1: [0u8; 56],
            buffer: core::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit())),
            flags: AtomicU8::new(OPEN),
        }
    }

    /// Allocates an empty ring directly on the heap. Unlike
    /// `Arc::new(Self::new())` this neither builds the ring on the stack
    /// nor writes its slots, so the cost does not grow with `N`; rings are
    /// created per connection, on the connect path.
    fn new_shared() -> Arc<Self> {
        assert!(N > 0 && N.is_power_of_two(), "N must be a power of 2");
        let mut ring = Arc::<Self>::new_uninit();
        let raw = Arc::get_mut(&mut ring)
            .expect("freshly allocated")
            .as_mut_ptr();
        // SAFETY: `raw` points to a writable, properly aligned allocation.
        // Every field except `buffer` is written here, and `buffer` is an
        // array of `MaybeUninit`, which is valid uninitialised.
        unsafe {
            (&raw mut (*raw).head).write(AtomicUsize::new(0));
            (&raw mut (*raw)._pad0).write([0; 56]);
            (&raw mut (*raw).tail).write(AtomicUsize::new(0));
            (&raw mut (*raw)._pad1).write([0; 56]);
            (&raw mut (*raw).flags).write(AtomicU8::new(OPEN));
            ring.assume_init()
        }
    }

    /// Push an item into the ring. Returns `Err(item)` if full.
    ///
    /// Must only be called from the producer thread.
    #[inline(always)]
    fn push(&self, item: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) & (N - 1);

        if next_head == self.tail.load(Ordering::Acquire) {
            return Err(item);
        }

        // SAFETY: only the producer writes slot `head`, and the slot is
        // empty: the consumer has already moved past it.
        unsafe {
            (*self.buffer[head].get()).write(item);
        }
        self.head.store(next_head, Ordering::Release);
        Ok(())
    }

    /// Pop an item from the ring. Returns `None` if empty.
    ///
    /// Must only be called from the consumer thread.
    #[inline(always)]
    fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);

        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        // SAFETY: `tail != head`, so the producer initialised this slot
        // and published it; advancing `tail` below gives up our claim.
        let item = unsafe { (*self.buffer[tail].get()).assume_init_read() };
        self.tail.store((tail + 1) & (N - 1), Ordering::Release);
        Some(item)
    }

    /// Returns the number of items currently in the ring.
    #[inline(always)]
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (head + N - tail) & (N - 1)
    }

    /// Returns true if the ring is empty.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the capacity (max items before full).
    /// Actual usable capacity is N-1 (one slot reserved to distinguish full from empty).
    #[inline(always)]
    fn capacity(&self) -> usize {
        N - 1
    }
}

impl<T, const N: usize> Drop for SpscRing<T, N> {
    fn drop(&mut self) {
        // Slots are `MaybeUninit`, so queued items must be dropped by hand.
        while self.pop().is_some() {}
    }
}

pub struct SpscRx<T, const N: usize> {
    ring: Arc<SpscRing<T, N>>,
}

impl<T, const N: usize> Drop for SpscRx<T, N> {
    fn drop(&mut self) {
        self.ring.flags.fetch_and(!CONSUMER_ALIVE, Ordering::AcqRel);
    }
}

impl<T, const N: usize> SpscRx<T, N> {
    pub fn pop(&self) -> Option<T> {
        self.ring.pop()
    }

    pub fn is_closed(&self) -> bool {
        self.ring.flags.load(Ordering::Acquire) != OPEN
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }
}

pub struct SpscTx<T, const N: usize> {
    ring: Arc<SpscRing<T, N>>,
}

impl<T, const N: usize> Drop for SpscTx<T, N> {
    fn drop(&mut self) {
        self.ring.flags.fetch_and(!PRODUCER_ALIVE, Ordering::AcqRel);
    }
}

impl<T, const N: usize> SpscTx<T, N> {
    pub fn push(&self, item: T) -> Result<(), T> {
        self.ring.push(item)
    }

    pub fn is_closed(&self) -> bool {
        self.ring.flags.load(Ordering::Acquire) != OPEN
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }
}

/// Creates a new SPSC channel with the given capacity. Returns a `(Tx, Rx)` pair for sending and receiving items.
/// The Tx handle should be used by the producer thread, and the Rx handle should be used by the consumer thread.
/// The channel is closed when either handle is dropped; the other handle can check for closure with `is_closed()`.
pub fn channel<T, const N: usize>() -> (SpscTx<T, N>, SpscRx<T, N>) {
    let ring = SpscRing::new_shared();
    (SpscTx { ring: ring.clone() }, SpscRx { ring })
}

// SAFETY: Tx & Rx are designed for single-producer, single-consumer use.
// Once created via `channel`, the producer thread should only use `Tx` and the consumer
// thread should only use `Rx`. Atomic ordering ensures visibility of the control block state.
unsafe impl<T: Send, const N: usize> Send for SpscTx<T, N> {}
unsafe impl<T: Send, const N: usize> Send for SpscRx<T, N> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_single() {
        let ring: SpscRing<u64, 4> = SpscRing::new();
        assert!(ring.is_empty());

        ring.push(42).unwrap();
        assert_eq!(ring.len(), 1);

        let val = ring.pop().unwrap();
        assert_eq!(val, 42);
        assert!(ring.is_empty());
    }

    #[test]
    fn push_until_full() {
        let ring: SpscRing<u32, 4> = SpscRing::new();

        // Capacity is N-1 = 3
        ring.push(1).unwrap();
        ring.push(2).unwrap();
        ring.push(3).unwrap();
        assert_eq!(ring.len(), 3);

        // Should fail — ring is full
        let result = ring.push(4);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 4);
    }

    #[test]
    fn pop_empty() {
        let ring: SpscRing<u32, 4> = SpscRing::new();
        assert!(ring.pop().is_none());
    }

    #[test]
    fn fifo_order() {
        let ring: SpscRing<u32, 8> = SpscRing::new();

        for i in 0..7 {
            ring.push(i).unwrap();
        }
        for i in 0..7 {
            assert_eq!(ring.pop().unwrap(), i);
        }
    }

    #[test]
    fn wrap_around() {
        let ring: SpscRing<u32, 4> = SpscRing::new();

        // Fill and drain multiple times to test wrap-around
        for _ in 0..10 {
            ring.push(1).unwrap();
            ring.push(2).unwrap();
            ring.push(3).unwrap();

            assert_eq!(ring.pop().unwrap(), 1);
            assert_eq!(ring.pop().unwrap(), 2);
            assert_eq!(ring.pop().unwrap(), 3);
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn capacity() {
        let ring: SpscRing<u32, 16> = SpscRing::new();
        assert_eq!(ring.capacity(), 15);
    }

    #[test]
    #[should_panic(expected = "N must be a power of 2")]
    fn rejects_non_power_of_two_capacity() {
        let _ = channel::<u32, 3>();
    }

    #[test]
    fn spsc_across_threads() {
        use std::thread;

        let (tx, rx) = channel::<u64, 1024>();
        let count = 10_000u64;

        let producer = thread::spawn(move || {
            for i in 0..count {
                loop {
                    if tx.push(i).is_ok() {
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut received = Vec::with_capacity(count as usize);
            while received.len() < count as usize {
                if let Some(val) = rx.pop() {
                    received.push(val);
                } else {
                    std::hint::spin_loop();
                }
            }
            received
        });

        producer.join().unwrap();
        let received = consumer.join().unwrap();

        // Verify FIFO ordering
        for (i, val) in received.iter().enumerate() {
            assert_eq!(*val, i as u64);
        }
    }

    #[test]
    pub fn test_closure() {
        let (tx, rx) = channel::<u64, 4>();
        assert!(!rx.is_closed());
        drop(tx);
        assert!(rx.is_closed());

        let (tx, rx) = channel::<u64, 4>();
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }
}

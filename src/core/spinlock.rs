//! A spinlock for kernel free locking, intended to circumvent the need for system calls in DPDK threads.
//!
//! [`SpinLock`] is a generic guard around a arbitrary type [`T`].
//! It provides interior mutability through its `with` method,
//! which takes a closure that gets exclusive access to the data while the lock is held.
//!
//! The lock is a simple spinlock implemented with an `AtomicBool` and `core::hint::spin_loop()` for efficient waiting.
//!
//! [`RwSpinLock`] is a read-write spinlock that allows multiple readers or one writer at a time,
//! implemented with an `AtomicUsize` to track the number of readers and a writer flag.

use std::cell::UnsafeCell;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// A minimal spinlock; the global allocator can't rely on `std::sync::Mutex`
/// without risking reentrancy through the allocator itself.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: all access to `data` goes through `with`, which holds the lock.
unsafe impl<T> Sync for SpinLock<T> where T: Send {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = self.lock();
        f(guard.as_mut())
    }

    pub fn lock(&self) -> Guard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock, so we have exclusive access to `data`.
        Guard {
            lock: self,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    data: &'a mut T,
}

impl<'a, T> Drop for Guard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<'a, T> AsRef<T> for Guard<'a, T> {
    fn as_ref(&self) -> &T {
        self.data
    }
}

impl<'a, T> AsMut<T> for Guard<'a, T> {
    fn as_mut(&mut self) -> &mut T {
        self.data
    }
}

pub struct RwSpinLock<T> {
    state: AtomicUsize,
    data: UnsafeCell<T>,
}

// SAFETY: all access to `data` goes through `with_read` or `with_write`, which
// hold the appropriate locks. `T: Sync` is required because multiple readers
// may hold `&T` concurrently; `T: Send` is required for exclusive mutation on
// a thread other than the one that created the lock.
unsafe impl<T> Sync for RwSpinLock<T> where T: Send + Sync {}

impl<T> RwSpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }

    pub fn with_read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let guard = self.read_lock();
        f(guard.as_ref())
    }

    pub fn read_lock(&self) -> ReadGuard<'_, T> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state & 1 == 0 {
                // No writer, try to increment reader count
                if self
                    .state
                    .compare_exchange_weak(state, state + 2, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            } else {
                core::hint::spin_loop();
            }
        }
        // SAFETY: we hold a read lock, so we have shared access to `data`.
        ReadGuard {
            lock: self,
            data: unsafe { &*self.data.get() },
        }
    }

    pub fn with_write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = self.write_lock();
        f(guard.as_mut())
    }

    pub fn write_lock(&self) -> WriteGuard<'_, T> {
        while self
            .state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: we hold a write lock, so we have exclusive access to `data`.
        WriteGuard {
            lock: self,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

pub struct WriteGuard<'a, T> {
    lock: &'a RwSpinLock<T>,
    data: &'a mut T,
}

impl<'a, T> Drop for WriteGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}

impl<'a, T> AsRef<T> for WriteGuard<'a, T> {
    fn as_ref(&self) -> &T {
        self.data
    }
}

impl<'a, T> AsMut<T> for WriteGuard<'a, T> {
    fn as_mut(&mut self) -> &mut T {
        self.data
    }
}

pub struct ReadGuard<'a, T> {
    lock: &'a RwSpinLock<T>,
    data: &'a T,
}

impl<'a, T> Drop for ReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(2, Ordering::Release);
    }
}

impl<'a, T> AsRef<T> for ReadGuard<'a, T> {
    fn as_ref(&self) -> &T {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::{RwSpinLock, SpinLock};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn spin_lock_is_released_when_with_panics() {
        let lock = SpinLock::new(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            lock.with(|_| panic!("boom"));
        }));
        assert!(result.is_err());
        assert_eq!(lock.with(|value| *value), 1);
    }

    #[test]
    fn read_lock_is_released_when_with_read_panics() {
        let lock = RwSpinLock::new(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            lock.with_read(|_| panic!("boom"));
        }));
        assert!(result.is_err());
        lock.with_write(|value| *value += 1);
        assert_eq!(lock.with_read(|value| *value), 2);
    }

    #[test]
    fn write_lock_is_released_when_with_write_panics() {
        let lock = RwSpinLock::new(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            lock.with_write(|_| panic!("boom"));
        }));
        assert!(result.is_err());
        assert_eq!(lock.with_read(|value| *value), 1);
    }
}

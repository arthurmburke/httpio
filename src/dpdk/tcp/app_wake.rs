//! Worker -> application wake-ups: which connections have something new.
//!
//! A `TcpStream` that cannot make progress used to wake its own task and
//! return `Pending`, so every waiting stream was re-polled on every turn of
//! the runtime whether or not anything had happened to it. Here the worker
//! says which connections changed, and only those are polled again:
//!
//! ```text
//!  worker lcore                          application runtime
//!  ------------                          -------------------
//!  change a connection's state           stream: nothing to do
//!  (data, credit, reset, ...)              -> store waker in its AppWake
//!        |                                 -> check again, then Pending
//!        v
//!  AppNotifier::notify(conn) --ring-->   Driver task (one per worker):
//!                                          pop conn, take its waker, wake
//! ```
//!
//! No system calls are involved. The worker only pushes to a ring; it never
//! calls a waker, because waking a sleeping runtime thread is a `futex`
//! call. For the same reason the application side never sleeps while a
//! stream is waiting: the driver task keeps the runtime turning by
//! waking itself, with a CPU relax hint on turns that found nothing. It is
//! one spinning task per worker instead of one per waiting stream, and it
//! stops once nothing has been waiting for a while, letting the runtime
//! sleep when the application is not waiting on the network at all.
//!
//! # Why no wake-up is lost
//!
//! The stream stores its waker and *then* checks its rings again. The
//! driver takes the waker only after popping a notification the worker
//! pushed *after* changing the state. The waker slot is behind a lock, so
//! the store and the take are ordered: either the take sees the stored
//! waker and wakes it, or the take came first, in which case the worker's
//! change is visible to the stream's second check. Coalesced notifications
//! keep that property because the driver clears `queued` with a swap, which
//! reads (and so is ordered after) the worker's own swap.
//!
//! # Limits
//!
//! The driver runs on the tokio runtime of the first stream that waits. A
//! stream polled outside tokio falls back to waking itself. If several
//! runtimes share one worker and the driver's runtime is shut down while
//! streams on another are waiting, those streams are not woken until one
//! of them is polled again. On a multi-threaded runtime tokio may still
//! make system calls of its own to move work between its threads.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::core::spinlock::SpinLock;
use crate::core::spsc::{self, SpscRx, SpscTx};

/// Notifications in flight from the worker to the driver. Each connection
/// is queued at most once, so this only fills with more connections than
/// slots all changing between two driver turns; the overflow waits in
/// [`AppNotifier::backlog`].
const READY_CAP: usize = 4096;
/// Notifications handled per driver turn before other tasks get to run.
const DRAIN_BUDGET: usize = 256;
/// Turns with no stream waiting before the driver stops. A stream that was
/// just woken waits again almost at once, so stopping immediately would
/// respawn the driver for every message.
const IDLE_TURNS_BEFORE_EXIT: u32 = 4096;

/// The application side of one worker's ready list, shared by its streams
/// and its driver task.
pub(crate) struct AppReady {
    /// Popped only by the driver; the lock makes that safe to express and
    /// is never contended (`running` admits one driver at a time).
    rx: SpinLock<SpscRx<Arc<AppWake>, READY_CAP>>,
    /// Streams with a waker stored.
    waiting: AtomicUsize,
    /// A driver task exists (or is being spawned).
    running: AtomicBool,
}

/// One connection's wake-up state, shared by its `TcpStream`, the worker
/// and (while a notification is in flight) the ready ring.
pub(crate) struct AppWake {
    ready: Arc<AppReady>,
    waker: SpinLock<Option<Waker>>,
    /// A notification for this connection is on its way to the driver.
    queued: AtomicBool,
}

/// The worker's end: pushes changed connections to the driver.
pub(crate) struct AppNotifier {
    tx: SpscTx<Arc<AppWake>, READY_CAP>,
    ready: Arc<AppReady>,
    /// Notifications the ring had no room for, oldest first.
    backlog: VecDeque<Arc<AppWake>>,
}

pub(crate) fn channel() -> (AppNotifier, Arc<AppReady>) {
    let (tx, rx) = spsc::channel();
    let ready = Arc::new(AppReady {
        rx: SpinLock::new(rx),
        waiting: AtomicUsize::new(0),
        running: AtomicBool::new(false),
    });
    (
        AppNotifier {
            tx,
            ready: ready.clone(),
            backlog: VecDeque::new(),
        },
        ready,
    )
}

impl AppNotifier {
    /// Tells the application that `wake`'s connection changed. Call it
    /// *after* making the change visible (pushing to a ring, storing a
    /// flag). Coalesces: a connection already queued is not queued again.
    pub(crate) fn notify(&mut self, wake: &Arc<AppWake>) {
        if wake.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        if !self.backlog.is_empty() {
            self.backlog.push_back(wake.clone());
        } else if let Err(wake) = self.tx.push(wake.clone()) {
            self.backlog.push_back(wake);
        }
    }

    /// Moves backlogged notifications onto the ring as it drains.
    pub(crate) fn retry(&mut self) {
        while let Some(wake) = self.backlog.pop_front() {
            if let Err(wake) = self.tx.push(wake) {
                self.backlog.push_front(wake);
                break;
            }
        }
    }

    /// Worker shutdown: gets the remaining notifications to the driver if
    /// any stream is still waiting on them, giving up after a bounded spin
    /// in case the driver's runtime is already gone.
    pub(crate) fn flush(&mut self) {
        for _ in 0..10_000_000u32 {
            self.retry();
            if self.backlog.is_empty() || self.ready.waiting.load(Ordering::SeqCst) == 0 {
                return;
            }
            std::hint::spin_loop();
        }
    }
}

impl AppReady {
    pub(crate) fn wake_handle(self: &Arc<Self>) -> Arc<AppWake> {
        Arc::new(AppWake {
            ready: self.clone(),
            waker: SpinLock::new(None),
            queued: AtomicBool::new(false),
        })
    }

    /// Makes sure a driver task exists. `false` if there is none and this
    /// thread has no tokio runtime to host one.
    fn ensure_driver(self: &Arc<Self>) -> bool {
        if self.running.swap(true, Ordering::SeqCst) {
            return true;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(drive(self.clone()));
                true
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                false
            }
        }
    }
}

impl AppWake {
    /// Stores `waker` to be woken when the worker next reports a change to
    /// this connection. The caller must check its state again afterwards
    /// and may only then return `Pending`.
    ///
    /// Returns `false`, storing nothing, when no driver can run; the
    /// caller then has to keep itself awake.
    pub(crate) fn park(&self, waker: &Waker) -> bool {
        self.waker.with(|slot| match slot {
            Some(stored) if stored.will_wake(waker) => {}
            Some(stored) => *stored = waker.clone(),
            None => {
                // Counted before the driver could take it, and before
                // `ensure_driver` reads `running`: a driver deciding to
                // stop either sees this waiter or has already cleared
                // `running`, in which case a new one is spawned below.
                self.ready.waiting.fetch_add(1, Ordering::SeqCst);
                *slot = Some(waker.clone());
            }
        });
        if self.ready.ensure_driver() {
            true
        } else {
            self.unpark();
            false
        }
    }

    /// Removes the stored waker, if any.
    fn take(&self) -> Option<Waker> {
        self.waker.with(|slot| {
            let waker = slot.take();
            if waker.is_some() {
                self.ready.waiting.fetch_sub(1, Ordering::SeqCst);
            }
            waker
        })
    }

    /// Forgets the stored waker: the stream is going away.
    pub(crate) fn unpark(&self) {
        drop(self.take());
    }

    /// Wakes the stream directly. For changes made on an application
    /// thread (a flush request); the worker uses [`AppNotifier::notify`].
    pub(crate) fn wake_now(&self) {
        if let Some(waker) = self.take() {
            waker.wake();
        }
    }
}

/// The task that turns the worker's notifications into wake-ups.
async fn drive(ready: Arc<AppReady>) {
    let mut running = Running {
        ready: ready.clone(),
        owned: true,
    };
    let mut idle_turns = 0u32;
    loop {
        let mut woke = false;
        ready.rx.with(|rx| {
            for _ in 0..DRAIN_BUDGET {
                let Some(wake) = rx.pop() else {
                    break;
                };
                // Cleared before the waker is taken, so a change the worker
                // makes from here on queues the connection again.
                wake.queued.swap(false, Ordering::AcqRel);
                wake.wake_now();
                woke = true;
            }
        });

        if ready.waiting.load(Ordering::SeqCst) != 0 || woke {
            idle_turns = 0;
        } else {
            idle_turns += 1;
            if idle_turns >= IDLE_TURNS_BEFORE_EXIT {
                // Stop, unless a stream started waiting in the meantime
                // and nobody has spawned a replacement yet.
                ready.running.store(false, Ordering::SeqCst);
                if ready.waiting.load(Ordering::SeqCst) == 0
                    || ready.running.swap(true, Ordering::SeqCst)
                {
                    running.owned = false;
                    return;
                }
                idle_turns = 0;
            }
        }

        // Either way the task stays runnable: letting the runtime sleep
        // would make the next wake-up a system call.
        if woke {
            // Let the tasks just woken run before the next turn. A plain
            // self-wake would not: tokio keeps running whatever is queued
            // (this task) for a batch of turns before it looks at the
            // future `block_on` is driving.
            tokio::task::yield_now().await;
        } else {
            std::hint::spin_loop();
            Respin(false).await;
        }
    }
}

/// `AppReady::running`, cleared if the driver is cancelled with its
/// runtime so the next waiting stream spawns one on a runtime that is
/// still alive.
struct Running {
    ready: Arc<AppReady>,
    owned: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.owned {
            self.ready.running.store(false, Ordering::SeqCst);
        }
    }
}

/// Returns `Pending` once with the task already woken: the cheapest way
/// to give other tasks a turn and run again.
struct Respin(bool);

impl Future for Respin {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Waker, Arc<Count>) {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        (Waker::from(count.clone()), count)
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }
    async fn turns(n: usize) {
        for _ in 0..n {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn only_notified_connections_are_woken_and_notifications_coalesce() {
        runtime().block_on(async {
            let (mut notifier, ready) = channel();
            let (busy, idle) = (ready.wake_handle(), ready.wake_handle());
            let (busy_waker, busy_count) = counter();
            let (idle_waker, idle_count) = counter();
            assert!(busy.park(&busy_waker));
            assert!(idle.park(&idle_waker));
            assert_eq!(ready.waiting.load(Ordering::SeqCst), 2);

            notifier.notify(&busy);
            notifier.notify(&busy);
            assert_eq!(
                notifier.tx.len(),
                1,
                "a queued connection is not queued twice"
            );
            turns(8).await;
            assert_eq!(busy_count.0.load(Ordering::SeqCst), 1);
            assert_eq!(idle_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(ready.waiting.load(Ordering::SeqCst), 1);

            // Once handled, the next change queues the connection again,
            // and a wake with no waker stored is simply dropped.
            notifier.notify(&busy);
            turns(8).await;
            assert_eq!(busy_count.0.load(Ordering::SeqCst), 1);
            assert!(busy.park(&busy_waker));
            notifier.notify(&busy);
            turns(8).await;
            assert_eq!(busy_count.0.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn driver_stops_when_nothing_waits_and_restarts_on_demand() {
        runtime().block_on(async {
            let (mut notifier, ready) = channel();
            let wake = ready.wake_handle();
            let (waker, count) = counter();
            assert!(wake.park(&waker));
            assert!(ready.running.load(Ordering::SeqCst));
            wake.unpark();
            turns(IDLE_TURNS_BEFORE_EXIT as usize + 8).await;
            assert!(!ready.running.load(Ordering::SeqCst));

            assert!(wake.park(&waker));
            assert!(ready.running.load(Ordering::SeqCst));
            notifier.notify(&wake);
            turns(8).await;
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn parking_is_refused_without_a_runtime_and_backlog_survives_a_full_ring() {
        let (mut notifier, ready) = channel();
        let wake = ready.wake_handle();
        let (waker, _) = counter();
        assert!(!wake.park(&waker), "no tokio runtime on this thread");
        assert_eq!(ready.waiting.load(Ordering::SeqCst), 0);
        assert!(!ready.running.load(Ordering::SeqCst));

        let wakes: Vec<_> = (0..READY_CAP + 10).map(|_| ready.wake_handle()).collect();
        for wake in &wakes {
            notifier.notify(wake);
        }
        assert_eq!(notifier.backlog.len(), 11);
        let drained = ready.rx.with(|rx| std::iter::from_fn(|| rx.pop()).count());
        assert_eq!(drained, READY_CAP - 1);
        notifier.retry();
        assert!(notifier.backlog.is_empty());
        assert_eq!(ready.rx.with(|rx| rx.len()), 11);
    }
}

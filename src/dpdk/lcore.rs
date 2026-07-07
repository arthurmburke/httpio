//! Safe wrappers for running work on a dedicated EAL worker lcore.
//!
//! DPDK pre-creates and pins one pthread per lcore in the EAL coremask
//! (`-l`/`-c`). `rte_eal_remote_launch` hands a C entry point to one of
//! those already-pinned threads; there is no thread creation or affinity
//! juggling to do here. The main lcore keeps running the caller's code
//! (in this project, the tokio runtime driving the HTTP client).

use std::os::raw::{c_int, c_void};

use super::ffi;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CoreType {
    Main,
    Worker,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Core {
    pub id: u32,
    pub socket: u32,
    pub type_: CoreType,
}

pub struct CoreIterator {
    current: u32,
}

impl Default for CoreIterator {
    fn default() -> Self {
        Self {
            current: ffi::RTE_MAX_LCORE,
        }
    }
}

impl Iterator for CoreIterator {
    type Item = Core;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: `rte_get_next_lcore` is safe to call with valid parameters.
        let next = unsafe { ffi::rte_get_next_lcore(self.current, 0, 0) };
        if next >= ffi::RTE_MAX_LCORE {
            None
        } else {
            self.current = next;
            let socket = unsafe { ffi::rte_lcore_to_socket_id(next) };
            let type_ = if next == main_lcore_id() {
                CoreType::Main
            } else {
                CoreType::Worker
            };

            Some(Core {
                id: next,
                socket,
                type_,
            })
        }
    }
}

pub fn get_core_info(lcore: u32) -> Core {
    let socket = unsafe { ffi::rte_lcore_to_socket_id(lcore) };
    let type_ = if lcore == main_lcore_id() {
        CoreType::Main
    } else {
        CoreType::Worker
    };

    Core {
        id: lcore,
        socket,
        type_,
    }
}

/// The calling thread's lcore id.
pub fn current_lcore_id() -> u32 {
    // SAFETY: `rte_lcore_id` reads a per-lcore variable; valid on any EAL
    // thread. (A `static inline` wrapped by bindgen.)
    unsafe { ffi::rte_lcore_id() }
}

/// The main (initial) lcore's id -- the one that called `rte_eal_init`.
pub fn main_lcore_id() -> u32 {
    // SAFETY: reads immutable EAL configuration; valid on any EAL thread.
    unsafe { ffi::rte_get_main_lcore() }
}

/// Number of lcores in the EAL coremask.
pub fn lcore_count() -> u32 {
    unsafe { ffi::rte_lcore_count() }
}

/// Picks the first worker lcore: the next enabled lcore after the current
/// (main) one, not wrapping around. Returns `None` if EAL was started
/// with only one lcore (pass e.g. `-l 0-1` to get a worker).
pub fn first_worker_lcore() -> Option<u32> {
    let main = main_lcore_id();
    // skip_main=1: never return the main lcore; wrap=0: stop at the end.
    let next = unsafe { ffi::rte_get_next_lcore(main, 1, 0) };
    // rte_get_next_lcore returns RTE_MAX_LCORE when there is no next
    // lcore.
    if next >= ffi::RTE_MAX_LCORE {
        None
    } else {
        Some(next)
    }
}

/// Get the next lcore after `lcore`.
pub fn next_lcore(lcore: u32) -> Option<u32> {
    let next = unsafe { ffi::rte_get_next_lcore(lcore, 0, 0) };
    if next >= ffi::RTE_MAX_LCORE {
        None
    } else {
        Some(next)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum CoreState {
    WAIT = 0,
    RUNNING = 1,
    FINISHED = 2,
}

pub fn get_lcore_state(lcore: u32) -> CoreState {
    unsafe { std::mem::transmute(ffi::rte_eal_get_lcore_state(lcore)) }
}

#[derive(Debug)]
pub struct LaunchError {
    pub lcore: u32,
    pub rc: i32,
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rte_eal_remote_launch on lcore {} failed with rc={} (busy or invalid lcore)",
            self.lcore, self.rc
        )
    }
}
impl std::error::Error for LaunchError {}

/// Runs `f` on the given worker lcore. `f` is a boxed `FnOnce` moved to
/// the worker; it runs to completion there. The returned [`WorkerJoin`]
/// waits for it.
///
/// The closure must be `Send` (it crosses to another thread) and `'static`
/// (the worker outlives this call). Its return value is discarded (the
/// EAL launch ABI only carries an `int`).
pub fn launch<F>(lcore: u32, f: F) -> Result<WorkerJoin, LaunchError>
where
    F: FnOnce() + Send + 'static,
{
    // Double-box: the outer box is a thin pointer we can pass as `void*`;
    // the inner `dyn FnOnce` is the fat trait object.
    let boxed: Box<dyn FnOnce()> = Box::new(f);
    let arg = Box::into_raw(Box::new(boxed)) as *mut c_void;

    // SAFETY: `trampoline` reconstructs exactly the `Box<Box<dyn FnOnce()>>`
    // we leaked above; `arg` is that pointer and is used exactly once.
    let rc = unsafe { ffi::rte_eal_remote_launch(Some(trampoline), arg, lcore) };
    if rc != 0 {
        // Launch failed: reclaim the leaked closure so it isn't dropped
        // on the worker (which never ran) nor leaked.
        // SAFETY: the trampoline never ran, so we still own `arg`.
        unsafe {
            drop(Box::from_raw(arg as *mut Box<dyn FnOnce()>));
        }
        return Err(LaunchError { lcore, rc });
    }
    Ok(WorkerJoin { lcore })
}

/// C entry point handed to `rte_eal_remote_launch`. Reconstitutes and
/// runs the boxed closure.
unsafe extern "C" fn trampoline(arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the `Box<Box<dyn FnOnce()>>` leaked in `launch`.
    let closure = unsafe { Box::from_raw(arg as *mut Box<dyn FnOnce()>) };
    closure();
    0
}

/// Handle to a launched worker; join it with [`wait`](Self::wait).
pub struct WorkerJoin {
    lcore: u32,
}

impl WorkerJoin {
    /// Blocks until the worker lcore's function returns. Safe to call
    /// from the main lcore only.
    pub fn wait(self) -> i32 {
        // SAFETY: valid worker lcore id from a successful launch.
        unsafe { ffi::rte_eal_wait_lcore(self.lcore) }
    }

    pub fn lcore(&self) -> u32 {
        self.lcore
    }
}

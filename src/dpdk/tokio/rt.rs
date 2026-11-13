//! Construct a tokio runtime whose threads are not schedulable on DPDK
//! lcores.
//!
//! DPDK pins each EAL lcore to a physical CPU and busy-polls it at 100%.
//! A default tokio runtime lets the OS schedule its worker threads across
//! every CPU, so they can land on a DPDK-owned core and starve the
//! busy-poll loop (or be starved by it). [`build_runtime`] pins every
//! tokio thread to the set of CPUs that DPDK is *not* using, giving the
//! two runtimes disjoint cores.
//!
//! Call after `dpdk::eal::init` -- the DPDK lcore -> CPU mapping is only
//! known once EAL has parsed its coremask.

use std::collections::BTreeSet;
use std::io;
use std::mem;

use crate::dpdk::lcore::CoreIterator;

/// Builds a multi-threaded tokio runtime confined to the CPUs not owned by
/// any DPDK lcore. One worker thread is created per available CPU, with all
/// workers confined to that CPU set; the spawn-blocking pool is likewise kept off
/// the DPDK cores.
///
/// Errors if every CPU the process may run on is a DPDK lcore (nothing
/// left for tokio), or if the runtime fails to build.
pub fn build_runtime() -> io::Result<tokio::runtime::Runtime> {
    build_runtime_on(available_cpus()?)
}

/// The machine's online CPUs minus those assigned to DPDK lcores. This is
/// the core set [`build_runtime`] pins tokio to.
///
/// The online set is taken from `sysconf(_SC_NPROCESSORS_ONLN)` (CPUs
/// `0..n`) rather than the calling thread's affinity mask, because EAL has
/// by now pinned this (main-lcore) thread to a single CPU -- reading its
/// mask would report just that one core. This assumes CPUs are numbered
/// `0..n` (the normal case); it targets a dedicated DPDK host and does not
/// account for an external cgroup cpuset narrower than the DPDK cores.
pub fn available_cpus() -> io::Result<Vec<usize>> {
    let dpdk = dpdk_lcore_cpus();
    Ok(online_cpus()?
        .into_iter()
        .filter(|cpu| !dpdk.contains(cpu))
        .collect())
}

/// Builds a multi-threaded runtime whose threads are pinned to exactly
/// `cpus` (one worker per CPU, sharing the allowed CPU set).
fn build_runtime_on(cpus: Vec<usize>) -> io::Result<tokio::runtime::Runtime> {
    if cpus.is_empty() {
        return Err(io::Error::other(
            "no CPUs left for the tokio runtime after excluding DPDK lcores \
             (leave some cores off EAL's `-l` list)",
        ));
    }
    let worker_threads = cpus.len();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_time()
        .on_thread_start(move || {
            if let Err(e) = pin_thread_to_cpus(cpus.iter().copied()) {
                eprintln!("warning: failed to pin tokio thread to CPUs: {e}");
            }
        })
        .build()
}

/// The set of physical CPUs backing the enabled DPDK lcores.
fn dpdk_lcore_cpus() -> BTreeSet<usize> {
    let mut cpus = BTreeSet::new();
    for core in CoreIterator::default() {
        // EAL permits one logical lcore to run on several physical CPUs.
        // Both types are the target's cpu_set_t; transmute checks their
        // sizes at compile time, and libc supplies the CPU_ISSET accessor.
        let set: libc::cpu_set_t =
            unsafe { mem::transmute(crate::dpdk::ffi::rte_lcore_cpuset(core.id)) };
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if unsafe { libc::CPU_ISSET(cpu, &set) } {
                cpus.insert(cpu);
            }
        }
    }
    cpus
}

/// The machine's online CPU ids, assumed numbered `0..n`.
fn online_cpus() -> io::Result<Vec<usize>> {
    // SAFETY: sysconf with a valid name; returns the count or -1 on error.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n < 1 {
        return Err(io::Error::other(
            "sysconf(_SC_NPROCESSORS_ONLN) reported no online CPUs",
        ));
    }
    Ok((0..n as usize).collect())
}

/// Pins the calling thread to set of CPUs.
fn pin_thread_to_cpus<I: Iterator<Item = usize>>(cpus: I) -> io::Result<()> {
    // SAFETY: builds a cpu_set_t and applies it to the calling
    // thread (pid 0).
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for cpu in cpus {
            libc::CPU_SET(cpu, &mut set);
        }
        if libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

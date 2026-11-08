#![cfg(dpdk)]

use httpio::dpdk::{eal, ffi, lcore::CoreIterator};

#[test]
fn iterator_visits_enabled_lcores_and_terminates() {
    // Use a CPU allowed in this container, with two logical lcores on it.
    // This integration-test process owns EAL independently of other tests.
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &mut affinity) },
        0
    );
    let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .rev()
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &affinity) })
        .take(2)
        .collect();
    let mapping = cpus
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    eal::init(&[
        "lcore-test",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("(0,1)@({mapping})"),
        "--main-lcore",
        "1",
    ])
    .unwrap();
    let ids: Vec<_> = CoreIterator::default()
        .take(ffi::RTE_MAX_LCORE as usize + 1)
        .map(|core| core.id)
        .collect();
    let worker = httpio::dpdk::first_worker_lcore();
    let available = httpio::dpdk::tokio::rt::available_cpus().unwrap();
    eal::cleanup();
    assert_eq!(ids, [0, 1]);
    assert_eq!(worker, Some(0));
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
    let expected: Vec<_> = (0..online).filter(|cpu| !cpus.contains(cpu)).collect();
    assert_eq!(available, expected);
}

//! Does the stack scale across cores? Runs N workers behind one
//! `WorkerHandle`, each uploading to its own sink, and reports the total
//! rate. Run it for 1, 2, 4... workers and compare.
//!
//! There is no NIC. Each worker's queue is a pair of rings whose other
//! ends belong to a single-queue port of its own, served by a peer engine
//! on its own lcore that accepts connections and discards what it
//! receives. A connection's replies therefore return to the queue it was
//! sent from by construction, which is what the flow rules arrange on a
//! real device. So this measures the software: whether N workers do N
//! times the work, with the application reaching them all through one
//! handle. It says nothing about a NIC's own scaling, and on a VM the
//! cores may not be as independent as they look.
//!
//! Needs 1 + 2N lcores: main, N workers, N peers.
//!
//! ```sh
//! BENCH_SCALING_WORKERS=4 bench_scaling -l 0-8 -m 2048 --no-huge --no-pci --log-level=error
//! ```
//!
//! `BENCH_SCALING_SECONDS` (3), `BENCH_SCALING_CONNECTIONS` per worker (1),
//! `BENCH_SCALING_CHUNK` bytes per write (65536), and
//! `BENCH_SEND_CAPACITY` / `BENCH_SEND_MAX_CAPACITY` set the run.

#[cfg(not(dpdk))]
fn main() {
    panic!("requires the DPDK devcontainer");
}

#[cfg(dpdk)]
fn main() {
    imp::main();
}

#[cfg(dpdk)]
mod imp {
    use std::ffi::CString;
    use std::net::Ipv4Addr;
    use std::os::raw::{c_char, c_int, c_uint};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use httpio::dpdk::lcore::{CoreIterator, CoreType};
    use httpio::dpdk::port::QueueSteering;
    use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
    use httpio::dpdk::tcp::stream::{TcpOptions, TcpStream};
    use httpio::dpdk::tcp::worker::{MAX_SEND_CAPACITY, SEND_CAPACITY, SendConfig, WorkerHandle};
    use httpio::dpdk::{self, EthPort, Mempool, ffi};

    // `rte_eth_from_rings` builds a port whose receive and transmit queues
    // are separate rings, which is what lets two threads sit at the two
    // ends. (A `net_ring` vdev loops each queue back onto one ring.) The
    // driver is not among the libraries libdpdk.pc links, hence by hand.
    #[link(name = "rte_net_ring")]
    unsafe extern "C" {
        fn rte_eth_from_rings(
            name: *const c_char,
            rx_queues: *const *mut ffi::rte_ring,
            nb_rx_queues: c_uint,
            tx_queues: *const *mut ffi::rte_ring,
            nb_tx_queues: c_uint,
            numa_node: c_uint,
        ) -> c_int;
    }

    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
    const POOL_MBUFS: u32 = 8191;

    fn setting(name: &str, default: usize) -> usize {
        std::env::var(name).map_or(default, |v| v.parse().unwrap())
    }

    fn ring(name: &str) -> *mut ffi::rte_ring {
        let name = CString::new(name).unwrap();
        // One thread at each end.
        // RING_F_SP_ENQ | RING_F_SC_DEQ (function-like macros in rte_ring.h).
        let flags = 0x0001 | 0x0002;
        let ring = unsafe { ffi::rte_ring_create(name.as_ptr(), 4096, 0, flags) };
        assert!(!ring.is_null(), "ring allocation failed");
        ring
    }

    fn ring_port(name: &str, rx: &[*mut ffi::rte_ring], tx: &[*mut ffi::rte_ring]) -> u16 {
        let name = CString::new(name).unwrap();
        let port = unsafe {
            rte_eth_from_rings(
                name.as_ptr(),
                rx.as_ptr(),
                rx.len() as c_uint,
                tx.as_ptr(),
                tx.len() as c_uint,
                0,
            )
        };
        u16::try_from(port).expect("rte_eth_from_rings failed")
    }

    fn pool(name: String) -> Mempool {
        Mempool::create(
            &name,
            POOL_MBUFS,
            256,
            dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
            -1,
        )
        .unwrap()
    }

    /// One worker's counterpart: accepts whatever connects and discards
    /// what arrives, counting it.
    fn sink(port: EthPort, pool: Mempool, received: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: SERVER_IP,
            local_mac: port.mac_addr().unwrap(),
            gateway: None,
        });
        engine.listen(80);
        let mut connections = Vec::new();
        let mut events = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            engine.poll_into(
                &port,
                &pool,
                httpio::dpdk::time::Instant::now(),
                &mut events,
            );
            connections.extend(std::iter::from_fn(|| engine.accept(80)));
            let mut bytes = 0;
            for &connection in &connections {
                loop {
                    let data = engine.recv(connection, usize::MAX);
                    if data.is_empty() {
                        break;
                    }
                    bytes += data.len() as u64;
                }
            }
            if bytes != 0 {
                received.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    pub fn main() {
        let workers = setting("BENCH_SCALING_WORKERS", 1);
        let seconds = setting("BENCH_SCALING_SECONDS", 3);
        let per_worker = setting("BENCH_SCALING_CONNECTIONS", 1);
        let chunk = setting("BENCH_SCALING_CHUNK", 64 * 1024);
        let send_config = SendConfig {
            capacity: setting("BENCH_SEND_CAPACITY", SEND_CAPACITY)
                .try_into()
                .unwrap(),
            max_capacity: setting("BENCH_SEND_MAX_CAPACITY", MAX_SEND_CAPACITY)
                .try_into()
                .unwrap(),
            ..SendConfig::default()
        };

        let args: Vec<String> = std::env::args().collect();
        let eal_args: Vec<&str> = args.iter().map(String::as_str).collect();
        dpdk::eal::init(&eal_args).unwrap();
        let lcores: Vec<u32> = CoreIterator::default()
            .filter(|core| core.type_ == CoreType::Worker)
            .map(|core| core.id)
            .collect();
        assert!(
            lcores.len() >= 2 * workers,
            "{workers} workers need {} worker lcores (-l), found {}",
            2 * workers,
            lcores.len()
        );
        let (worker_lcores, sink_lcores) = lcores.split_at(workers);

        // Queue q of the client port sends on up[q] and receives on down[q].
        let up: Vec<_> = (0..workers).map(|q| ring(&format!("up{q}"))).collect();
        let down: Vec<_> = (0..workers).map(|q| ring(&format!("down{q}"))).collect();
        let client_port = ring_port("scaling_client", &down, &up);

        let stop = Arc::new(AtomicBool::new(false));
        let mut received = Vec::new();
        let mut sink_joins = Vec::new();
        for q in 0..workers {
            let port_id = ring_port(&format!("scaling_sink{q}"), &[up[q]], &[down[q]]);
            let pool = pool(format!("sink{q}"));
            let port = EthPort::init(port_id, &pool, 1024, 1024, 1500, -1).unwrap();
            let count = Arc::new(AtomicU64::new(0));
            received.push(count.clone());
            let stop = stop.clone();
            sink_joins
                .push(dpdk::launch(sink_lcores[q], move || sink(port, pool, count, stop)).unwrap());
        }

        let pools: Vec<_> = (0..workers).map(|q| pool(format!("worker{q}"))).collect();
        let queues = EthPort::init_queues(
            client_port,
            &pools.iter().collect::<Vec<_>>(),
            1024,
            1024,
            1500,
            -1,
            // The rings are the steering: queue q's peer answers on queue q.
            QueueSteering::Unmanaged,
        )
        .unwrap();
        let config = EngineConfig {
            local_ip: CLIENT_IP,
            local_mac: queues[0].mac_addr().unwrap(),
            gateway: None,
        };
        let stack = queues
            .into_iter()
            .zip(pools)
            .zip(worker_lcores)
            .map(|((queue, pool), &lcore)| (TcpEngine::new(config), queue, pool, lcore))
            .collect();
        let (handle, worker_joins) = WorkerHandle::spawn_all(stack).unwrap();
        let handle = handle.with_send_config(send_config);
        assert_eq!(handle.workers(), workers);

        // The application: one thread per connection, each knowing nothing
        // but the handle. Local ports in sequence, as the HTTP client
        // takes them, so the handle deals the connections out in turn.
        let connections = workers * per_worker;
        // CPUs this process may use that no EAL lcore occupies. Read from a
        // fresh thread's view of the machine: this one is pinned.
        let lcore_cpus: Vec<usize> = CoreIterator::default()
            .map(|core| core.id as usize)
            .collect();
        let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
        let spare_cpus: Arc<Vec<usize>> = Arc::new(
            (0..online)
                .filter(|cpu| !lcore_cpus.contains(cpu))
                .collect(),
        );
        assert!(
            spare_cpus.len() >= connections,
            "{connections} writers need as many CPUs outside the lcores; {} are free",
            spare_cpus.len()
        );
        let connected = Arc::new(AtomicU64::new(0));
        let apps: Vec<_> = (0..connections)
            .map(|i| {
                let handle = handle.clone();
                // Each writer its own buffer: clones of one shared buffer would
                // have every core contending for a single reference count.
                let payload = Bytes::from(vec![0x5a; chunk]);
                let (stop, connected) = (stop.clone(), connected.clone());
                let spare_cpus = spare_cpus.clone();
                std::thread::spawn(move || {
                    // A thread started after EAL init inherits the main
                    // lcore's pinning: left alone, every writer would share
                    // that one CPU. Give each a CPU no lcore is using.
                    let cpu = spare_cpus[i % spare_cpus.len()];
                    unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(cpu, &mut set);
                        assert_eq!(
                            libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set),
                            0
                        );
                    }
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    runtime.block_on(async {
                        let local_port = 49152 + i as u16;
                        let options = TcpOptions {
                            nodelay: true,
                            ..TcpOptions::default()
                        };
                        let mut stream =
                            TcpStream::connect(&handle, SERVER_IP, 80, local_port, options, None)
                                .await
                                .expect("connect");
                        connected.fetch_add(1, Ordering::Relaxed);
                        while !stop.load(Ordering::Relaxed) {
                            stream.send(payload.clone()).await.expect("send");
                        }
                    });
                })
            })
            .collect();

        let started = Instant::now();
        while connected.load(Ordering::Relaxed) < connections as u64 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "connections did not establish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Let the congestion windows open before measuring.
        std::thread::sleep(Duration::from_secs(1));
        let snapshot = |counts: &[Arc<AtomicU64>]| -> Vec<u64> {
            counts.iter().map(|c| c.load(Ordering::Relaxed)).collect()
        };
        let before = snapshot(&received);
        let measured = Instant::now();
        std::thread::sleep(Duration::from_secs(seconds as u64));
        let after = snapshot(&received);
        let elapsed = measured.elapsed().as_secs_f64();

        let gbit = |bytes: u64| bytes as f64 * 8.0 / elapsed / 1e9;
        let per_queue: Vec<f64> = after
            .iter()
            .zip(&before)
            .map(|(a, b)| gbit(a - b))
            .collect();
        let total: f64 = per_queue.iter().sum();
        println!("workers\tconnections\ttotal_gbit_s\tper_worker_gbit_s");
        println!(
            "{workers}\t{connections}\t{total:.2}\t{}",
            per_queue
                .iter()
                .map(|rate| format!("{rate:.2}"))
                .collect::<Vec<_>>()
                .join(",")
        );

        // The sinks keep acknowledging until the writers have returned.
        stop.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(50));
        // A writer blocked on credit will not see `stop`; the process is
        // done either way.
        drop(apps);
        drop(handle);
        let _ = (worker_joins, sink_joins);
        std::process::exit(0);
    }
}

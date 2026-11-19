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
//!
//! `BENCH_SCALING_MODE` picks what crosses between the application and the
//! workers: `upload` (the default) writes to a peer that discards;
//! `download` reads from a peer that sends as fast as it is allowed;
//! `echo` writes one chunk and reads it back, over and over, and reports
//! the round-trip time as well. `echo-raw` is that with no application
//! thread: one engine echoing from its own lcore, which is what the
//! round trip costs before anything crosses to an application.
//!
//! `BENCH_SCALING_READ_DELAY_US=N` makes a `download` reader take N
//! microseconds over each chunk, so the worker's ring to it stays full.
//!
//! `BENCH_SCALING_REGISTER=1` registers each application thread with EAL,
//! which gives it a mempool cache to free received mbufs into.

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

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Upload,
        Download,
        Echo,
        EchoRaw,
    }

    /// `echo` without a worker or an application: the engine itself sends
    /// a chunk and waits for it to come back, on the worker's lcore.
    fn raw_echo(
        mut engine: TcpEngine,
        port: EthPort,
        pool: Mempool,
        chunk: usize,
        trips: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
    ) {
        use httpio::core::time::Instant;
        let payload = Bytes::from(vec![0x5a; chunk]);
        let tuple = engine.connect(SERVER_IP, 80, 49152).unwrap();
        engine.set_nodelay(tuple, true);
        let mut events = Vec::new();
        let mut pending = None;
        while !stop.load(Ordering::Relaxed) {
            engine.poll_into(&port, &pool, Instant::now(), &mut events);
            if engine.state(tuple) != Some(httpio::dpdk::tcp::state::TcpState::Established) {
                continue;
            }
            let read = pending.get_or_insert_with(|| {
                engine.send(tuple, payload.clone());
                0
            });
            loop {
                let data = engine.recv(tuple, usize::MAX);
                if data.is_empty() {
                    break;
                }
                *read += data.len();
            }
            if *read >= chunk {
                pending = None;
                trips.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

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

    /// One worker's counterpart. It accepts whatever connects, and then:
    /// discards what arrives, counting it (upload); keeps each connection
    /// supplied with data to send (download); or sends back what arrives
    /// (echo).
    fn sink(
        port: EthPort,
        pool: Mempool,
        received: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        mode: Mode,
        chunk: usize,
    ) {
        // What a download connection may have queued and unacknowledged.
        const BACKLOG: usize = 1024 * 1024;
        let payload = Bytes::from(vec![0x5a; chunk]);
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
                httpio::core::time::Instant::now(),
                &mut events,
            );
            while let Some(connection) = engine.accept(80) {
                engine.set_nodelay(connection, true);
                connections.push(connection);
            }
            let mut bytes = 0;
            for &connection in &connections {
                if mode == Mode::Download {
                    while engine.buffered_send_bytes(connection) < BACKLOG {
                        engine.send(connection, payload.clone());
                    }
                    continue;
                }
                loop {
                    let data = engine.recv(connection, usize::MAX);
                    if data.is_empty() {
                        break;
                    }
                    bytes += data.len() as u64;
                    if mode == Mode::Echo || mode == Mode::EchoRaw {
                        engine.send(connection, Bytes::copy_from_slice(&data));
                    }
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
        let mode = match std::env::var("BENCH_SCALING_MODE").as_deref() {
            Err(_) | Ok("upload") => Mode::Upload,
            Ok("download") => Mode::Download,
            Ok("echo") => Mode::Echo,
            Ok("echo-raw") => Mode::EchoRaw,
            Ok(other) => panic!("BENCH_SCALING_MODE: unknown mode {other:?}"),
        };
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
                .push(
                    dpdk::launch(sink_lcores[q], move || {
                        sink(port, pool, count, stop, mode, chunk)
                    })
                    .unwrap(),
                );
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
        if mode == Mode::EchoRaw {
            assert_eq!(workers, 1, "echo-raw runs one engine");
            let mut stack: Vec<_> = stack;
            let (engine, port, pool, lcore) = stack.pop().unwrap();
            let trips = Arc::new(AtomicU64::new(0));
            let (count, stop) = (trips.clone(), stop.clone());
            let _join =
                dpdk::launch(lcore, move || raw_echo(engine, port, pool, chunk, count, stop))
                    .unwrap();
            std::thread::sleep(Duration::from_secs(1));
            let before = trips.load(Ordering::Relaxed);
            let measured = Instant::now();
            std::thread::sleep(Duration::from_secs(seconds as u64));
            let done = trips.load(Ordering::Relaxed) - before;
            let elapsed = measured.elapsed().as_secs_f64();
            println!("workers\tconnections\tchunk\tround_trips_s\tmean_round_trip_us");
            println!(
                "1\t1\t{chunk}\t{:.0}\t{:.3}",
                done as f64 / elapsed,
                elapsed * 1e6 / done as f64
            );
            std::process::exit(0);
        }
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
        // What each application thread has read (bytes) or completed
        // (echo round trips): one counter per thread, so none is shared.
        let app_counts: Vec<_> = (0..connections)
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();
        let apps: Vec<_> = (0..connections)
            .map(|i| {
                let handle = handle.clone();
                let count = app_counts[i].clone();
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
                    let slow_reader = setting("BENCH_SCALING_READ_DELAY_US", 0);
                    if setting("BENCH_SCALING_REGISTER", 0) == 1 {
                        // SAFETY: registers the calling thread; no arguments.
                        assert_eq!(unsafe { ffi::rte_thread_register() }, 0);
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
                            match mode {
                                Mode::Upload => stream.send(payload.clone()).await.expect("send"),
                                Mode::Download => {
                                    let data = stream.recv_chunk().await.expect("recv");
                                    let data = data.expect("peer closed");
                                    count.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    if slow_reader != 0 {
                                        // Falls behind the worker, so
                                        // its ring fills and stays full.
                                        let until = Instant::now()
                                            + Duration::from_micros(slow_reader as u64);
                                        while Instant::now() < until {
                                            std::hint::spin_loop();
                                        }
                                    }
                                }
                                Mode::EchoRaw => unreachable!("no application thread"),
                                Mode::Echo => {
                                    stream.send(payload.clone()).await.expect("send");
                                    let mut read = 0;
                                    while read < payload.len() {
                                        let data = stream.recv_chunk().await.expect("recv");
                                        let data = data.expect("peer closed");
                                        read += data.len();
                                    }
                                    count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
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
        // Uploads are counted where they arrive; the other modes by the
        // application threads, connection `i` belonging to worker
        // `i % workers`.
        let counts = if mode == Mode::Upload {
            &received
        } else {
            &app_counts
        };
        let before = snapshot(counts);
        let measured = Instant::now();
        std::thread::sleep(Duration::from_secs(seconds as u64));
        let after = snapshot(counts);
        let elapsed = measured.elapsed().as_secs_f64();
        let done: Vec<u64> = after.iter().zip(&before).map(|(a, b)| a - b).collect();
        if mode == Mode::Echo {
            let trips: u64 = done.iter().sum();
            println!("workers\tconnections\tchunk\tround_trips_s\tmean_round_trip_us");
            println!(
                "{workers}\t{connections}\t{chunk}\t{:.0}\t{:.3}",
                trips as f64 / elapsed,
                elapsed * 1e6 * connections as f64 / trips as f64
            );
            std::process::exit(0);
        }

        let gbit = |bytes: u64| bytes as f64 * 8.0 / elapsed / 1e9;
        let mut per_queue = vec![0.0; workers];
        for (i, bytes) in done.iter().enumerate() {
            per_queue[i % workers] += gbit(*bytes);
        }
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

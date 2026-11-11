#[path = "support/allocation_profile.rs"]
mod allocation_profile;
#[global_allocator]
static ALLOCATOR: allocation_profile::ProfileAllocator = allocation_profile::ProfileAllocator;

#[test]
fn allocator_accounting_includes_realloc_and_free() {
    use std::alloc::{GlobalAlloc, Layout};
    let (_, stats) = allocation_profile::measure(|| unsafe {
        let small = Layout::from_size_align(32, 8).unwrap();
        let ptr = ALLOCATOR.alloc(small);
        assert!(!ptr.is_null());
        let ptr = ALLOCATOR.realloc(ptr, small, 96);
        assert!(!ptr.is_null());
        ALLOCATOR.dealloc(ptr, Layout::from_size_align(96, 8).unwrap());
        let ptr = ALLOCATOR.alloc_zeroed(small);
        assert!(!ptr.is_null());
        ALLOCATOR.dealloc(ptr, small);
    });
    assert_eq!(
        (
            stats.alloc_calls,
            stats.zeroed_calls,
            stats.realloc_calls,
            stats.free_calls
        ),
        (1, 1, 1, 2)
    );
    assert_eq!(
        (
            stats.requested_bytes,
            stats.released_bytes,
            stats.failed_calls
        ),
        (160, 160, 0)
    );
}

#[cfg(not(dpdk))]
#[test]
#[ignore = "requires native DPDK; see docs/dpdk-memory-profile.md"]
fn profile_dpdk_memory() {
    panic!("libdpdk was not found: run inside the DPDK devcontainer");
}

#[cfg(dpdk)]
mod dpdk {
    use super::allocation_profile::{Stats, measure};
    use bytes::Bytes;
    use httpio::dpdk::{
        EthPort, Mbuf, Mempool, eal, ffi,
        mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
        net::{arp, eth, ipv4, tcp},
        tcp::{
            engine::{EngineConfig, TcpEngine},
            tcb::{Event, FourTuple},
        },
    };
    use serde::Serialize;
    use std::{hint::black_box, time::Instant};

    const LOCAL_IP: [u8; 4] = [10, 0, 0, 1];
    const PEER_IP: [u8; 4] = [10, 0, 0, 2];
    const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
    static DATA: [u8; 1024] = [42; 1024];

    struct Fixture {
        engine: TcpEngine,
        port: EthPort,
        pool: Mempool,
        tuple: FourTuple,
        peer: tcp::TcpHeader,
        injection: Vec<Mbuf>,
        events: Vec<(FourTuple, Event)>,
        // Advance protocol time explicitly; benchmarking must not fire RTOs
        // merely because the host was descheduled between samples.
        now: Instant,
    }
    impl Fixture {
        fn new() -> Self {
            let pool = Mempool::create("memory-profile", 4095, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1)
                .unwrap();
            let port = EthPort::init(0, &pool, 128, 128, 1500, 0).unwrap();
            let mut engine = TcpEngine::new(EngineConfig {
                local_ip: LOCAL_IP,
                local_mac: LOCAL_MAC,
                gateway: None,
            });
            let tuple = engine.connect(PEER_IP, 80, 1234).unwrap();
            let mut f = Self {
                engine,
                port,
                pool,
                tuple,
                peer: tcp::TcpHeader {
                    src_port: 80,
                    dst_port: 1234,
                    seq: 1000,
                    ack: 0,
                    flags: tcp::flags::ACK,
                    window: u16::MAX,
                    urgent_pointer: 0,
                    options: tcp::TcpOptions { mss: Some(1460) },
                },
                injection: Vec::with_capacity(64),
                events: Vec::new(),
                now: Instant::now(),
            };
            let mut packet = f.ethernet(arp::ETHERTYPE_ARP, arp::ARP_HDR_LEN);
            arp::ArpPacket {
                operation: arp::OP_REPLY,
                sender_mac: PEER_MAC,
                sender_ip: PEER_IP,
                target_mac: LOCAL_MAC,
                target_ip: LOCAL_IP,
            }
            .write(&mut packet.data_mut()[eth::ETH_HDR_LEN..]);
            f.inject(packet);
            f.poll();
            let packet = f.port.rx_packets(64).next().expect("SYN");
            let (syn, _) = tcp::TcpHeader::parse(
                &packet.data()[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN..],
                LOCAL_IP,
                PEER_IP,
                true,
            )
            .unwrap();
            f.peer.ack = syn.seq.wrapping_add(1);
            drop(packet);
            f.peer.flags = tcp::flags::SYN | tcp::flags::ACK;
            f.prepare_rx(0, false);
            f.poll();
            assert!(f.events.contains(&(f.tuple, Event::Established)));
            f.drain_output();
            f.peer.flags = tcp::flags::ACK;
            f.peer.seq += 1;
            f.engine.set_nodelay(f.tuple, true);
            f
        }
        fn ethernet(&self, kind: u16, size: usize) -> Mbuf {
            let mut packet = Mbuf::alloc(&self.pool).unwrap();
            let data = packet.append((eth::ETH_HDR_LEN + size) as u16).unwrap();
            eth::EthHeader {
                src: PEER_MAC,
                dst: LOCAL_MAC,
                ethertype: kind,
            }
            .write(data);
            packet
        }
        fn inject(&mut self, packet: Mbuf) {
            self.injection.push(packet);
            self.port.tx_burst_in_place(&mut self.injection);
            assert!(self.injection.is_empty());
        }
        fn prepare_rx(&mut self, bytes: usize, rejected: bool) {
            let mut header = self.peer.clone();
            if rejected {
                header.seq = header.seq.wrapping_add(1_000_000);
            }
            let size = ipv4::IPV4_HDR_LEN + header.wire_len() + bytes;
            let mut packet = self.ethernet(eth::ETHERTYPE_IPV4, size);
            let data = &mut packet.data_mut()[eth::ETH_HDR_LEN..];
            ipv4::Ipv4Header {
                dscp_ecn: 0,
                total_length: size as u16,
                identification: 0,
                flags_fragment_offset: 0x4000,
                ttl: 64,
                protocol: ipv4::PROTO_TCP,
                src: PEER_IP,
                dst: LOCAL_IP,
            }
            .write(data, false);
            let end = ipv4::IPV4_HDR_LEN + header.wire_len();
            header.write(
                &mut data[ipv4::IPV4_HDR_LEN..end],
                &DATA[..bytes],
                PEER_IP,
                LOCAL_IP,
                false,
            );
            data[end..].copy_from_slice(&DATA[..bytes]);
            self.inject(packet);
        }
        fn poll(&mut self) {
            self.engine
                .poll_into(&self.port, &self.pool, self.now, &mut self.events);
        }
        fn drain_output(&mut self) {
            for packet in self.port.rx_packets(64) {
                black_box(packet);
            }
        }
        fn finish_rx(&mut self) {
            self.drain_output();
            self.poll();
            self.drain_output();
        }
        fn finish_tx(&mut self) {
            let mut count = 0;
            for packet in self.port.rx_packets(64) {
                let data = packet.data();
                let (header, len) = tcp::TcpHeader::parse(
                    &data[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN..],
                    LOCAL_IP,
                    PEER_IP,
                    true,
                )
                .unwrap();
                let payload = data.len() - eth::ETH_HDR_LEN - ipv4::IPV4_HDR_LEN - len;
                self.peer.ack = header.seq.wrapping_add(payload as u32);
                count += 1;
            }
            assert!(count > 0, "TX workload sent no packets");
            self.prepare_rx(0, false);
            self.poll();
            self.drain_output();
        }
        fn available(&self) -> u32 {
            unsafe { ffi::rte_mempool_avail_count(self.pool.as_raw()) }
        }
    }

    #[derive(Serialize)]
    struct Row {
        scenario: &'static str,
        iterations: usize,
        stats: Stats,
        allocations_per_op: f64,
        requested_bytes_per_op: f64,
        allocator_ns_per_op: f64,
        free_ns_per_op: f64,
        allocator_ns_per_call: f64,
        baseline_p50_ns: u64,
        baseline_p95_ns: u64,
        baseline_mean_ns: f64,
        instrumented_mean_ns: f64,
        pool_available_before: u32,
        pool_available_after: u32,
    }
    fn profile(
        name: &'static str,
        iterations: usize,
        f: &mut Fixture,
        mut prepare: impl FnMut(&mut Fixture),
        mut work: impl FnMut(&mut Fixture),
        mut finish: impl FnMut(&mut Fixture),
    ) -> Row {
        for _ in 0..128 {
            prepare(f);
            work(f);
            finish(f);
        }
        let before = f.available();
        let mut latency = Vec::with_capacity(iterations);
        // Baseline pass has counting/timing disabled inside the allocator.
        for _ in 0..iterations {
            prepare(f);
            let start = Instant::now();
            work(f);
            let ns = start.elapsed().as_nanos() as u64;
            latency.push(ns);
            finish(f);
        }
        let mut stats = Stats::default();
        let mut instrumented_ns = 0u64;
        for _ in 0..iterations {
            prepare(f);
            let (ns, sample) = measure(|| {
                let start = Instant::now();
                work(f);
                start.elapsed().as_nanos() as u64
            });
            instrumented_ns += ns;
            stats.add(sample);
            finish(f);
        }
        let after = f.available();
        assert_eq!(before, after, "mbuf leak in {name}");
        assert_eq!(stats.failed_calls, 0);
        let mean = latency.iter().map(|&n| n as f64).sum::<f64>() / iterations as f64;
        latency.sort_unstable();
        Row {
            scenario: name,
            iterations,
            stats,
            allocations_per_op: stats.allocations() as f64 / iterations as f64,
            requested_bytes_per_op: stats.requested_bytes as f64 / iterations as f64,
            allocator_ns_per_op: stats.allocation_ns as f64 / iterations as f64,
            free_ns_per_op: stats.free_ns as f64 / iterations as f64,
            allocator_ns_per_call: if stats.allocations() == 0 {
                0.0
            } else {
                stats.allocation_ns as f64 / stats.allocations() as f64
            },
            baseline_p50_ns: latency[(iterations - 1) / 2],
            baseline_p95_ns: latency[(iterations - 1) * 95 / 100],
            baseline_mean_ns: mean,
            instrumented_mean_ns: instrumented_ns as f64 / iterations as f64,
            pool_available_before: before,
            pool_available_after: after,
        }
    }

    #[test]
    #[ignore = "profiling run; use --release --ignored --nocapture --test-threads=1"]
    fn profile_dpdk_memory() {
        let iterations = std::env::var("DPDK_PROFILE_ITERS")
            .map(|s| {
                s.parse::<usize>()
                    .expect("DPDK_PROFILE_ITERS must be an integer")
            })
            .unwrap_or(10_000);
        assert!(
            (100..=1_000_000).contains(&iterations),
            "use 100..=1000000 iterations"
        );
        let cpu = unsafe { libc::sched_getcpu() };
        assert!(cpu >= 0);
        let (_, eal_stats) = measure(|| {
            eal::init(&[
                "memory-profile",
                "--no-huge",
                "--no-pci",
                "--no-shconf",
                "--no-telemetry",
                "--lcores",
                &format!("0@{cpu}"),
                "--vdev=net_ring0",
            ])
            .unwrap()
        });
        let (mut f, setup_stats) = measure(Fixture::new);
        let mut rows = Vec::new();
        rows.push(profile(
            "timer_overhead",
            iterations,
            &mut f,
            |_| {},
            |_| {
                black_box(());
            },
            |_| {},
        ));
        rows.push(profile(
            "mbuf_alloc_free",
            iterations,
            &mut f,
            |_| {},
            |f| {
                drop(black_box(Mbuf::alloc(&f.pool).unwrap()));
            },
            |_| {},
        ));
        rows.push(profile(
            "mbuf_bytes_owner",
            iterations,
            &mut f,
            |_| {},
            |f| {
                let mut p = Mbuf::alloc(&f.pool).unwrap();
                p.append(64).unwrap().fill(42);
                drop(black_box(p.into_bytes()));
            },
            |_| {},
        ));
        rows.push(profile(
            "idle_poll",
            iterations,
            &mut f,
            |_| {},
            Fixture::poll,
            |_| {},
        ));
        rows.push(profile(
            "rx_ack",
            iterations,
            &mut f,
            |f| f.prepare_rx(0, false),
            Fixture::poll,
            Fixture::finish_rx,
        ));
        rows.push(profile(
            "rx_rejected",
            iterations,
            &mut f,
            |f| f.prepare_rx(64, true),
            Fixture::poll,
            Fixture::finish_rx,
        ));
        rows.push(profile(
            "rx_data_1024",
            iterations,
            &mut f,
            |f| f.prepare_rx(1024, false),
            |f| {
                f.poll();
                let data = f.engine.recv(f.tuple, 1024);
                assert_eq!(data.len(), 1024);
                drop(black_box(data));
                f.peer.seq = f.peer.seq.wrapping_add(1024);
            },
            Fixture::finish_rx,
        ));
        for (name, chunks, copy) in [
            ("tx_owned_1024", 1, false),
            ("tx_copied_1024", 1, true),
            ("tx_4_fragments", 4, false),
            ("tx_32_fragments", 32, false),
        ] {
            rows.push(profile(
                name,
                iterations,
                &mut f,
                |_| {},
                |f| {
                    let size = 1024 / chunks;
                    for _ in 0..chunks {
                        let bytes = if copy {
                            Bytes::copy_from_slice(&DATA[..size])
                        } else {
                            Bytes::from_static(&DATA[..size])
                        };
                        f.engine.send(f.tuple, bytes);
                    }
                    f.poll();
                },
                Fixture::finish_tx,
            ));
        }
        for row in &rows {
            if matches!(
                row.scenario,
                "timer_overhead"
                    | "mbuf_alloc_free"
                    | "idle_poll"
                    | "rx_ack"
                    | "rx_rejected"
                    | "tx_owned_1024"
                    | "tx_4_fragments"
            ) {
                assert_eq!(
                    row.stats.allocations(),
                    0,
                    "allocation regression: {}",
                    row.scenario
                );
            }
        }
        let report = serde_json::json!({
            "schema_version": 1, "iterations": iterations, "warmup_iterations": 128,
            "cpu": cpu, "optimized": !cfg!(debug_assertions), "driver": "net_ring", "pool_cache_size": 0,
            "dpdk_version": unsafe { std::ffi::CStr::from_ptr(ffi::rte_version()) }.to_string_lossy(),
            "architecture": std::env::consts::ARCH, "os": std::env::consts::OS,
            "allocator": "std::alloc::System", "pool_objects": 4095,
            "mbuf_data_room_size": DEFAULT_MBUF_DATA_ROOM_SIZE,
            "scope": "Rust System allocator on the calling thread only; DPDK/C allocations excluded; prepare/finish excluded",
            "timing_note": "baseline retains inactive TLS hook and Instant sampling overhead; allocator timing includes clock overhead; not CPU cycles or attributable end-to-end speedup",
            "rust_eal_setup": eal_stats, "rust_fixture_setup": setup_stats, "scenarios": rows,
        });
        println!(
            "\n{:<20} {:>9} {:>10} {:>11} {:>11} {:>11} {:>11}",
            "scenario",
            "alloc/op",
            "bytes/op",
            "alloc ns/op",
            "free ns/op",
            "p50 ns/op",
            "p95 ns/op"
        );
        for r in &rows {
            println!(
                "{:<20} {:>9.3} {:>10.1} {:>11.1} {:>11.1} {:>11} {:>11}",
                r.scenario,
                r.allocations_per_op,
                r.requested_bytes_per_op,
                r.allocator_ns_per_op,
                r.free_ns_per_op,
                r.baseline_p50_ns,
                r.baseline_p95_ns
            );
        }
        let path = std::env::var("DPDK_PROFILE_OUTPUT")
            .unwrap_or_else(|_| "target/dpdk-memory-profile.json".into());
        let path = std::path::Path::new(&path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        println!("JSON report: {}", path.display());
        drop(f);
        eal::cleanup();
    }
}

//! Per-component microbenchmarks, with kernel baselines for the same job.
//!
//! ```text
//! bench_components -l 0 --no-huge --vdev=net_ring0
//! ```
//!
//! The arguments are EAL arguments; the `net_ring0` vdev loops the port's
//! TX back to its RX, so the engine can be driven with hand-built frames.
//! Without the DPDK stack only the kernel and `core` sections run.
//!
//! Output is one tab-separated row per measurement: `section  name
//! ns/op  [throughput]`.

use std::hint::black_box;
use std::io::{Read, Write};
use std::time::Instant;

fn main() {
    kernel::run();
    core_rings::run();
    dpdk_parts::run();
}

/// Times `iters` calls of `f` after a warm-up tenth and prints ns/op.
/// `bytes` (per call), when non-zero, adds a throughput column.
fn bench(section: &str, name: &str, iters: u64, bytes: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = start.elapsed().as_nanos() as f64 / iters as f64;
    if bytes == 0 {
        println!("{section}\t{name}\t{ns:.1} ns");
    } else {
        let gbit = bytes as f64 * 8.0 / ns;
        println!("{section}\t{name}\t{ns:.1} ns\t{gbit:.2} Gbit/s");
    }
    ns
}

/// What the kernel charges for the equivalent work: a syscall, a TCP
/// segment through its stack, and waking a sleeping thread.
mod kernel {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    pub fn run() {
        bench("kernel", "syscall (getppid)", 2_000_000, 0, || {
            black_box(unsafe { libc::getppid() });
        });
        bench("kernel", "Instant::now", 5_000_000, 0, || {
            black_box(Instant::now());
        });

        // Both ends in one thread: the data is already queued when read()
        // is called, so this is stack + syscall cost with no sleep/wake.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut b, _) = listener.accept().unwrap();
        a.set_nodelay(true).unwrap();
        b.set_nodelay(true).unwrap();
        for size in [64usize, 1460, 65536] {
            let msg = vec![7u8; size];
            let mut buf = vec![0u8; size];
            let iters = if size > 4096 { 100_000 } else { 500_000 };
            bench(
                "kernel",
                &format!("loopback TCP write+read {size}B (no wake)"),
                iters,
                size,
                || {
                    a.write_all(&msg).unwrap();
                    b.read_exact(&mut buf).unwrap();
                },
            );
        }

        // Two threads, each asleep in read() until the other writes: every
        // hop is a kernel wake-up of a blocked thread, as an interrupt
        // driven receive is.
        let (mut near, far) = (a, b);
        let echo = std::thread::spawn(move || {
            let mut far = far;
            let mut buf = [0u8; 64];
            while far.read_exact(&mut buf).is_ok() {
                if far.write_all(&buf).is_err() {
                    break;
                }
            }
        });
        let msg = [7u8; 64];
        let mut buf = [0u8; 64];
        bench(
            "kernel",
            "loopback TCP 64B ping-pong, 2 threads (2 wakes)",
            100_000,
            0,
            || {
                near.write_all(&msg).unwrap();
                near.read_exact(&mut buf).unwrap();
            },
        );
        drop(near);
        echo.join().unwrap();

        let (ping_tx, ping_rx) = std::sync::mpsc::channel::<u64>();
        let (pong_tx, pong_rx) = std::sync::mpsc::channel::<u64>();
        let echo = std::thread::spawn(move || {
            while let Ok(v) = ping_rx.recv() {
                if pong_tx.send(v).is_err() {
                    break;
                }
            }
        });
        bench(
            "kernel",
            "std mpsc ping-pong, 2 threads (futex wakes)",
            200_000,
            0,
            || {
                ping_tx.send(1).unwrap();
                black_box(pong_rx.recv().unwrap());
            },
        );
        drop(ping_tx);
        echo.join().unwrap();
    }
}

/// The lock-free rings that carry every byte between the application
/// thread and the worker lcore.
mod core_rings {
    use super::*;
    use httpio::core::{mpsc, spsc};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub fn run() {
        let (tx, rx) = spsc::channel::<u64, 1024>();
        bench("core", "spsc push+pop, 1 thread", 20_000_000, 0, || {
            let _ = tx.push(1);
            black_box(rx.pop());
        });
        let (tx, rx) = mpsc::channel::<u64, 1024>();
        bench("core", "mpsc push+pop, 1 thread", 20_000_000, 0, || {
            let _ = tx.push(1);
            black_box(rx.pop());
        });

        // The busy-poll handoff the stream and worker use, both directions.
        let (ping_tx, ping_rx) = spsc::channel::<u64, 1024>();
        let (pong_tx, pong_rx) = spsc::channel::<u64, 1024>();
        let stop = Arc::new(AtomicBool::new(false));
        let echo_stop = stop.clone();
        let echo = std::thread::spawn(move || {
            while !echo_stop.load(Ordering::Relaxed) {
                match ping_rx.pop() {
                    Some(v) => {
                        let _ = pong_tx.push(v);
                    }
                    None => std::hint::spin_loop(),
                }
            }
        });
        bench(
            "core",
            "spsc ping-pong, 2 spinning threads",
            2_000_000,
            0,
            || {
                let _ = ping_tx.push(1);
                loop {
                    if let Some(v) = pong_rx.pop() {
                        black_box(v);
                        break;
                    }
                    std::hint::spin_loop();
                }
            },
        );
        stop.store(true, Ordering::Relaxed);
        echo.join().unwrap();

        // One turn of the application-side busy poll: a task that wakes
        // itself and returns Pending, as `TcpStream` does while it waits.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let turns = 2_000_000u64;
        let start = Instant::now();
        runtime.block_on(async {
            let mut left = turns;
            std::future::poll_fn(|cx| {
                if left == 0 {
                    return std::task::Poll::Ready(());
                }
                left -= 1;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            })
            .await
        });
        let ns = start.elapsed().as_nanos() as f64 / turns as f64;
        println!("core\ttokio current_thread self-wake turn\t{ns:.1} ns");
    }
}

#[cfg(not(dpdk))]
mod dpdk_parts {
    pub fn run() {
        eprintln!("DPDK sections skipped: build inside the devcontainer.");
    }
}

#[cfg(dpdk)]
mod dpdk_parts {
    use super::*;
    use std::net::Ipv4Addr;

    use bytes::Bytes;
    use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
    use httpio::dpdk::net::arp::{self, ArpTable};
    use httpio::dpdk::net::eth::{self, EthAddr};
    use httpio::dpdk::net::{checksum, ipv4, tcp};
    use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
    use httpio::dpdk::tcp::rx_queue::ReassemblyBuffer;
    use httpio::dpdk::tcp::seq::Seq;
    use httpio::dpdk::tcp::tcb::{FourTuple, Tcb};
    use httpio::dpdk::tcp::tx_queue::SendBuffer;
    use httpio::dpdk::{EthPort, Mbuf, Mempool, eal};

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const LOCAL_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 1]);
    const PEER_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 2]);
    const MSS: usize = 1460;

    pub fn run() {
        wire_formats();
        buffers();
        tcb();
        engine();
    }

    fn peer_header(seq: u32, ack: u32, flags: u8) -> tcp::TcpHeader {
        tcp::TcpHeader {
            src_port: 80,
            dst_port: 1234,
            seq,
            ack,
            flags,
            window: u16::MAX,
            urgent_pointer: 0,
            options: tcp::TcpOptions::default(),
        }
    }

    /// The peer's SYN-ACK. It must announce an MSS: without one the stack
    /// assumes 536 bytes and every "1460 B segment" below would really be
    /// three smaller ones.
    fn peer_synack(seq: u32, ack: u32) -> tcp::TcpHeader {
        let mut header = peer_header(seq, ack, tcp::flags::SYN | tcp::flags::ACK);
        header.options.mss = Some(MSS as u16);
        header
    }

    fn wire_formats() {
        for size in [64usize, MSS] {
            let data = vec![0xa5u8; size];
            bench(
                "net",
                &format!("checksum::sum16 {size}B"),
                5_000_000,
                size,
                || {
                    black_box(checksum::sum16(black_box(&data), 0));
                },
            );
        }

        let payload = vec![0xa5u8; MSS];
        let hdr = peer_header(1, 2, tcp::flags::ACK);
        let mut segment = vec![0u8; tcp::TCP_HDR_LEN + MSS];
        segment[tcp::TCP_HDR_LEN..].copy_from_slice(&payload);
        for (offload, name) in [(false, "software checksum"), (true, "checksum offload")] {
            bench(
                "net",
                &format!("TcpHeader::write 1460B payload, {name}"),
                2_000_000,
                MSS,
                || {
                    hdr.write(
                        &mut segment[..tcp::TCP_HDR_LEN],
                        black_box(&payload),
                        PEER_IP,
                        LOCAL_IP,
                        offload,
                    );
                },
            );
        }
        hdr.write(
            &mut segment[..tcp::TCP_HDR_LEN],
            &payload,
            PEER_IP,
            LOCAL_IP,
            false,
        );
        for (verify, name) in [(true, "software verify"), (false, "NIC verified")] {
            bench(
                "net",
                &format!("TcpHeader::parse 1460B payload, {name}"),
                2_000_000,
                MSS,
                || {
                    black_box(tcp::TcpHeader::parse(
                        black_box(&segment),
                        PEER_IP,
                        LOCAL_IP,
                        verify,
                    ));
                },
            );
        }

        let ip = ipv4::Ipv4Header {
            dscp_ecn: 0,
            total_length: 1500,
            identification: 0,
            flags_fragment_offset: 0x4000,
            ttl: 64,
            protocol: ipv4::PROTO_TCP,
            src: PEER_IP,
            dst: LOCAL_IP,
        };
        let mut buf = [0u8; ipv4::IPV4_HDR_LEN];
        bench("net", "Ipv4Header::write", 10_000_000, 0, || {
            ip.write(black_box(&mut buf), false);
        });
        bench("net", "Ipv4Header::parse (verify)", 10_000_000, 0, || {
            black_box(ipv4::Ipv4Header::parse(black_box(&buf), true));
        });

        let mut table = ArpTable::new();
        let now = Instant::now();
        table.learn(PEER_IP, PEER_MAC, true, now);
        bench("net", "ArpTable::resolve (hit)", 20_000_000, 0, || {
            black_box(table.resolve(black_box(PEER_IP), now));
        });
    }

    fn buffers() {
        let chunk = Bytes::from(vec![0xa5u8; MSS]);
        let mut send = SendBuffer::default();
        bench("tcp", "SendBuffer push+take 1460B", 10_000_000, MSS, || {
            send.push(chunk.clone());
            black_box(send.take(MSS));
        });
        // One 64 KB application write segmented into MSS-sized pieces.
        let big = Bytes::from(vec![0xa5u8; 64 * 1024]);
        bench(
            "tcp",
            "SendBuffer push 64KB + take 45x1460B",
            200_000,
            64 * 1024,
            || {
                send.push(big.clone());
                while !send.is_empty() {
                    black_box(send.take(MSS));
                }
            },
        );

        let mut recv = ReassemblyBuffer::default();
        let mut next = Seq::new(1);
        bench(
            "tcp",
            "ReassemblyBuffer insert+read 1460B in order",
            10_000_000,
            MSS,
            || {
                next = recv.insert(next, chunk.clone(), next);
                black_box(recv.read(usize::MAX));
            },
        );
    }

    /// An established connection's `Tcb`, plus the peer's next sequence
    /// number and ours.
    fn established_tcb() -> (Tcb, u32, u32) {
        let now = Instant::now();
        let mut tcb = Tcb::new_active(FourTuple {
            local_ip: LOCAL_IP,
            local_port: 1234,
            remote_ip: PEER_IP,
            remote_port: 80,
        });
        tcb.set_nodelay(true);
        let syn = tcb.poll_output(now).remove(0);
        let ours = syn.seq.0.wrapping_add(1);
        let synack = peer_synack(1000, ours);
        tcb.on_segment(&synack, Bytes::new(), now);
        tcb.poll_output(now);
        (tcb, 1001, ours)
    }

    fn tcb() {
        let now = Instant::now();
        let chunk = Bytes::from(vec![0xa5u8; MSS]);
        let mut out = Vec::new();

        let (mut tcb, mut peer_seq, ours) = established_tcb();
        bench(
            "tcp",
            "Tcb receive 1460B: on_segment + recv + ACK",
            5_000_000,
            MSS,
            || {
                let hdr = peer_header(peer_seq, ours, tcp::flags::ACK);
                tcb.on_segment(&hdr, chunk.clone(), now);
                peer_seq = peer_seq.wrapping_add(MSS as u32);
                black_box(tcb.recv(usize::MAX));
                tcb.poll_output_into(now, &mut out);
                black_box(&out);
            },
        );

        let (mut tcb, peer_seq, mut ours) = established_tcb();
        bench(
            "tcp",
            "Tcb send 1460B: send + segment + process ACK",
            5_000_000,
            MSS,
            || {
                tcb.send(chunk.clone());
                tcb.poll_output_into(now, &mut out);
                black_box(&out);
                ours = ours.wrapping_add(MSS as u32);
                let ack = peer_header(peer_seq, ours, tcp::flags::ACK);
                tcb.on_segment(&ack, Bytes::new(), now);
            },
        );
    }

    fn frame(pool: &Mempool, ethertype: u16, size: usize) -> Mbuf {
        let mut packet = Mbuf::alloc(pool).expect("mbuf pool exhausted");
        let data = packet.append((eth::ETH_HDR_LEN + size) as u16).unwrap();
        eth::EthHeader {
            src: PEER_MAC,
            dst: LOCAL_MAC,
            ethertype,
        }
        .write(data);
        packet
    }

    /// Builds a peer TCP frame and loops it into the port's RX queue.
    fn inject(port: &EthPort, pool: &Mempool, header: &tcp::TcpHeader, payload: &[u8]) {
        let size = ipv4::IPV4_HDR_LEN + header.wire_len() + payload.len();
        let mut packet = frame(pool, eth::ETHERTYPE_IPV4, size);
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
        let tcp_end = ipv4::IPV4_HDR_LEN + header.wire_len();
        header.write(
            &mut data[ipv4::IPV4_HDR_LEN..tcp_end],
            payload,
            PEER_IP,
            LOCAL_IP,
            false,
        );
        data[tcp_end..].copy_from_slice(payload);
        assert!(port.tx_burst(vec![packet]).is_empty());
    }

    /// Discards whatever the engine transmitted, returning the last TCP
    /// header seen.
    fn drain(port: &EthPort) -> Option<tcp::TcpHeader> {
        let mut last = None;
        for packet in port.rx_packets(64) {
            let data = packet.data();
            if eth::EthHeader::parse(data).map(|h| h.ethertype) != Some(eth::ETHERTYPE_IPV4) {
                continue;
            }
            let ip_payload = &data[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN..];
            last = tcp::TcpHeader::parse(ip_payload, LOCAL_IP, PEER_IP, false).map(|(h, _)| h);
        }
        last
    }

    fn engine() {
        let args: Vec<String> = std::env::args().collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        eal::init(&args).expect("EAL initialization failed");
        {
            let pool = Mempool::create("bench", 8191, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1)
                .expect("failed to create mbuf pool");
            let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).expect("port init failed");
            let payload = vec![0xa5u8; MSS];
            let chunk = Bytes::from(payload.clone());
            let now = Instant::now();
            let mut events = Vec::new();

            bench("dpdk", "Mbuf alloc + free", 20_000_000, 0, || {
                black_box(Mbuf::alloc(&pool));
            });
            // What a TSO-sized segment costs to hand to the port, by where
            // the application's bytes are: on the heap they are copied
            // into pool mbufs; in DMA memory they are attached.
            const TSO_PAYLOAD: usize = 32 * 1024;
            let heap = Bytes::from(vec![0xa5u8; TSO_PAYLOAD]);
            bench(
                "dpdk",
                "32KB TSO payload from the heap: copy into chained mbufs",
                500_000,
                TSO_PAYLOAD,
                || {
                    let mut head = Mbuf::alloc(&pool).unwrap();
                    head.append(54).unwrap();
                    let mut data = &heap[..];
                    while !data.is_empty() {
                        let mut tail = Mbuf::alloc(&pool).unwrap();
                        let n = data.len().min(tail.tailroom() as usize);
                        tail.append(n as u16).unwrap().copy_from_slice(&data[..n]);
                        data = &data[n..];
                        head.chain(tail).ok().unwrap();
                    }
                    black_box(&head);
                },
            );
            let mut dma = httpio::dpdk::DmaBuffer::new(TSO_PAYLOAD).expect("no DMA memory");
            dma.as_mut_slice().fill(0xa5);
            let dma = dma.freeze();
            bench(
                "dpdk",
                "32KB TSO payload from DMA memory: attach (9 pieces, 4KB pages)",
                500_000,
                TSO_PAYLOAD,
                || {
                    let mut head = Mbuf::alloc(&pool).unwrap();
                    head.append(54).unwrap();
                    // One attachment per DMA-contiguous piece. Without
                    // hugepages (as here) that is every 4 KB page, so nine
                    // pieces; on hugepages the whole payload is one.
                    let mut rest = dma.clone();
                    while !rest.is_empty() {
                        let to_page_end = 4096 - (rest.as_ptr() as usize & 4095);
                        let piece = rest.split_to(to_page_end.min(rest.len()));
                        let tail = Mbuf::from_external_bytes(&pool, piece).unwrap();
                        head.chain(tail).ok().unwrap();
                    }
                    black_box(&head);
                },
            );
            // The application's side of the two: its one copy of a 32 KB
            // write, to the heap and into a recycled DMA block.
            let source = vec![0xa5u8; TSO_PAYLOAD];
            bench(
                "dpdk",
                "32KB write copied to the heap (Bytes::copy_from_slice)",
                500_000,
                TSO_PAYLOAD,
                || {
                    black_box(Bytes::copy_from_slice(black_box(&source)));
                },
            );
            let mut writer = httpio::dpdk::DmaWriter::new();
            bench(
                "dpdk",
                "32KB write copied into DMA memory (DmaWriter)",
                500_000,
                TSO_PAYLOAD,
                || {
                    black_box(writer.copy(black_box(&source)));
                },
            );

            bench(
                "dpdk",
                "net_ring tx_burst + rx_burst, 1 mbuf",
                5_000_000,
                0,
                || {
                    let packet = frame(&pool, eth::ETHERTYPE_IPV4, 64);
                    let mut batch = vec![packet];
                    port.tx_burst_in_place(&mut batch);
                    black_box(port.rx_packets(64).count());
                },
            );

            let mut engine = TcpEngine::new(EngineConfig {
                local_ip: LOCAL_IP,
                local_mac: LOCAL_MAC,
                gateway: None,
            });
            bench("engine", "poll, idle", 5_000_000, 0, || {
                engine.poll_into(&port, &pool, now, &mut events);
            });

            // Handshake against a hand-built peer.
            let tuple = engine.connect(PEER_IP, 80, 1234).unwrap();
            engine.set_nodelay(tuple, true);
            engine.poll_into(&port, &pool, now, &mut events);
            drain(&port);
            let mut reply = frame(&pool, arp::ETHERTYPE_ARP, arp::ARP_HDR_LEN);
            arp::ArpPacket {
                operation: arp::OP_REPLY,
                sender_mac: PEER_MAC,
                sender_ip: PEER_IP,
                target_mac: LOCAL_MAC,
                target_ip: LOCAL_IP,
            }
            .write(&mut reply.data_mut()[eth::ETH_HDR_LEN..]);
            assert!(port.tx_burst(vec![reply]).is_empty());
            engine.poll_into(&port, &pool, now, &mut events);
            let syn = drain(&port).expect("no SYN");
            let mut ours = syn.seq.wrapping_add(1);
            let mut peer_seq = 1000u32;
            inject(&port, &pool, &peer_synack(peer_seq, ours), &[]);
            peer_seq += 1;
            engine.poll_into(&port, &pool, now, &mut events);
            drain(&port);

            // The harness's own share of the two engine rows below.
            bench(
                "engine",
                "(harness) build + inject 1460B frame + drain",
                2_000_000,
                MSS,
                || {
                    // A stale segment: built and looped, then dropped unread.
                    inject(&port, &pool, &peer_header(0, 0, tcp::flags::RST), &payload);
                    drain(&port);
                },
            );

            bench(
                "engine",
                "receive 1460B: inject + poll + recv + ACK out",
                2_000_000,
                MSS,
                || {
                    inject(
                        &port,
                        &pool,
                        &peer_header(peer_seq, ours, tcp::flags::ACK),
                        &payload,
                    );
                    peer_seq = peer_seq.wrapping_add(MSS as u32);
                    engine.poll_into(&port, &pool, now, &mut events);
                    black_box(engine.recv(tuple, usize::MAX));
                    engine.poll_into(&port, &pool, now, &mut events);
                    drain(&port);
                },
            );

            bench(
                "engine",
                "send 1460B: send + poll + frame out + ACK in",
                2_000_000,
                MSS,
                || {
                    engine.send(tuple, chunk.clone());
                    engine.poll_into(&port, &pool, now, &mut events);
                    drain(&port);
                    ours = ours.wrapping_add(MSS as u32);
                    inject(
                        &port,
                        &pool,
                        &peer_header(peer_seq, ours, tcp::flags::ACK),
                        &[],
                    );
                    engine.poll_into(&port, &pool, now, &mut events);
                },
            );

            // The same segment with its payload already in DMA memory, as
            // `TcpStream` writes arrive on a multi-segment port: attached
            // to the frame, not copied into it. This port has no checksum
            // offload, so the payload is still read once to sum it.
            let mut staged = httpio::dpdk::DmaBuffer::new(MSS).expect("no DMA memory");
            staged.as_mut_slice().fill(0xa5);
            let staged = staged.freeze();
            bench(
                "engine",
                "send 1460B from DMA memory: attached, not copied",
                2_000_000,
                MSS,
                || {
                    engine.send(tuple, staged.clone());
                    engine.poll_into(&port, &pool, now, &mut events);
                    drain(&port);
                    ours = ours.wrapping_add(MSS as u32);
                    inject(
                        &port,
                        &pool,
                        &peer_header(peer_seq, ours, tcp::flags::ACK),
                        &[],
                    );
                    engine.poll_into(&port, &pool, now, &mut events);
                },
            );
        }
        eal::cleanup();
    }
}

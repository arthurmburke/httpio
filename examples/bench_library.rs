//! Isolated, established-connection software TCP comparison. No AF_PACKET.
//! `bench_library kernel` or `bench_library dpdk <EAL args>`.
//! BENCH_LIBRARY_ROUNDS=1000, BENCH_LIBRARY_BREAKDOWN=1 for diagnostic timings.
use std::hint::black_box;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const SIZES: [usize; 5] = [64, 1460, 16 * 1024, 64 * 1024, 1024 * 1024];

#[cfg(target_os = "linux")]
fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) },
        0
    );
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> u64 {
    0
}

#[derive(Default)]
struct Parts {
    tx_ns: u128,
    rx_ns: u128,
    forward_ns: u128,
    app_ns: u128,
}
#[cfg(dpdk)]
fn timed<T>(enabled: bool, total: &mut u128, f: impl FnOnce() -> T) -> T {
    if !enabled {
        return f();
    }
    let start = Instant::now();
    let value = f();
    *total += start.elapsed().as_nanos();
    value
}
fn run(label: &str, size: usize, mut transfer: impl FnMut(&[u8], &mut [u8], &mut Parts)) {
    let rounds: usize = std::env::var("BENCH_LIBRARY_ROUNDS").map_or(1000, |v| v.parse().unwrap());
    assert!(rounds > 0);
    let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut output = vec![0; size];
    for _ in 0..100 {
        transfer(&payload, &mut output, &mut Parts::default());
    }
    assert_eq!(output, payload);
    let mut parts = Parts::default();
    #[cfg(all(dpdk, feature = "tcp-metrics"))]
    httpio::dpdk::tcp::metrics::reset();
    let cpu = cpu_ns();
    let start = Instant::now();
    for _ in 0..rounds {
        transfer(black_box(&payload), black_box(&mut output), &mut parts);
    }
    let elapsed = start.elapsed();
    let cpu = cpu_ns() - cpu;
    let cpu_us = if cfg!(target_os = "linux") {
        cpu as f64 / rounds as f64 / 1000.0
    } else {
        f64::NAN
    };
    assert_eq!(output, payload);
    #[cfg(all(dpdk, feature = "tcp-metrics"))]
    if label.starts_with("dpdk") {
        eprintln!(
            "LIBRARY_METRICS bytes={size} rounds={rounds} {}",
            serde_json::to_string(&httpio::dpdk::tcp::metrics::snapshot()).unwrap()
        );
    }
    println!(
        "{label}\t{size}\t{rounds}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}",
        elapsed.as_secs_f64() * 1e6 / rounds as f64,
        cpu_us,
        size as f64 * rounds as f64 * 8.0 / elapsed.as_secs_f64() / 1e9,
        parts.tx_ns as f64 / rounds as f64 / 1000.0,
        parts.rx_ns as f64 / rounds as f64 / 1000.0,
        parts.forward_ns as f64 / rounds as f64 / 1000.0,
        parts.app_ns as f64 / rounds as f64 / 1000.0
    );
}
fn main() {
    #[cfg(all(dpdk, feature = "tcp-metrics"))]
    eprintln!(
        "Diagnostic build: tcp-metrics timers perturb performance; do not use as the headline benchmark."
    );
    let args: Vec<_> = std::env::args().collect();
    println!(
        "backend\tbytes\trounds\twall_us\tcpu_us\tpayload_gbit_s\tsender_engine_us\treceiver_engine_us\tharness_forward_us\tapp_api_copy_us"
    );
    match args.get(1).map(String::as_str) {
        Some("kernel") => kernel(),
        Some("dpdk") => dpdk(&args[2..]),
        _ => panic!("usage: bench_library kernel | dpdk EAL_ARGS"),
    }
}

fn kernel() {
    use std::net::{TcpListener, TcpStream};
    for size in SIZES {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut b, _) = listener.accept().unwrap();
        for stream in [&a, &b] {
            stream.set_nodelay(true).unwrap();
            stream.set_nonblocking(true).unwrap();
        }
        run("kernel-loopback", size, |payload, output, _| {
            let start = Instant::now();
            let (mut sent, mut received) = (0, 0);
            while received < payload.len() {
                if sent < payload.len() {
                    match a.write(&payload[sent..]) {
                        Ok(0) => panic!("closed sender"),
                        Ok(n) => sent += n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => panic!("{e}"),
                    }
                }
                match b.read(&mut output[received..]) {
                    Ok(0) => panic!("closed receiver"),
                    Ok(n) => received += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{e}"),
                }
                assert!(start.elapsed() < Duration::from_secs(5));
            }
            // The return byte makes completion application-observable and
            // carries the receiver's cumulative TCP ACK back to the sender.
            b.write_all(&[1]).unwrap();
            let mut reply = [0];
            loop {
                match a.read(&mut reply) {
                    Ok(1) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    other => panic!("reply: {other:?}"),
                }
                assert!(start.elapsed() < Duration::from_secs(5));
            }
            assert_eq!(reply, [1]);
        });
    }
}

#[cfg(not(dpdk))]
fn dpdk(_: &[String]) {
    panic!("requires the DPDK devcontainer");
}

/// What a physical NIC does between the two stacks when checksum offload
/// and TSO are on: cuts a TSO packet into MSS-sized wire packets, and hands
/// the receiver single-segment packets whose checksums it reports as
/// verified. Checksums are never computed; the receiver trusts the flags,
/// as it does with a real device. This is harness cost, not library cost.
#[cfg(dpdk)]
fn emulated_nic(
    packet: httpio::dpdk::Mbuf,
    pool: &httpio::dpdk::Mempool,
    scratch: &mut Vec<u8>,
    out: &mut std::collections::VecDeque<httpio::dpdk::Mbuf>,
) {
    use httpio::dpdk::{Mbuf, ffi};
    const GOOD: u64 =
        ffi::RTE_MBUF_F_RX_IP_CKSUM_GOOD as u64 | ffi::RTE_MBUF_F_RX_L4_CKSUM_GOOD as u64;
    let raw = packet.as_raw();
    // SAFETY: `packet` is a live, uniquely owned mbuf.
    let (flags, tx_offload, segments) = unsafe {
        (
            (*raw).ol_flags,
            (*raw).__bindgen_anon_3.tx_offload,
            (*raw).nb_segs,
        )
    };
    if segments == 1 && flags & ffi::RTE_MBUF_F_TX_TCP_SEG == 0 {
        let tx =
            ffi::RTE_MBUF_F_TX_IPV4 | ffi::RTE_MBUF_F_TX_IP_CKSUM | ffi::RTE_MBUF_F_TX_TCP_CKSUM;
        unsafe { (*raw).ol_flags = (flags & !tx) | GOOD };
        out.push_back(packet);
        return;
    }
    scratch.clear();
    for segment in packet.segments() {
        scratch.extend_from_slice(segment);
    }
    let header_len = 34 + usize::from(scratch[46] >> 4) * 4;
    let payload_len = scratch.len() - header_len;
    let mss = if flags & ffi::RTE_MBUF_F_TX_TCP_SEG != 0 {
        ((tx_offload >> 24) & 0xffff) as usize
    } else {
        payload_len
    };
    let seq = u32::from_be_bytes(scratch[38..42].try_into().unwrap());
    let tcp_flags = scratch[47];
    let mut offset = 0;
    while offset < payload_len {
        let n = mss.min(payload_len - offset);
        let last = offset + n == payload_len;
        let mut wire = Mbuf::alloc(pool).expect("harness pool exhausted");
        let buf = wire.append((header_len + n) as u16).unwrap();
        buf[..header_len].copy_from_slice(&scratch[..header_len]);
        buf[header_len..].copy_from_slice(&scratch[header_len + offset..header_len + offset + n]);
        buf[16..18].copy_from_slice(&((header_len - 14 + n) as u16).to_be_bytes());
        buf[38..42].copy_from_slice(&seq.wrapping_add(offset as u32).to_be_bytes());
        // FIN and PSH belong to the last wire packet only.
        buf[47] = if last { tcp_flags } else { tcp_flags & !0x09 };
        unsafe { (*wire.as_raw()).ol_flags = GOOD };
        out.push_back(wire);
        offset += n;
    }
}
#[cfg(dpdk)]
fn dpdk(args: &[String]) {
    use bytes::Bytes;
    use httpio::dpdk::tcp::{
        engine::{EngineConfig, TcpEngine},
        state::TcpState,
    };
    use httpio::dpdk::{self, EthPort, Mbuf, Mempool};
    let mut eal_args = vec!["bench_library"];
    eal_args.extend(args.iter().map(String::as_str));
    dpdk::eal::init(&eal_args).unwrap();
    let breakdown = std::env::var("BENCH_LIBRARY_BREAKDOWN").is_ok_and(|v| v == "1");
    {
        let pool = Mempool::create(
            "library-bench",
            16383,
            256,
            dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
            -1,
        )
        .unwrap();
        let mut a_port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).unwrap();
        let mut b_port = EthPort::init(1, &pool, 1024, 1024, 1500, -1).unwrap();
        // `net_ring` has no offloads. BENCH_LIBRARY_OFFLOAD=cksum|tso makes
        // the stack take the paths it takes on a physical NIC, with the
        // harness doing the NIC's part (see `emulated_nic`).
        let offload = std::env::var("BENCH_LIBRARY_OFFLOAD").unwrap_or_default();
        let emulate = match offload.as_str() {
            "" | "none" => false,
            "cksum" | "tso" => true,
            other => panic!("BENCH_LIBRARY_OFFLOAD: unknown mode {other:?}"),
        };
        let tso = offload == "tso";
        for port in [&mut a_port, &mut b_port] {
            let mut offloads = port.offloads();
            assert_eq!(offloads.tso_max_payload, 0, "expected a software device");
            assert!(
                !offloads.tx_checksum && !offloads.rx_checksum,
                "expected a software device"
            );
            if emulate {
                offloads.tx_checksum = true;
                offloads.rx_checksum = true;
                if tso {
                    offloads.tso_max_payload = 32 * 1024;
                }
                port.emulate_offloads(offloads);
            }
            eprintln!("Port offloads: {:?}", port.offloads());
        }
        let label = match (breakdown, offload.as_str()) {
            (false, "cksum") => "dpdk-ring-cksum",
            (false, "tso") => "dpdk-ring-tso",
            (false, _) => "dpdk-ring",
            (true, "cksum") => "dpdk-ring-cksum-breakdown",
            (true, "tso") => "dpdk-ring-tso-breakdown",
            (true, _) => "dpdk-ring-breakdown",
        };
        // A port's ring carries both what its engine transmitted and what
        // the harness delivered for it to receive. An engine reads at most
        // 64 packets per poll, so deliver at most that many at a time: then
        // everything in a ring after a poll is that engine's own output.
        // The rest waits here, as it would in a NIC's receive queue.
        let mut a_to_b: std::collections::VecDeque<Mbuf> = Default::default();
        let mut b_to_a: std::collections::VecDeque<Mbuf> = Default::default();
        let mut scratch: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut burst: Vec<Mbuf> = Vec::with_capacity(64);
        // BENCH_LIBRARY_DELIVER=1 hands an engine one packet per poll, which
        // is what a poll loop faster than the packet rate sees.
        let deliver: usize =
            std::env::var("BENCH_LIBRARY_DELIVER").map_or(64, |v| v.parse().unwrap());
        assert!((1..=64).contains(&deliver));
        // BENCH_LIBRARY_LOSS=N drops every Nth data packet from the sender
        // to the receiver (retransmissions included), after segmentation.
        let loss: usize = std::env::var("BENCH_LIBRARY_LOSS").map_or(0, |v| v.parse().unwrap());
        let mut data_packets = 0usize;
        let mut forward = |from: &EthPort,
                           to: &EthPort,
                           wire: &mut std::collections::VecDeque<Mbuf>,
                           lossy: bool| {
            let first_new = wire.len();
            loop {
                let before = wire.len();
                if emulate {
                    for packet in from.rx_packets(64) {
                        emulated_nic(packet, &pool, &mut scratch, wire);
                    }
                } else {
                    wire.extend(from.rx_packets(64));
                }
                if wire.len() == before {
                    break;
                }
            }
            if lossy && loss != 0 {
                let mut index = 0;
                wire.retain(|packet| {
                    index += 1;
                    if index <= first_new || packet.pkt_len() <= 100 {
                        return true;
                    }
                    data_packets += 1;
                    data_packets % loss != 0
                });
            }
            burst.extend(wire.drain(..wire.len().min(deliver)));
            to.tx_burst_in_place(&mut burst);
            assert!(burst.is_empty(), "harness ring overflow");
        };
        // BENCH_LIBRARY_BYTES=N runs one size only, for profiling.
        let only: Option<usize> = std::env::var("BENCH_LIBRARY_BYTES")
            .ok()
            .map(|v| v.parse().unwrap());
        for (case, size) in SIZES.into_iter().enumerate() {
            if only.is_some_and(|only| only != size) {
                continue;
            }
            let mut a = TcpEngine::new(EngineConfig {
                local_ip: "10.88.0.1".parse().unwrap(),
                local_mac: a_port.mac_addr().unwrap(),
                gateway: None,
            });
            let mut b = TcpEngine::new(EngineConfig {
                local_ip: "10.88.0.2".parse().unwrap(),
                local_mac: b_port.mac_addr().unwrap(),
                gateway: None,
            });
            if std::env::var("BENCH_LIBRARY_GRO").is_ok_and(|v| v == "0") {
                a.set_rx_gro(false);
                b.set_rx_gro(false);
            }
            b.listen(80);
            let a_tuple = a
                .connect("10.88.0.2".parse().unwrap(), 80, 2000 + case as u16)
                .unwrap();
            a.set_nodelay(a_tuple, true);
            let (mut a_events, mut b_events) = (Vec::new(), Vec::new());
            let mut accepted = None;
            let start = Instant::now();
            while accepted.is_none() || a.state(a_tuple) != Some(TcpState::Established) {
                a.poll_into(&a_port, &pool, Instant::now(), &mut a_events);
                forward(&a_port, &b_port, &mut a_to_b, true);
                b.poll_into(&b_port, &pool, Instant::now(), &mut b_events);
                forward(&b_port, &a_port, &mut b_to_a, false);
                if accepted.is_none() {
                    accepted = b.accept(80);
                }
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "handshake stalled"
                );
            }
            let b_tuple = accepted.unwrap();
            b.set_nodelay(b_tuple, true);
            // Payload creation is outside timing, matching kernel's preallocated buffer.
            // With TSO the stream layer hands the engine DMA memory to
            // attach rather than heap memory to copy (see `DmaWriter`).
            let payload = if tso {
                let mut buffer = dpdk::DmaBuffer::new(size).unwrap();
                for (i, b) in buffer.as_mut_slice().iter_mut().enumerate() {
                    *b = (i % 251) as u8;
                }
                buffer.freeze()
            } else {
                Bytes::from((0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>())
            };
            run(label, size, |_, output, parts| {
                timed(breakdown, &mut parts.app_ns, || {
                    a.send(a_tuple, payload.clone())
                });
                let mut received = 0;
                let mut replied = false;
                let start = Instant::now();
                loop {
                    timed(breakdown, &mut parts.tx_ns, || {
                        a.poll_into(&a_port, &pool, Instant::now(), &mut a_events)
                    });
                    timed(breakdown, &mut parts.forward_ns, || {
                        forward(&a_port, &b_port, &mut a_to_b, true)
                    });
                    timed(breakdown, &mut parts.rx_ns, || {
                        b.poll_into(&b_port, &pool, Instant::now(), &mut b_events)
                    });
                    timed(breakdown, &mut parts.forward_ns, || {
                        forward(&b_port, &a_port, &mut b_to_a, false)
                    });
                    timed(breakdown, &mut parts.app_ns, || {
                        loop {
                            let chunk = b.recv(b_tuple, size - received);
                            if chunk.is_empty() {
                                break;
                            }
                            output[received..received + chunk.len()].copy_from_slice(&chunk);
                            received += chunk.len();
                        }
                        if received == size && !replied {
                            b.send(b_tuple, Bytes::from_static(&[1]));
                            replied = true;
                        }
                    });
                    let reply = timed(breakdown, &mut parts.app_ns, || a.recv(a_tuple, 1));
                    if !reply.is_empty() {
                        assert_eq!(reply.as_ref(), &[1]);
                        break;
                    }
                    assert!(start.elapsed() < Duration::from_secs(5), "transfer stalled");
                }
            });
            // Discard residual ACK/window updates before creating the next pair.
            drop((a, b));
            a_to_b.clear();
            b_to_a.clear();
            drop(a_port.rx_packets(64));
            drop(b_port.rx_packets(64));
        }
    }
    dpdk::eal::cleanup();
}

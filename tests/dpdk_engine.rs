#![cfg(dpdk)]

#[path = "support/allocations.rs"]
mod allocations;
#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
use allocations::count_allocations;
use bytes::Bytes;
use httpio::core::time::{Duration, Instant};
use httpio::dpdk::{
    EthPort, Mbuf, Mempool, eal,
    mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
    net::{arp, eth, eth::EthAddr, ipv4, tcp},
    tcp::{
        engine::{EngineConfig, TcpEngine},
        rto::{MAX_RETRANSMITS, MAX_RTO},
        tcb::Event,
    },
};
use std::net::Ipv4Addr;

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const LOCAL_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 1]);
const PEER_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 2]);

fn ethernet_packet(pool: &Mempool, kind: u16, size: usize) -> Mbuf {
    let mut packet = Mbuf::alloc(pool).unwrap();
    let data = packet.append((eth::ETH_HDR_LEN + size) as u16).unwrap();
    eth::EthHeader {
        src: PEER_MAC,
        dst: LOCAL_MAC,
        ethertype: kind,
    }
    .write(data);
    packet
}

fn inject_tcp(port: &EthPort, pool: &Mempool, header: &tcp::TcpHeader, payload: &[u8]) {
    let size = ipv4::IPV4_HDR_LEN + header.wire_len() + payload.len();
    let mut packet = ethernet_packet(pool, eth::ETHERTYPE_IPV4, size);
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
    header.write(
        &mut data[ipv4::IPV4_HDR_LEN..ipv4::IPV4_HDR_LEN + header.wire_len()],
        payload,
        PEER_IP,
        LOCAL_IP,
        false,
    );
    data[ipv4::IPV4_HDR_LEN + header.wire_len()..].copy_from_slice(payload);
    assert!(port.tx_burst(vec![packet]).is_empty());
}

fn output(port: &EthPort) -> Vec<tcp::TcpHeader> {
    port.rx_burst(64)
        .into_iter()
        .filter_map(|packet| {
            let frame = packet.data();
            if eth::EthHeader::parse(frame)?.ethertype != eth::ETHERTYPE_IPV4 {
                return None;
            }
            let ip = ipv4::Ipv4Header::parse(&frame[eth::ETH_HDR_LEN..], true)?;
            tcp::TcpHeader::parse(
                &frame[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN
                    ..eth::ETH_HDR_LEN + ip.total_length as usize],
                ip.src,
                ip.dst,
                true,
            )
            .map(|(header, _)| header)
        })
        .collect()
}

/// TCP packets the engine put on the wire, with their payloads.
fn tcp_output(port: &EthPort) -> Vec<(tcp::TcpHeader, Vec<u8>)> {
    port.rx_burst(64)
        .into_iter()
        .filter_map(|packet| {
            let frame = packet.data();
            if eth::EthHeader::parse(frame)?.ethertype != eth::ETHERTYPE_IPV4 {
                return None;
            }
            let ip = ipv4::Ipv4Header::parse(&frame[eth::ETH_HDR_LEN..], true)?;
            let segment = &frame[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN
                ..eth::ETH_HDR_LEN + ip.total_length as usize];
            let (header, _) = tcp::TcpHeader::parse(segment, ip.src, ip.dst, true)?;
            let payload = segment[header.wire_len()..].to_vec();
            Some((header, payload))
        })
        .collect()
}

/// A corked tail's packet is built while the tail is held and sent as it
/// is on the flush -- but only when it is still the right packet.
fn corked_tails_are_sent_from_prebuilt_packets(port: &EthPort, pool: &Mempool) {
    let available = unsafe { httpio::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) };
    let mut engine = TcpEngine::new(EngineConfig {
        local_ip: LOCAL_IP,
        local_mac: LOCAL_MAC,
        gateway: None,
    });
    let now = Instant::now();
    let mut reply = ethernet_packet(pool, arp::ETHERTYPE_ARP, arp::ARP_HDR_LEN);
    arp::ArpPacket {
        operation: arp::OP_REPLY,
        sender_mac: PEER_MAC,
        sender_ip: PEER_IP,
        target_mac: LOCAL_MAC,
        target_ip: LOCAL_IP,
    }
    .write(&mut reply.data_mut()[eth::ETH_HDR_LEN..]);
    assert!(port.tx_burst(vec![reply]).is_empty());
    engine.poll(port, pool, now);
    let tuple = engine.connect(PEER_IP, 80, 5000).unwrap();
    engine.poll(port, pool, now);
    let syn = output(port).remove(0);
    let mut peer = tcp::TcpHeader {
        src_port: 80,
        dst_port: 5000,
        seq: 7000,
        ack: syn.seq.wrapping_add(1),
        flags: tcp::flags::SYN | tcp::flags::ACK,
        window: u16::MAX,
        urgent_pointer: 0,
        options: tcp::TcpOptions::default(),
    };
    inject_tcp(port, pool, &peer, &[]);
    engine.poll(port, pool, now);
    output(port);
    peer.seq += 1;
    peer.flags = tcp::flags::ACK;
    engine.set_cork(tuple, true);

    // Staged in two writes, held, then flushed: one packet, the one built
    // while it waited.
    engine.send(tuple, Bytes::from_static(b"held "));
    engine.poll(port, pool, now);
    engine.send(tuple, Bytes::from_static(b"tail"));
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty(), "the tail must be held");
    assert_eq!(engine.prebuilt_sent(), 0);
    engine.flush(tuple);
    engine.poll(port, pool, now);
    let sent = tcp_output(port);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, b"held tail");
    assert_eq!(sent[0].0.ack, peer.seq);
    assert!(sent[0].0.has_flag(tcp::flags::PSH));
    assert_eq!(engine.prebuilt_sent(), 1);
    peer.ack = sent[0].0.seq.wrapping_add(9);
    inject_tcp(port, pool, &peer, &[]);
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty());

    // The peer sends data while a tail is held, and the application reads
    // it: the packet is rebuilt with the new acknowledgement and window,
    // and that one is sent.
    engine.send(tuple, Bytes::from_static(b"second"));
    engine.poll(port, pool, now);
    inject_tcp(port, pool, &peer, &[9; 10]);
    peer.seq += 10;
    engine.poll(port, pool, now);
    engine.recv_each(tuple, usize::MAX, |_| true);
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty());
    engine.flush(tuple);
    engine.poll(port, pool, now);
    let sent = tcp_output(port);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, b"second");
    assert_eq!(sent[0].0.ack, peer.seq);
    assert_eq!(engine.prebuilt_sent(), 2);
    peer.ack = sent[0].0.seq.wrapping_add(6);

    // Data from the peer and the flush in the same poll: the packet built
    // earlier acknowledges too little, so it is not the one sent.
    engine.send(tuple, Bytes::from_static(b"third"));
    engine.poll(port, pool, now);
    inject_tcp(port, pool, &peer, &[9; 5]);
    peer.seq += 5;
    engine.flush(tuple);
    engine.poll(port, pool, now);
    let sent = tcp_output(port);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, b"third");
    assert_eq!(sent[0].0.ack, peer.seq, "a stale packet was sent");
    assert_eq!(engine.prebuilt_sent(), 2);
    peer.ack = sent[0].0.seq.wrapping_add(5);
    inject_tcp(port, pool, &peer, &[]);
    engine.poll(port, pool, now);
    tcp_output(port);

    // Uncorking releases a held tail just as a flush does.
    engine.send(tuple, Bytes::from_static(b"fourth"));
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty());
    engine.set_cork(tuple, false);
    engine.poll(port, pool, now);
    let sent = tcp_output(port);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, b"fourth");
    assert_eq!(engine.prebuilt_sent(), 3);

    // A held tail whose connection is reset is never sent: the peer gets
    // the reset and nothing else, and the packet built for the tail goes
    // back to the pool with it.
    let next = sent[0].0.seq.wrapping_add(6);
    engine.set_cork(tuple, true);
    engine.send(tuple, Bytes::from_static(b"never sent"));
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty());
    engine.recv_each(tuple, usize::MAX, |_| true);
    engine.reset(tuple);
    let events = engine.poll(port, pool, now);
    assert!(events.contains(&(tuple, Event::Reset)));
    let sent = tcp_output(port);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].0.has_flag(tcp::flags::RST));
    assert_eq!(sent[0].0.seq, next);
    assert!(sent[0].1.is_empty(), "held data went out with the reset");
    assert_eq!(engine.state(tuple), None);
    assert_eq!(engine.prebuilt_sent(), 3);
    engine.reset(tuple);
    engine.poll(port, pool, now);
    assert!(tcp_output(port).is_empty());
    drop(engine);
    assert_eq!(
        unsafe { httpio::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) },
        available
    );
}

#[test]
fn engine_transmits_window_updates_and_final_reset() {
    let cpu = unsafe { libc::sched_getcpu() };
    eal::init(&[
        "engine-test",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("0@{cpu}"),
        "--vdev=net_ring0",
    ])
    .unwrap();
    {
        let pool = Mempool::new("engine-test", 4095, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
        let mut port = EthPort::init(0, &pool, 128, 128, 1500, 0).unwrap();
        for burst in [1, 32, 64, 128, 256, u16::MAX] {
            port.set_tx_burst_limit(std::num::NonZeroU16::new(burst).unwrap());
            // Partial transmission must retain the unsent suffix and free all
            // received/abandoned buffers, without allocating batch storage.
            let available = unsafe { httpio::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) };
            let mut batch: Vec<_> = (0..2048u16)
                .map(|id| {
                    let mut packet = Mbuf::alloc(&pool).unwrap();
                    packet.append(2).unwrap().copy_from_slice(&id.to_be_bytes());
                    packet
                })
                .collect();
            let capacity = batch.capacity();
            let (_, count) = count_allocations(|| port.tx_burst_in_place(&mut batch));
            assert_eq!(count, 0);
            assert!(!batch.is_empty(), "expected virtual ring backpressure");
            let sent = 2048 - batch.len();
            assert!(sent > 0);
            assert_eq!(batch.capacity(), capacity);
            assert_eq!(batch[0].data(), &(sent as u16).to_be_bytes());
            let (_, count) = count_allocations(|| {
                let mut received = 0;
                while received < sent {
                    let packets = port.rx_packets(64);
                    assert!(packets.len() > 0);
                    for packet in packets {
                        assert_eq!(packet.data(), &(received as u16).to_be_bytes());
                        received += 1;
                    }
                }
            });
            assert_eq!(count, 0);
            batch.clear();
            assert_eq!(
                unsafe { httpio::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) },
                available
            );
            for _ in 0..4 {
                batch.push(Mbuf::alloc(&pool).unwrap());
            }
            port.tx_burst_in_place(&mut batch);
            let mut packets = port.rx_packets(64);
            drop(packets.next());
            drop(packets); // Drop the unconsumed suffix too.
            assert_eq!(
                unsafe { httpio::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) },
                available
            );
        }
        port.set_tx_burst_limit(std::num::NonZeroU16::new(64).unwrap());

        corked_tails_are_sent_from_prebuilt_packets(&port, &pool);

        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: LOCAL_IP,
            local_mac: LOCAL_MAC,
            gateway: None,
        });
        let mut now = Instant::now();
        // Learn the peer's MAC before the active open.
        let arp_reply = || {
            let mut packet = ethernet_packet(&pool, arp::ETHERTYPE_ARP, arp::ARP_HDR_LEN);
            arp::ArpPacket {
                operation: arp::OP_REPLY,
                sender_mac: PEER_MAC,
                sender_ip: PEER_IP,
                target_mac: LOCAL_MAC,
                target_ip: LOCAL_IP,
            }
            .write(&mut packet.data_mut()[eth::ETH_HDR_LEN..]);
            assert!(port.tx_burst(vec![packet]).is_empty());
        };
        // A cold next hop emits ARP, but must not consume the SYN or arm RTO.
        let tuple = engine.connect(PEER_IP, 80, 1234).unwrap();
        engine.poll(&port, &pool, now);
        let requests = port.rx_burst(64);
        assert_eq!(requests.len(), 1);
        assert_eq!(
            eth::EthHeader::parse(requests[0].data()).unwrap().ethertype,
            arp::ETHERTYPE_ARP
        );
        drop(requests);
        now += Duration::from_millis(1);
        arp_reply();
        engine.poll(&port, &pool, now);
        let syn = output(&port).remove(0); // immediate, without a one-second RTO
        assert!(syn.has_flag(tcp::flags::SYN));
        let mut peer = tcp::TcpHeader {
            src_port: 80,
            dst_port: 1234,
            seq: 1000,
            ack: syn.seq.wrapping_add(1),
            flags: tcp::flags::SYN | tcp::flags::ACK,
            window: u16::MAX,
            urgent_pointer: 0,
            options: tcp::TcpOptions::default(),
        };
        inject_tcp(&port, &pool, &peer, &[]);
        engine.poll(&port, &pool, now);
        output(&port);
        peer.seq += 1;
        peer.flags = tcp::flags::ACK;
        let mut events = Vec::new();
        for segment in 0..64 {
            inject_tcp(&port, &pool, &peer, &[42; 1024]);
            let (_, allocations) =
                count_allocations(|| engine.poll_into(&port, &pool, now, &mut events));
            // Wait until the reassembly queue has grown to hold 64 entries.
            if segment >= 48 {
                assert_eq!(allocations, 0, "steady-state RX allocated");
            }
            let acks = output(&port);
            peer.seq += 1024;
            // One packet per poll: every second in-order segment is
            // acknowledged, the one in between is not.
            if segment % 2 == 0 {
                assert!(acks.is_empty(), "lone segment acknowledged at once");
            } else {
                assert_eq!(acks.len(), 1);
                assert_eq!(acks[0].ack, peer.seq);
            }
        }
        // Pure ACKs and rejected payloads must not allocate Bytes owners.
        for _ in 0..3 {
            inject_tcp(&port, &pool, &peer, &[]);
            let (_, count) = count_allocations(|| engine.poll_into(&port, &pool, now, &mut events));
            assert_eq!(count, 0, "control packet allocated");
        }
        let mut invalid = peer.clone();
        invalid.seq = peer.seq.wrapping_add(1_000_000);
        inject_tcp(&port, &pool, &invalid, b"outside receive window");
        let (_, count) = count_allocations(|| engine.poll_into(&port, &pool, now, &mut events));
        assert_eq!(count, 0, "rejected payload allocated");
        output(&port);

        // An otherwise idle TCB must be reactivated by an application read.
        let (empty, allocations) = count_allocations(|| engine.recv(tuple, 0));
        assert!(empty.is_empty());
        assert_eq!(allocations, 0);
        // Reads are views of the mbuf: a split read shares it through
        // its own reference count, with no owner allocated for either part.
        let (prefix, allocations) = count_allocations(|| engine.recv(tuple, 256));
        assert_eq!(&prefix[..], &[42; 256]);
        assert_eq!(allocations, 0, "a read must not allocate");
        let (suffix, allocations) = count_allocations(|| engine.recv(tuple, 1024));
        assert_eq!(&suffix[..], &[42; 768]);
        assert_eq!(allocations, 0, "split reads must share the mbuf");
        assert_eq!(
            unsafe { prefix.as_ptr().add(prefix.len()) },
            suffix.as_ptr()
        );
        drop((prefix, suffix));
        engine.poll(&port, &pool, now);
        let update = output(&port);
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].window, 1024);
        assert_eq!(update[0].flags, tcp::flags::ACK);

        engine.send(tuple, Bytes::from_static(b"never acknowledged"));
        engine.poll(&port, &pool, now);
        output(&port);
        let mut resets = 0;
        let mut aborted = false;
        for _ in 0..=MAX_RETRANSMITS {
            now += MAX_RTO + Duration::from_secs(1);
            // Each step outlives the ARP entry; the peer still answers ARP
            // (it only ignores TCP), so the next hop stays resolvable.
            arp_reply();
            aborted |= engine
                .poll(&port, &pool, now)
                .contains(&(tuple, Event::Reset));
            resets += output(&port)
                .iter()
                .filter(|h| h.has_flag(tcp::flags::RST))
                .count();
        }
        assert!(aborted);
        assert_eq!(resets, 1);
        assert_eq!(engine.state(tuple), None);
        engine.poll(&port, &pool, now);
        assert!(output(&port).is_empty());

        // Pool exhaustion retains the SYN without advancing retransmission
        // backoff. It goes out immediately once an mbuf becomes available.
        arp_reply();
        engine.poll(&port, &pool, now);
        let starved = engine.connect(PEER_IP, 80, 2000).unwrap();
        let mut held = Vec::new();
        while let Some(packet) = Mbuf::alloc(&pool) {
            held.push(packet);
        }
        engine.poll(&port, &pool, now);
        assert_eq!(engine.pending_tx_len(), 1);
        for _ in 0..3 {
            now += Duration::from_secs(2);
            assert!(
                !engine
                    .poll(&port, &pool, now)
                    .contains(&(starved, Event::Reset))
            );
            assert_eq!(engine.pending_tx_len(), 1);
        }
        drop(held);
        engine.poll(&port, &pool, now);
        assert_eq!(engine.pending_tx_len(), 0);
        let sent = output(&port);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].src_port, 2000);
        engine.poll(&port, &pool, now + Duration::from_millis(500));
        assert!(output(&port).is_empty(), "RTO must start at NIC acceptance");

        // Fill the virtual NIC, leaving only the RX burst's freed slots.
        // A burst of new SYNs must retain its unaccepted suffix locally.
        let mut filler: Vec<_> = (0..2048).map(|_| Mbuf::alloc(&pool).unwrap()).collect();
        port.tx_burst_in_place(&mut filler);
        assert!(!filler.is_empty());
        drop(filler);
        for port_number in 3000..3128 {
            engine.connect(PEER_IP, 80, port_number).unwrap();
        }
        engine.poll(&port, &pool, now);
        assert!(engine.pending_tx_len() > 0);
        assert!(engine.pending_tx_len() <= 256);
        let mut source_ports = std::collections::HashSet::new();
        // Drain the NIC completely before the next poll (net_ring loops TX to RX).
        for _ in 0..32 {
            for hdr in output(&port) {
                if (3000..3128).contains(&hdr.src_port) {
                    assert!(source_ports.insert(hdr.src_port), "duplicate SYN");
                }
            }
        }
        engine.poll(&port, &pool, now);
        assert_eq!(engine.pending_tx_len(), 0);
        for _ in 0..4 {
            for hdr in output(&port) {
                if (3000..3128).contains(&hdr.src_port) {
                    assert!(source_ports.insert(hdr.src_port), "duplicate SYN");
                }
            }
        }
        assert_eq!(source_ports.len(), 128, "partial TX must not lose SYNs");

        // Unreachable neighbors still fail promptly instead of hanging connect forever.
        let unreachable = engine
            .connect(Ipv4Addr::new(10, 0, 0, 99), 80, 4000)
            .unwrap();
        engine.poll(&port, &pool, now);
        output(&port);
        let events = engine.poll(&port, &pool, now + Duration::from_secs(30));
        assert!(events.contains(&(unreachable, Event::Reset)));
        assert_eq!(engine.state(unreachable), None);
    }
    eal::cleanup();
}

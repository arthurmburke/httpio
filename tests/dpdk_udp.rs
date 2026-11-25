//! The engine's UDP layer against a peer the test plays itself, on a
//! `net_ring` port that loops what the engine transmits back to the test's
//! receive burst and what the test transmits to the engine's. EAL can be
//! initialized once per process, so everything runs in one test, in
//! sections that each leave the port drained.
#![cfg(dpdk)]

use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::Bytes;
use httpio::core::time::{Duration, Instant};
use httpio::dpdk::net::eth::EthAddr;
use httpio::dpdk::net::{arp, checksum, eth, ipv4, tcp, udp};
use httpio::dpdk::tcp::engine::{EngineConfig, Gateway, TcpEngine};
use httpio::dpdk::udp::{UdpError, UdpStatsSnapshot};
use httpio::dpdk::{
    DmaBuffer, EthPort, Mbuf, Mempool, eal, ffi, mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
};

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const LOCAL_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 1]);
const PEER_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 2]);

const fn peer(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(PEER_IP, port)
}

const fn local(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(LOCAL_IP, port)
}

/// How the injected datagram's checksum is filled in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Checksum {
    Valid,
    /// 0: the sender computed none.
    None,
    /// Valid, then one bit flipped.
    Corrupt,
}

fn available(pool: &Mempool) -> u32 {
    unsafe { ffi::rte_mempool_avail_count(pool.as_raw()) }
}

/// A complete Ethernet + IPv4 + UDP frame from `src` to `dst`.
fn udp_frame(
    pool: &Mempool,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
    checksum: Checksum,
    fragment: u16,
) -> Mbuf {
    let ip_len = ipv4::IPV4_HDR_LEN + udp::UDP_HDR_LEN + payload.len();
    let mut packet = Mbuf::alloc(pool).unwrap();
    let data = packet.append((eth::ETH_HDR_LEN + ip_len) as u16).unwrap();
    eth::EthHeader {
        dst: LOCAL_MAC,
        src: PEER_MAC,
        ethertype: eth::ETHERTYPE_IPV4,
    }
    .write(data);
    let data = &mut data[eth::ETH_HDR_LEN..];
    ipv4::Ipv4Header {
        dscp_ecn: 0,
        total_length: ip_len as u16,
        identification: 0,
        flags_fragment_offset: fragment,
        ttl: 64,
        protocol: ipv4::PROTO_UDP,
        src: *src.ip(),
        dst: *dst.ip(),
    }
    .write(data, false);
    let (header, rest) = data[ipv4::IPV4_HDR_LEN..].split_at_mut(udp::UDP_HDR_LEN);
    rest.copy_from_slice(payload);
    udp::UdpHeader {
        src_port: src.port(),
        dst_port: dst.port(),
        length: 0,
        checksum: 0,
    }
    .write(header, payload, *src.ip(), *dst.ip(), false);
    match checksum {
        Checksum::Valid => {}
        Checksum::None => header[6..8].fill(0),
        Checksum::Corrupt => header[7] ^= 0x01,
    }
    packet
}

fn inject(port: &EthPort, packet: Mbuf) {
    assert!(port.tx_burst(vec![packet]).is_empty());
}

fn inject_udp(
    port: &EthPort,
    pool: &Mempool,
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
    checksum: Checksum,
) {
    inject(port, udp_frame(pool, src, dst, payload, checksum, 0x4000));
}

fn inject_arp_reply(port: &EthPort, pool: &Mempool, ip: Ipv4Addr) {
    let mut reply = Mbuf::alloc(pool).unwrap();
    let data = reply
        .append((eth::ETH_HDR_LEN + arp::ARP_HDR_LEN) as u16)
        .unwrap();
    eth::EthHeader {
        dst: LOCAL_MAC,
        src: PEER_MAC,
        ethertype: arp::ETHERTYPE_ARP,
    }
    .write(data);
    arp::ArpPacket {
        operation: arp::OP_REPLY,
        sender_mac: PEER_MAC,
        sender_ip: ip,
        target_mac: LOCAL_MAC,
        target_ip: LOCAL_IP,
    }
    .write(&mut data[eth::ETH_HDR_LEN..]);
    inject(port, reply);
}

/// One UDP packet the engine transmitted, with its checksums verified in
/// software (`net_ring` has no offload) unless `offloaded`.
#[derive(Debug)]
struct Sent {
    eth: eth::EthHeader,
    ip: ipv4::Ipv4Header,
    udp: udp::UdpHeader,
    payload: Vec<u8>,
    /// The payload's segments' addresses (more than one when attached).
    segments: Vec<*const u8>,
    ol_flags: u64,
}

/// What the engine transmitted since the last drain.
#[derive(Default, Debug)]
struct Output {
    udp: Vec<Sent>,
    arp_requests: Vec<Ipv4Addr>,
    tcp: Vec<tcp::TcpHeader>,
}

fn drain(port: &EthPort) -> Output {
    let mut out = Output::default();
    loop {
        let packets = port.rx_burst(64);
        if packets.is_empty() {
            return out;
        }
        for packet in packets {
            let flat: Vec<u8> = packet.segments().flatten().copied().collect();
            let ether = eth::EthHeader::parse(&flat).unwrap();
            match ether.ethertype {
                arp::ETHERTYPE_ARP => {
                    let request = arp::ArpPacket::parse(&flat[eth::ETH_HDR_LEN..]).unwrap();
                    assert_eq!(request.operation, arp::OP_REQUEST);
                    assert_eq!(ether.dst, EthAddr::BROADCAST);
                    out.arp_requests.push(request.target_ip);
                }
                eth::ETHERTYPE_IPV4 => {
                    let offloaded = packet.ol_flags() & ffi::RTE_MBUF_F_TX_L4_MASK
                        == ffi::RTE_MBUF_F_TX_UDP_CKSUM;
                    let ip =
                        ipv4::Ipv4Header::parse(&flat[eth::ETH_HDR_LEN..], !offloaded).unwrap();
                    let l4 = &flat[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN
                        ..eth::ETH_HDR_LEN + ip.total_length as usize];
                    if ip.protocol == ipv4::PROTO_TCP {
                        out.tcp
                            .push(tcp::TcpHeader::parse(l4, ip.src, ip.dst, true).unwrap().0);
                        continue;
                    }
                    assert_eq!(ip.protocol, ipv4::PROTO_UDP);
                    let (header, len) =
                        udp::UdpHeader::parse(l4, ip.src, ip.dst, !offloaded).unwrap();
                    if !offloaded {
                        assert_ne!(header.checksum, 0, "software path always computes one");
                    }
                    let mut segments = Vec::new();
                    let mut at = 0;
                    for segment in packet.segments() {
                        if at + segment.len() > 42 && !segment.is_empty() {
                            segments.push(segment[42usize.saturating_sub(at)..].as_ptr());
                        }
                        at += segment.len();
                    }
                    out.udp.push(Sent {
                        eth: ether,
                        ip,
                        udp: header,
                        payload: l4[udp::UDP_HDR_LEN..udp::UDP_HDR_LEN + len].to_vec(),
                        segments,
                        ol_flags: packet.ol_flags(),
                    });
                }
                other => panic!("unexpected ethertype {other:#x}"),
            }
        }
    }
}

/// Polls and returns what the engine transmitted, so that none of it
/// loops back into the next poll.
fn poll(engine: &mut TcpEngine, port: &EthPort, pool: &Mempool, now: Instant) -> Output {
    engine.poll(port, pool, now);
    drain(port)
}

fn stats(engine: &TcpEngine, port: u16) -> UdpStatsSnapshot {
    engine.udp().stats(port).unwrap().snapshot()
}

#[test]
fn udp_engine_against_a_ring_peer() {
    let cpu = unsafe { libc::sched_getcpu() };
    eal::init(&[
        "udp-test",
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
        let pool = Mempool::new("udp-test", 4095, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
        let mut port = EthPort::init(0, &pool, 128, 128, 1500, 0).unwrap();
        let offloads = port.offloads();
        assert!(
            !offloads.tx_udp_checksum && !offloads.rx_udp_checksum,
            "expected a software device"
        );
        assert!(port.udp_steered(), "one queue is trivially steered");
        let baseline = available(&pool);
        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: LOCAL_IP,
            local_mac: LOCAL_MAC,
            gateway: None,
        });
        let now = Instant::now();
        let mut now_plus = |secs| now + Duration::from_secs(secs);

        receive(&mut engine, &port, &pool, now);
        transmit(&mut engine, &port, &pool, now, &mut now_plus);
        offloads_and_zero_copy(&mut engine, &mut port, &pool, now);
        port.emulate_offloads(offloads);
        tcp_alongside(&mut engine, &port, &pool, now);
        directed_broadcast(&port, &pool, now);

        drop(engine);
        drain(&port);
        assert_eq!(available(&pool), baseline, "an mbuf leaked");
    }
    eal::cleanup();
}

fn receive(engine: &mut TcpEngine, port: &EthPort, pool: &Mempool, now: Instant) {
    let udp = engine.udp_mut();
    assert_eq!(udp.bind(7000), Ok(()));
    assert_eq!(udp.bind(7000), Err(UdpError::AddrInUse));
    assert_eq!(udp.bind(0), Err(UdpError::InvalidAddress));

    // Delivered as a view of the mbuf it arrived in: the mbuf stays out of
    // the pool for as long as the datagram is held.
    let before = available(pool);
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7000),
        b"hello",
        Checksum::Valid,
    );
    assert!(poll(engine, port, pool, now).udp.is_empty());
    assert_eq!(engine.udp().updated_bindings(), &[7000]);
    assert_eq!(engine.udp().pending_rx(7000), 1);
    let datagram = engine.udp_mut().recv_from(7000).unwrap();
    assert_eq!(datagram.src, peer(5000));
    assert_eq!(datagram.dst, local(7000));
    assert_eq!(&datagram.data[..], b"hello");
    assert_eq!(available(pool), before - 1, "the payload was copied");
    assert_eq!(&datagram.clone().into_bytes()[..], b"hello");
    drop(datagram);
    assert_eq!(available(pool), before);
    assert!(engine.udp_mut().recv_from(7000).is_none());
    // A poll with nothing new lists nothing.
    poll(engine, port, pool, now);
    assert!(engine.udp().updated_bindings().is_empty());

    // No checksum (0) is accepted; a wrong one is not.
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7000),
        b"no checksum",
        Checksum::None,
    );
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7000),
        b"corrupt",
        Checksum::Corrupt,
    );
    // Neither is a fragment, nor a datagram for an unbound port, nor one
    // for another host.
    inject(
        port,
        udp_frame(
            pool,
            peer(5000),
            local(7000),
            b"fragment",
            Checksum::Valid,
            0x2000,
        ),
    );
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7001),
        b"unbound",
        Checksum::Valid,
    );
    inject_udp(
        port,
        pool,
        peer(5000),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 7000),
        b"not ours",
        Checksum::Valid,
    );
    // A UDP length past the end of the packet.
    let mut bad_length = udp_frame(pool, peer(5000), local(7000), b"x", Checksum::None, 0x4000);
    bad_length.data_mut()[38..40].copy_from_slice(&100u16.to_be_bytes());
    inject(port, bad_length);
    // A datagram larger than one receive buffer arrives chained.
    let mut chained = udp_frame(
        pool,
        peer(5000),
        local(7000),
        b"head",
        Checksum::None,
        0x4000,
    );
    let mut tail = Mbuf::alloc(pool).unwrap();
    tail.append(4).unwrap().copy_from_slice(b"tail");
    assert!(chained.chain(tail).is_ok());
    {
        let data = chained.data_mut();
        data[16..18].copy_from_slice(&(20u16 + 8 + 8).to_be_bytes());
        data[38..40].copy_from_slice(&16u16.to_be_bytes());
        data[24..26].fill(0);
        let csum = checksum::checksum(&data[14..34]);
        data[24..26].copy_from_slice(&csum.to_be_bytes());
    }
    inject(port, chained);
    // Limited broadcast is delivered too.
    inject_udp(
        port,
        pool,
        peer(5000),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, 7000),
        b"everyone",
        Checksum::Valid,
    );
    poll(engine, port, pool, now);
    let counters = engine.udp().counters();
    assert_eq!(counters.rx_bad_checksum, 1);
    assert_eq!(counters.rx_fragmented, 1);
    assert_eq!(counters.rx_unbound, 1);
    assert_eq!(counters.rx_malformed, 1);
    assert_eq!(counters.rx_chained, 1);
    let mut got = Vec::new();
    engine.udp_mut().recv_each(7000, |datagram| {
        got.push((datagram.dst, datagram.data.to_vec()));
        Ok(())
    });
    assert_eq!(
        got,
        [
            (local(7000), b"no checksum".to_vec()),
            (
                SocketAddrV4::new(Ipv4Addr::BROADCAST, 7000),
                b"everyone".to_vec()
            ),
        ]
    );

    // Connected: only the peer's datagrams are delivered.
    let udp = engine.udp_mut();
    assert_eq!(udp.connect(7000, Some(peer(5000))), Ok(()));
    assert_eq!(udp.connect(7001, None), Err(UdpError::NotBound));
    inject_udp(
        port,
        pool,
        peer(5001),
        local(7000),
        b"stranger",
        Checksum::Valid,
    );
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7000),
        b"friend",
        Checksum::Valid,
    );
    poll(engine, port, pool, now);
    let udp = engine.udp_mut();
    assert_eq!(&udp.recv_from(7000).unwrap().data[..], b"friend");
    assert!(udp.recv_from(7000).is_none());
    assert_eq!(stats(engine, 7000).rx_dropped_filtered, 1);
    engine.udp_mut().connect(7000, None).unwrap();

    // A full receive queue drops the newest; `recv_each` can stop and keep
    // the rest.
    engine.udp_mut().bind_with_capacity(7002, 4).unwrap();
    for i in 0..6u8 {
        inject_udp(port, pool, peer(5000), local(7002), &[i], Checksum::Valid);
    }
    poll(engine, port, pool, now);
    assert_eq!(engine.udp().pending_rx(7002), 4);
    let s = stats(engine, 7002);
    assert_eq!(
        (s.rx_datagrams, s.rx_bytes, s.rx_dropped_queue_full),
        (4, 4, 2)
    );
    let mut first = Vec::new();
    engine.udp_mut().recv_each(7002, |datagram| {
        if first.len() == 2 {
            return Err(datagram);
        }
        first.push(datagram.data[0]);
        Ok(())
    });
    assert_eq!(first, [0, 1]);
    assert_eq!(engine.udp().pending_rx(7002), 2);
    assert_eq!(engine.udp_mut().recv_from(7002).unwrap().data[0], 2);

    // Unbinding frees what it still held.
    let before = available(pool);
    engine.udp_mut().unbind(7002);
    assert_eq!(available(pool), before + 1);
    assert!(engine.udp().stats(7002).is_none());
    assert_eq!(engine.udp().pending_rx(7002), 0);

    // However large the queues, held datagrams never take the last
    // quarter of the receive pool: that is the NIC's, to refill its ring.
    let pool_size = available(pool) + 1; // a little is in flight elsewhere
    engine.udp_mut().bind_with_capacity(7003, 1 << 16).unwrap();
    let mut sent = 0;
    while stats(engine, 7003).rx_dropped_queue_full == 0 {
        inject_udp(port, pool, peer(5000), local(7003), b"pin", Checksum::Valid);
        poll(engine, port, pool, now);
        sent += 1;
        assert!(sent < 4096, "the pool was never protected");
    }
    let held = engine.udp().pending_rx(7003);
    assert_eq!(held, sent - 1);
    assert!(held > 2000, "only {held} were queued");
    assert!(
        available(pool) >= 4095 / 4 - 1,
        "{} left of {pool_size}",
        available(pool)
    );
    // Freed, the pool takes datagrams again.
    let before = available(pool);
    engine.udp_mut().recv_each(7003, |_| Ok(()));
    assert_eq!(available(pool), before + held as u32);
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7003),
        b"again",
        Checksum::Valid,
    );
    poll(engine, port, pool, now);
    assert_eq!(engine.udp().pending_rx(7003), 1);
    engine.udp_mut().unbind(7003);
}

/// With a gateway, the engine knows its subnet: a datagram to the
/// subnet-directed broadcast address goes to the broadcast MAC, without
/// ARP. On a /16 the same address is an ordinary host, resolved by ARP.
fn directed_broadcast(port: &EthPort, pool: &Mempool, now: Instant) {
    let dst = Ipv4Addr::new(10, 0, 0, 255);
    for (prefix_len, broadcast) in [(24, true), (16, false)] {
        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: LOCAL_IP,
            local_mac: LOCAL_MAC,
            gateway: Some(Gateway {
                ip: Ipv4Addr::new(10, 0, 0, 254),
                prefix_len,
            }),
        });
        let udp = engine.udp_mut();
        udp.bind(7000).unwrap();
        udp.send_to(7000, SocketAddrV4::new(dst, 9), Bytes::from_static(b"all"))
            .unwrap();
        let out = poll(&mut engine, port, pool, now);
        if broadcast {
            assert!(out.arp_requests.is_empty());
            assert_eq!(out.udp.len(), 1);
            assert_eq!(out.udp[0].eth.dst, EthAddr::BROADCAST);
            assert_eq!(out.udp[0].ip.dst, dst);
        } else {
            assert!(out.udp.is_empty());
            assert_eq!(out.arp_requests, [dst]);
        }
    }
}

fn transmit(
    engine: &mut TcpEngine,
    port: &EthPort,
    pool: &Mempool,
    now: Instant,
    now_plus: &mut impl FnMut(u64) -> Instant,
) {
    let udp = engine.udp_mut();
    assert_eq!(
        udp.send_to(7001, peer(5000), Bytes::from_static(b"x")),
        Err(UdpError::NotBound)
    );
    assert_eq!(
        udp.send_to(7000, peer(0), Bytes::from_static(b"x")),
        Err(UdpError::InvalidAddress)
    );
    // MTU 1500 less 28 bytes of headers; the pool's buffers are larger.
    assert_eq!(udp.max_payload(), 1472);
    assert_eq!(
        udp.send_to(7000, peer(5000), Bytes::from(vec![0; 1473])),
        Err(UdpError::TooLarge)
    );

    // Unknown next hop: the ARP request goes out in the same poll, the
    // datagram once the reply is in.
    udp.send_to(7000, peer(5000), Bytes::from_static(b"first"))
        .unwrap();
    assert_eq!(udp.pending_tx(), 1);
    let out = poll(engine, port, pool, now);
    assert!(out.udp.is_empty());
    assert_eq!(out.arp_requests, [PEER_IP]);
    assert_eq!(engine.udp().pending_tx(), 1);
    inject_arp_reply(port, pool, PEER_IP);
    let out = poll(engine, port, pool, now);
    assert_eq!(out.udp.len(), 1);
    let sent = &out.udp[0];
    assert_eq!((sent.eth.src, sent.eth.dst), (LOCAL_MAC, PEER_MAC));
    assert_eq!((sent.ip.src, sent.ip.dst), (LOCAL_IP, PEER_IP));
    assert_eq!(sent.ip.flags_fragment_offset, 0x4000, "Don't Fragment");
    assert_eq!(sent.ip.ttl, 64);
    assert_eq!((sent.udp.src_port, sent.udp.dst_port), (7000, 5000));
    assert_eq!(usize::from(sent.udp.length), 8 + 5);
    assert_eq!(sent.payload, b"first");
    assert_eq!(engine.udp().pending_tx(), 0);

    // Resolved: straight out, the largest one included, in order.
    let largest: Vec<u8> = (0..1472).map(|i| i as u8).collect();
    let udp = engine.udp_mut();
    udp.send_to(7000, peer(5000), Bytes::from_static(b"second"))
        .unwrap();
    udp.send_to(7000, peer(5001), Bytes::from(largest.clone()))
        .unwrap();
    udp.send_to(7000, peer(5000), Bytes::new()).unwrap();
    let out = poll(engine, port, pool, now);
    let payloads: Vec<_> = out
        .udp
        .iter()
        .map(|s| (s.udp.dst_port, s.payload.clone()))
        .collect();
    assert_eq!(
        payloads,
        [
            (5000, b"second".to_vec()),
            (5001, largest),
            (5000, Vec::new())
        ]
    );
    let s = stats(engine, 7000);
    assert_eq!(
        (s.tx_datagrams, s.tx_bytes, s.tx_dropped),
        (4, 5 + 6 + 1472, 0)
    );

    // Broadcast and multicast need no ARP.
    let udp = engine.udp_mut();
    for dst in [
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(239, 1, 2, 3),
        Ipv4Addr::new(224, 129, 2, 3),
    ] {
        udp.send_to(7000, SocketAddrV4::new(dst, 9), Bytes::from_static(b"all"))
            .unwrap();
    }
    let out = poll(engine, port, pool, now);
    assert!(out.arp_requests.is_empty());
    let macs: Vec<_> = out.udp.iter().map(|s| (s.ip.dst, s.eth.dst)).collect();
    assert_eq!(
        macs,
        [
            (Ipv4Addr::BROADCAST, EthAddr::BROADCAST),
            (
                Ipv4Addr::new(239, 1, 2, 3),
                EthAddr::new([1, 0, 0x5e, 1, 2, 3])
            ),
            (
                Ipv4Addr::new(224, 129, 2, 3),
                EthAddr::new([1, 0, 0x5e, 1, 2, 3])
            ),
        ]
    );

    // A next hop that never answers: dropped after the wait, and counted.
    let nowhere = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 99), 9);
    engine
        .udp_mut()
        .send_to(7000, nowhere, Bytes::from_static(b"lost"))
        .unwrap();
    assert_eq!(poll(engine, port, pool, now).arp_requests, [*nowhere.ip()]);
    let out = poll(engine, port, pool, now_plus(1));
    assert!(out.udp.is_empty());
    assert_eq!(out.arp_requests, [*nowhere.ip()], "the request is repeated");
    assert_eq!(engine.udp().pending_tx(), 1);
    assert!(poll(engine, port, pool, now_plus(3)).udp.is_empty());
    assert_eq!(engine.udp().pending_tx(), 0);
    assert_eq!(stats(engine, 7000).tx_dropped, 1);

    // At most 64 wait on ARP: beyond that the oldest are dropped.
    let elsewhere = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 98), 9);
    for _ in 0..70 {
        engine
            .udp_mut()
            .send_to(7000, elsewhere, Bytes::from_static(b"many"))
            .unwrap();
    }
    poll(engine, port, pool, now_plus(4));
    // Per-poll budget: 64 moved this poll, the other 6 next.
    assert_eq!(engine.udp().pending_tx(), 70);
    poll(engine, port, pool, now_plus(4));
    assert_eq!(engine.udp().pending_tx(), 64);
    assert_eq!(stats(engine, 7000).tx_dropped, 1 + 6);
    poll(engine, port, pool, now_plus(8));
    assert_eq!(engine.udp().pending_tx(), 0);
    assert_eq!(stats(engine, 7000).tx_dropped, 1 + 70);

    // The outbound queue is bounded.
    let udp = engine.udp_mut();
    udp.set_outbound_capacity(2);
    assert_eq!(udp.outbound_room(), 2);
    udp.send_to(7000, peer(5000), Bytes::from_static(b"a"))
        .unwrap();
    udp.send_to(7000, peer(5000), Bytes::from_static(b"b"))
        .unwrap();
    assert_eq!(
        udp.send_to(7000, peer(5000), Bytes::from_static(b"c")),
        Err(UdpError::QueueFull)
    );
    // A datagram queued before its binding goes still goes out, and counts.
    let early = engine.udp().stats(7000).unwrap().clone();
    engine.udp_mut().unbind(7000);
    assert_eq!(poll(engine, port, pool, now_plus(8)).udp.len(), 2);
    assert_eq!(early.snapshot().tx_datagrams, 4 + 3 + 2);
    let udp = engine.udp_mut();
    udp.set_outbound_capacity(1024);
    udp.bind(7000).unwrap();
}

fn offloads_and_zero_copy(
    engine: &mut TcpEngine,
    port: &mut EthPort,
    pool: &Mempool,
    now: Instant,
) {
    // TX offload: only the pseudo-header sum is written, and the mbuf asks
    // for the UDP (not TCP) checksum.
    let mut offloads = port.offloads();
    offloads.tx_udp_checksum = true;
    offloads.rx_udp_checksum = true;
    port.emulate_offloads(offloads);
    engine
        .udp_mut()
        .send_to(7000, peer(5000), Bytes::from_static(b"offloaded"))
        .unwrap();
    let out = poll(engine, port, pool, now);
    let sent = &out.udp[0];
    let pseudo = checksum::ipv4_pseudo_header_sum(LOCAL_IP, PEER_IP, ipv4::PROTO_UDP, 8 + 9);
    assert_eq!(sent.udp.checksum, checksum::fold_raw(pseudo));
    assert_eq!(
        sent.ol_flags & ffi::RTE_MBUF_F_TX_L4_MASK,
        ffi::RTE_MBUF_F_TX_UDP_CKSUM
    );
    assert_ne!(sent.ol_flags & ffi::RTE_MBUF_F_TX_IP_CKSUM, 0);

    // RX offload: an L4-good flag is trusted only when UDP RX offload is
    // on. The datagram is corrupt; only the flag says otherwise.
    let flagged = |pool: &Mempool| {
        let packet = udp_frame(
            pool,
            peer(5000),
            local(7000),
            b"trusted",
            Checksum::Corrupt,
            0x4000,
        );
        unsafe {
            (*packet.as_raw()).ol_flags |= ffi::RTE_MBUF_F_RX_L4_CKSUM_GOOD as u64;
        }
        packet
    };
    inject(port, flagged(pool));
    poll(engine, port, pool, now);
    assert_eq!(engine.udp().pending_rx(7000), 1);
    engine.udp_mut().recv_from(7000).unwrap();
    offloads.rx_udp_checksum = false;
    port.emulate_offloads(offloads);
    let bad_before = engine.udp().counters().rx_bad_checksum;
    inject(port, flagged(pool));
    poll(engine, port, pool, now);
    assert_eq!(engine.udp().pending_rx(7000), 0);
    assert_eq!(engine.udp().counters().rx_bad_checksum, bad_before + 1);

    // On a port that chains mbufs (software checksum, to verify it end to
    // end), a DMA-capable payload that fits one buffer is still copied:
    // that costs less than attaching it.
    offloads.tx_udp_checksum = false;
    offloads.tx_multi_segment = true;
    offloads.tx_max_segments = 8;
    port.emulate_offloads(offloads);
    let mut dma = DmaBuffer::new(1000).unwrap();
    for (i, b) in dma.as_mut_slice().iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    let payload = dma.freeze();
    engine
        .udp_mut()
        .send_to(7000, peer(5000), payload.clone())
        .unwrap();
    let out = poll(engine, port, pool, now);
    let sent = &out.udp[0];
    assert_eq!(sent.payload, &payload[..]);
    assert_ne!(sent.segments, [payload.as_ptr()], "a small payload was attached");
    // One larger than the transmit pool's buffers is attached, not copied.
    // (The engine takes its limits from the pool it polls with.)
    let small = Mempool::new("udp-small-tx", 255, 0, 128 + 512, -1).unwrap();
    engine.poll(port, &small, now);
    drain(port);
    assert!(engine.udp().max_payload() < payload.len());
    assert!(engine.udp().max_zero_copy_payload() >= payload.len());
    engine
        .udp_mut()
        .send_to(7000, peer(5000), payload.clone())
        .unwrap();
    let out = poll(engine, port, &small, now);
    let sent = &out.udp[0];
    assert_eq!(sent.payload, &payload[..]);
    assert_eq!(sent.segments, [payload.as_ptr()], "the payload was copied");
    // Back to the test pool's limits.
    engine.poll(port, pool, now);
    drain(port);
    // Heap memory is copied as before.
    let heap = Bytes::from(vec![3u8; 100]);
    engine
        .udp_mut()
        .send_to(7000, peer(5000), heap.clone())
        .unwrap();
    let out = poll(engine, port, pool, now);
    assert_eq!(out.udp[0].payload, &heap[..]);
    assert_ne!(out.udp[0].segments, [heap.as_ptr()]);
}

fn tcp_alongside(engine: &mut TcpEngine, port: &EthPort, pool: &Mempool, now: Instant) {
    // TCP on the same engine is untouched: a SYN to a listener gets its
    // SYN-ACK, in the same poll a datagram is received and one sent.
    engine.listen(80);
    let syn = tcp::TcpHeader {
        src_port: 40000,
        dst_port: 80,
        seq: 1000,
        ack: 0,
        flags: tcp::flags::SYN,
        window: u16::MAX,
        urgent_pointer: 0,
        options: tcp::TcpOptions::default(),
    };
    let size = ipv4::IPV4_HDR_LEN + syn.wire_len();
    let mut packet = Mbuf::alloc(pool).unwrap();
    let data = packet.append((eth::ETH_HDR_LEN + size) as u16).unwrap();
    eth::EthHeader {
        dst: LOCAL_MAC,
        src: PEER_MAC,
        ethertype: eth::ETHERTYPE_IPV4,
    }
    .write(data);
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
    .write(&mut data[eth::ETH_HDR_LEN..], false);
    syn.write(
        &mut data[34..34 + syn.wire_len()],
        &[],
        PEER_IP,
        LOCAL_IP,
        false,
    );
    inject(port, packet);
    inject_udp(
        port,
        pool,
        peer(5000),
        local(7000),
        b"ping",
        Checksum::Valid,
    );
    engine
        .udp_mut()
        .send_to(7000, peer(5000), Bytes::from_static(b"pong"))
        .unwrap();
    let out = poll(engine, port, pool, now);
    assert_eq!(out.tcp.len(), 1);
    assert_eq!(out.tcp[0].flags, tcp::flags::SYN | tcp::flags::ACK);
    assert_eq!(out.tcp[0].ack, 1001);
    assert_eq!(out.udp.len(), 1);
    assert_eq!(out.udp[0].payload, b"pong");
    assert_eq!(&engine.udp_mut().recv_from(7000).unwrap().data[..], b"ping");
}

#![cfg(dpdk)]

use bytes::Bytes;
use httpio::dpdk::{
    EthPort, Mbuf, Mempool, eal,
    mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
    net::{arp, eth, ipv4, tcp},
    tcp::{
        engine::{EngineConfig, TcpEngine},
        rto::{MAX_RETRANSMITS, MAX_RTO},
        tcb::Event,
    },
};
use std::time::{Duration, Instant};

const LOCAL_IP: [u8; 4] = [10, 0, 0, 1];
const PEER_IP: [u8; 4] = [10, 0, 0, 2];
const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

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
        let pool =
            Mempool::create("engine-test", 1023, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
        let port = EthPort::init(0, &pool, 128, 128, 1500, 0).unwrap();
        let mut engine = TcpEngine::new(EngineConfig {
            local_ip: LOCAL_IP,
            local_mac: LOCAL_MAC,
            gateway: None,
        });
        let mut now = Instant::now();
        // Learn the peer's MAC before the active open.
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
        engine.poll(&port, &pool, now);
        let tuple = engine.connect(PEER_IP, 80, 1234);
        engine.poll(&port, &pool, now);
        let syn = output(&port).remove(0);
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
        for _ in 0..64 {
            inject_tcp(&port, &pool, &peer, &[42; 1024]);
            engine.poll(&port, &pool, now);
            let ack = output(&port).remove(0);
            peer.seq += 1024;
            assert_eq!(ack.ack, peer.seq);
        }
        // An otherwise idle TCB must be reactivated by an application read.
        assert_eq!(engine.recv(tuple, 1024).len(), 1024);
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
    }
    eal::cleanup();
}

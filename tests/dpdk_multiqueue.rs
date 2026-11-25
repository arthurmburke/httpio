//! Two engines on two queues of one port, as two workers would run them,
//! against a server on a second port. `net_ring` has neither flow rules
//! nor a wire, so the test plays the NIC: it carries frames between the
//! ports and delivers each one to the queue that the port's
//! `PortSteering` (and so the real flow rules) would, and spreads the rest
//! of UDP over the queues as RSS would. UDP runs on the same engines after
//! TCP: a steered ephemeral port, a server port bound on both engines, and
//! the fallback for a device that refused the UDP flow rules.
#![cfg(dpdk)]

use httpio::core::time::Instant;
use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::Bytes;
use httpio::dpdk::net::arp::SharedNeighbors;
use httpio::dpdk::port::QueueSteering;
use httpio::dpdk::steering::{EPHEMERAL_FIRST, PortSteering};
use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
use httpio::dpdk::tcp::state::TcpState;
use httpio::dpdk::{EthPort, Mbuf, Mempool, eal};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);

/// The queue a NIC programmed with `steering`'s rules puts `frame` on:
/// TCP by destination port; UDP by destination port too where a rule
/// matches it and the device took the UDP rules (`udp_steered`), else
/// spread by RSS (played here by the source port); everything else (ARP)
/// on queue 0.
fn nic_queue(steering: PortSteering, udp_steered: bool, frame: &[u8]) -> usize {
    if frame.len() < 38 || frame[12..14] != [0x08, 0x00] {
        return 0;
    }
    let src_port = u16::from_be_bytes([frame[34], frame[35]]);
    let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
    let rss = usize::from(src_port) % usize::from(steering.queues());
    match frame[23] {
        6 => usize::from(steering.queue_of(dst_port).unwrap_or(0)),
        17 => match steering.queue_of(dst_port) {
            Some(queue) if udp_steered => usize::from(queue),
            _ => rss,
        },
        _ => 0,
    }
}

#[test]
fn each_queue_carries_the_connections_whose_ports_lead_to_it() {
    let cpu = unsafe { libc::sched_getcpu() };
    eal::init(&[
        "multiqueue-test",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("0@{cpu}"),
        "--vdev=net_ring0",
        "--vdev=net_ring1",
        "--vdev=net_ring2",
    ])
    .unwrap();
    {
        let pool = |name| Mempool::new(name, 2047, 0, 2176, -1).unwrap();
        let (pool0, pool1, server_pool) = (pool("mq-c0"), pool("mq-c1"), pool("mq-server"));

        // A device without flow rules refuses to start with several
        // queues rather than start with connections landing anywhere.
        let refused = EthPort::init_queues(
            2,
            &[&pool0, &pool1],
            256,
            256,
            1500,
            -1,
            QueueSteering::FlowRules,
        );
        assert!(refused.is_err(), "net_ring has no rte_flow");

        let mut queues = EthPort::init_queues(
            0,
            &[&pool0, &pool1],
            256,
            256,
            1500,
            -1,
            QueueSteering::Unmanaged,
        )
        .unwrap();
        let queue1 = queues.pop().unwrap();
        let queue0 = queues.pop().unwrap();
        assert_eq!((queue0.queue_id(), queue1.queue_id()), (0, 1));
        let steering = queue0.steering();
        assert_eq!(steering.queues(), 2);
        let server_port = EthPort::init(1, &server_pool, 256, 256, 1500, -1).unwrap();

        let neighbors = SharedNeighbors::new();
        let client = || {
            let mut engine = TcpEngine::new(EngineConfig {
                local_ip: CLIENT_IP,
                local_mac: queue0.mac_addr().unwrap(),
                gateway: None,
            });
            engine.share_neighbors(neighbors.clone());
            engine
        };
        let (mut engine0, mut engine1) = (client(), client());
        let mut server = TcpEngine::new(EngineConfig {
            local_ip: SERVER_IP,
            local_mac: server_port.mac_addr().unwrap(),
            gateway: None,
        });
        server.listen(80);

        // Frames each client queue was handed, to show both were used.
        let mut delivered = [0usize; 2];
        let mut pump =
            |engine0: &mut TcpEngine, engine1: &mut TcpEngine, server: &mut TcpEngine| {
                let now = Instant::now();
                engine0.poll(&queue0, &pool0, now);
                engine1.poll(&queue1, &pool1, now);
                // After a poll, what is in a ring port's queue is what its
                // engine transmitted. Client to server: one queue there.
                for queue in [&queue0, &queue1] {
                    let frames = queue.rx_burst(64);
                    assert!(server_port.tx_burst(frames).is_empty());
                }
                server.poll(&server_port, &server_pool, now);
                // Server to client: the NIC picks the queue.
                for frame in server_port.rx_burst(64) {
                    let queue = nic_queue(steering, true, frame.data());
                    delivered[queue] += 1;
                    let port: &EthPort = [&queue0, &queue1][queue];
                    assert!(port.tx_burst(vec![frame]).is_empty());
                }
            };

        // Two local ports, one leading to each queue; each engine opens
        // the connection whose port is its own.
        let (port0, port1) = (EPHEMERAL_FIRST, EPHEMERAL_FIRST + 1);
        assert_eq!(steering.queue_of(port0), Some(0));
        assert_eq!(steering.queue_of(port1), Some(1));

        // The second engine goes first and alone. The ARP reply to its
        // request is delivered to queue 0, so it can only complete the
        // handshake by finding the answer the first engine published.
        let conn1 = engine1.connect(SERVER_IP, 80, port1).unwrap();
        for _ in 0..50 {
            pump(&mut engine0, &mut engine1, &mut server);
        }
        assert_eq!(engine1.state(conn1), Some(TcpState::Established));

        let conn0 = engine0.connect(SERVER_IP, 80, port0).unwrap();
        for _ in 0..50 {
            pump(&mut engine0, &mut engine1, &mut server);
        }
        assert_eq!(engine0.state(conn0), Some(TcpState::Established));

        // Data both ways on both connections, each echoed by the server.
        engine0.send(conn0, Bytes::from_static(b"from queue zero"));
        engine1.send(conn1, Bytes::from(vec![7u8; 20_000]));
        let mut accepted = Vec::new();
        let (mut echo0, mut echo1) = (Vec::new(), Vec::new());
        for _ in 0..400 {
            pump(&mut engine0, &mut engine1, &mut server);
            accepted.extend(std::iter::from_fn(|| server.accept(80)));
            for &tuple in &accepted {
                loop {
                    let data = server.recv(tuple, usize::MAX);
                    if data.is_empty() {
                        break;
                    }
                    server.send(tuple, data.into_bytes());
                }
            }
            for (engine, conn, echo) in [
                (&mut engine0, conn0, &mut echo0),
                (&mut engine1, conn1, &mut echo1),
            ] {
                loop {
                    let data = engine.recv(conn, usize::MAX);
                    if data.is_empty() {
                        break;
                    }
                    echo.extend_from_slice(&data);
                }
            }
        }
        assert_eq!(accepted.len(), 2);
        assert_eq!(echo0, b"from queue zero");
        assert_eq!(echo1, vec![7u8; 20_000]);
        assert!(delivered[0] > 0 && delivered[1] > 0, "{delivered:?}");
        // Neither engine was handed the other's segments: a segment for
        // an unknown connection would have been answered with a reset.
        assert_eq!(engine0.state(conn0), Some(TcpState::Established));
        assert_eq!(engine1.state(conn1), Some(TcpState::Established));
        assert_eq!(engine0.state(conn1), None);
        assert_eq!(engine1.state(conn0), None);

        udp_on_both_queues(
            [&mut engine0, &mut engine1],
            &mut server,
            [(&queue0, &pool0), (&queue1, &pool1)],
            (&server_port, &server_pool),
        );

        drop((engine0, engine1, server));
        let _: Vec<Mbuf> = queue0.rx_burst(64);
        let _: Vec<Mbuf> = queue1.rx_burst(64);
        let _: Vec<Mbuf> = server_port.rx_burst(64);
    }
    eal::cleanup();
}

/// Datagrams from `SENDERS` server ports, one each, which RSS spreads over
/// both queues unless a flow rule claims their destination port.
const SENDERS: std::ops::Range<u16> = 9000..9008;

/// UDP on the engines the TCP part left running (their ARP tables, shared,
/// already know the server). `bind` is what `WorkerHandle::bind_udp` would
/// do per engine.
fn udp_on_both_queues(
    clients: [&mut TcpEngine; 2],
    server: &mut TcpEngine,
    queues: [(&EthPort, &Mempool); 2],
    (server_port, server_pool): (&EthPort, &Mempool),
) {
    let steering = queues[0].0.steering();
    let [engine0, engine1] = clients;
    let mut engines = [engine0, engine1];
    let pump = |engines: &mut [&mut TcpEngine; 2], server: &mut TcpEngine, udp_steered| {
        for _ in 0..5 {
            let now = Instant::now();
            for (engine, (queue, pool)) in engines.iter_mut().zip(queues) {
                engine.poll(queue, pool, now);
                let frames = queue.rx_burst(64);
                assert!(server_port.tx_burst(frames).is_empty());
            }
            server.poll(server_port, server_pool, now);
            for frame in server_port.rx_burst(64) {
                let queue = nic_queue(steering, udp_steered, frame.data());
                assert!(queues[queue].0.tx_burst(vec![frame]).is_empty());
            }
        }
    };
    for port in SENDERS {
        server.udp_mut().bind(port).unwrap();
    }
    let send_all = |server: &mut TcpEngine, dst: u16| {
        for port in SENDERS {
            let to = SocketAddrV4::new(CLIENT_IP, dst);
            let payload = Bytes::copy_from_slice(&port.to_be_bytes());
            server.udp_mut().send_to(port, to, payload).unwrap();
        }
    };
    let received = |engine: &TcpEngine, port| engine.udp().pending_rx(port);
    let first_on = |queue| {
        (EPHEMERAL_FIRST + 2..)
            .find(|&port| steering.queue_of(port) == Some(queue))
            .unwrap()
    };
    let total = SENDERS.len();

    // A steered ephemeral port is bound on its one engine, and every
    // datagram to it lands there, whatever RSS would have made of it.
    let steered = first_on(1);
    engines[1].udp_mut().bind(steered).unwrap();
    send_all(server, steered);
    pump(&mut engines, server, true);
    assert_eq!(received(engines[1], steered), total);
    assert_eq!(engines[0].udp().counters().rx_unbound, 0, "none strayed");

    // A server port matches no rule: RSS spreads its peers over both
    // queues, and the port is bound on both engines (fan-in).
    for engine in &mut engines {
        engine.udp_mut().bind(7007).unwrap();
    }
    send_all(server, 7007);
    pump(&mut engines, server, true);
    let (on0, on1) = (received(engines[0], 7007), received(engines[1], 7007));
    assert_eq!(on0 + on1, total);
    assert!(on0 > 0 && on1 > 0, "RSS used both queues: {on0} + {on1}");
    // Either engine replies through its own queue.
    let reply = SocketAddrV4::new(SERVER_IP, SENDERS.start);
    for engine in &mut engines {
        let pong = Bytes::from_static(b"pong");
        engine.udp_mut().send_to(7007, reply, pong).unwrap();
    }
    pump(&mut engines, server, true);
    assert_eq!(received(server, SENDERS.start), 2);

    // A device that refused the UDP rules: even an ephemeral port's
    // datagrams go where RSS puts them, so the port is bound on every
    // engine (`udp_steered == false`), and those that land off its steered
    // queue still arrive.
    let unsteered = first_on(0);
    for engine in &mut engines {
        engine.udp_mut().bind(unsteered).unwrap();
    }
    send_all(server, unsteered);
    pump(&mut engines, server, false);
    let (on0, on1) = (
        received(engines[0], unsteered),
        received(engines[1], unsteered),
    );
    assert_eq!(on0 + on1, total);
    assert!(on1 > 0, "some landed off the steered queue");
    for engine in &engines {
        assert_eq!(engine.udp().counters().rx_unbound, 0);
        assert_eq!(engine.udp().counters().rx_bad_checksum, 0);
    }
}

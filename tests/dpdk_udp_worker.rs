//! `UdpSocket` end to end: a real worker on a second lcore runs the engine,
//! a tokio runtime on the main lcore drives the sockets, and the test plays
//! the peer on a second port.
//!
//! The two ports are cross-connected ring ports: what the worker's port
//! transmits, the peer's receives, and the other way round. A `--vdev`
//! `net_ring` port cannot do that (it loops to itself), and a looping port
//! would hand the worker its own packets, so the ports are made with
//! `rte_eth_from_rings`. That lives in the `net_ring` driver, which EAL
//! loads as a plugin rather than this crate linking it, so it is looked up
//! in the loaded plugin. EAL can be initialized once per process, so
//! everything runs in one test.
#![cfg(dpdk)]

use std::ffi::{CStr, CString, c_char, c_int, c_uint};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use httpio::core::time::{Duration, Instant};
use httpio::dpdk::net::eth::EthAddr;
use httpio::dpdk::net::{arp, eth, ipv4, udp};
use httpio::dpdk::steering::{EPHEMERAL_FIRST, EPHEMERAL_LAST};
use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
use httpio::dpdk::tcp::worker::WorkerHandle;
use httpio::dpdk::udp::{UdpSocket, UdpStatsSnapshot};
use httpio::dpdk::{EthPort, Mbuf, Mempool, eal, ffi, mempool::DEFAULT_MBUF_DATA_ROOM_SIZE};

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const OTHER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const PEER_MAC: EthAddr = EthAddr::new([2, 0, 0, 0, 0, 2]);
const WAIT: Duration = Duration::from_secs(10);

const fn peer(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(PEER_IP, port)
}

/// `rte_eth_from_rings`, from the `net_ring` plugin EAL loaded.
type FromRings = unsafe extern "C" fn(
    name: *const c_char,
    rx_queues: *const *mut ffi::rte_ring,
    nb_rx_queues: c_uint,
    tx_queues: *const *mut ffi::rte_ring,
    nb_tx_queues: c_uint,
    numa_node: c_uint,
) -> c_int;

fn from_rings() -> FromRings {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let path = maps
        .lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .find(|path| path.contains("librte_net_ring"))
        .expect("EAL loads the net_ring driver plugin");
    let path = CString::new(path).unwrap();
    unsafe {
        let library = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert!(!library.is_null(), "{path:?} is loaded");
        let symbol = libc::dlsym(library, c"rte_eth_from_rings".as_ptr());
        assert!(!symbol.is_null(), "net_ring exports rte_eth_from_rings");
        std::mem::transmute::<*mut libc::c_void, FromRings>(symbol)
    }
}

/// Two ring ports wired to each other; returns their port ids.
fn cross_connected_ports() -> (u16, u16) {
    let ring = |name: &CStr| {
        // Single producer, single consumer: one lcore on each side.
        let ring = unsafe { ffi::rte_ring_create(name.as_ptr(), 1024, 0, 0x1 | 0x2) };
        assert!(!ring.is_null());
        ring
    };
    let (to_worker, to_peer) = (ring(c"udpw-to-worker"), ring(c"udpw-to-peer"));
    let from_rings = from_rings();
    let port = |name: &CStr, rx: *mut ffi::rte_ring, tx: *mut ffi::rte_ring| {
        let id = unsafe { from_rings(name.as_ptr(), &rx, 1, &tx, 1, 0) };
        assert!(id >= 0, "rte_eth_from_rings failed");
        id as u16
    };
    (
        port(c"udpw-worker", to_worker, to_peer),
        port(c"udpw-peer", to_peer, to_worker),
    )
}

/// One datagram the worker transmitted, checksum verified.
#[derive(Debug, PartialEq, Eq)]
struct Sent {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: Vec<u8>,
}

/// The test's side of the wire.
struct Peer {
    port: EthPort,
    pool: Mempool,
    worker_mac: EthAddr,
    received: Vec<Sent>,
    arp_requests: usize,
}

impl Peer {
    /// Takes what the worker sent: answers ARP for the peer's address and
    /// keeps UDP datagrams.
    fn pump(&mut self) {
        for packet in self.port.rx_burst(64) {
            let frame: Vec<u8> = packet.segments().flatten().copied().collect();
            let ether = eth::EthHeader::parse(&frame).unwrap();
            match ether.ethertype {
                arp::ETHERTYPE_ARP => {
                    let request = arp::ArpPacket::parse(&frame[eth::ETH_HDR_LEN..]).unwrap();
                    if request.operation == arp::OP_REQUEST && request.target_ip == PEER_IP {
                        self.arp_requests += 1;
                        self.arp_reply();
                    }
                }
                eth::ETHERTYPE_IPV4 => {
                    let ip = ipv4::Ipv4Header::parse(&frame[eth::ETH_HDR_LEN..], true).unwrap();
                    if ip.protocol != ipv4::PROTO_UDP {
                        continue;
                    }
                    assert_eq!(ether.dst, PEER_MAC);
                    assert_eq!(ip.flags_fragment_offset, 0x4000, "Don't Fragment");
                    let l4 = &frame[eth::ETH_HDR_LEN + ipv4::IPV4_HDR_LEN
                        ..eth::ETH_HDR_LEN + ip.total_length as usize];
                    let (header, len) = udp::UdpHeader::parse(l4, ip.src, ip.dst, true)
                        .expect("a valid UDP checksum");
                    self.received.push(Sent {
                        src: SocketAddrV4::new(ip.src, header.src_port),
                        dst: SocketAddrV4::new(ip.dst, header.dst_port),
                        payload: l4[udp::UDP_HDR_LEN..udp::UDP_HDR_LEN + len].to_vec(),
                    });
                }
                _ => {}
            }
        }
    }

    fn arp_reply(&self) {
        let mut reply = Mbuf::alloc(&self.pool).unwrap();
        let data = reply
            .append((eth::ETH_HDR_LEN + arp::ARP_HDR_LEN) as u16)
            .unwrap();
        eth::EthHeader {
            dst: self.worker_mac,
            src: PEER_MAC,
            ethertype: arp::ETHERTYPE_ARP,
        }
        .write(data);
        arp::ArpPacket {
            operation: arp::OP_REPLY,
            sender_mac: PEER_MAC,
            sender_ip: PEER_IP,
            target_mac: self.worker_mac,
            target_ip: LOCAL_IP,
        }
        .write(&mut data[eth::ETH_HDR_LEN..]);
        self.transmit(reply);
    }

    fn transmit(&self, packet: Mbuf) {
        let mut packets = vec![packet];
        // The worker drains the ring continuously; a full one is brief.
        while !packets.is_empty() {
            packets = self.port.tx_burst(packets);
        }
    }

    /// Sends one datagram from `src` to the worker.
    fn inject(&self, src: SocketAddrV4, dst_port: u16, payload: &[u8]) {
        let ip_len = ipv4::IPV4_HDR_LEN + udp::UDP_HDR_LEN + payload.len();
        let mut packet = Mbuf::alloc(&self.pool).unwrap();
        let data = packet.append((eth::ETH_HDR_LEN + ip_len) as u16).unwrap();
        eth::EthHeader {
            dst: self.worker_mac,
            src: PEER_MAC,
            ethertype: eth::ETHERTYPE_IPV4,
        }
        .write(data);
        let data = &mut data[eth::ETH_HDR_LEN..];
        ipv4::Ipv4Header {
            dscp_ecn: 0,
            total_length: ip_len as u16,
            identification: 0,
            flags_fragment_offset: 0x4000,
            ttl: 64,
            protocol: ipv4::PROTO_UDP,
            src: *src.ip(),
            dst: LOCAL_IP,
        }
        .write(data, false);
        let (header, rest) = data[ipv4::IPV4_HDR_LEN..].split_at_mut(udp::UDP_HDR_LEN);
        rest.copy_from_slice(payload);
        udp::UdpHeader {
            src_port: src.port(),
            dst_port,
            length: 0,
            checksum: 0,
        }
        .write(header, payload, *src.ip(), LOCAL_IP, false);
        self.transmit(packet);
    }

    /// Pumps until `n` datagrams have arrived, then takes them.
    async fn expect(&mut self, n: usize) -> Vec<Sent> {
        let deadline = Instant::now() + WAIT;
        while self.received.len() < n {
            assert!(
                Instant::now() < deadline,
                "only {:?} of {n} datagrams arrived",
                self.received
            );
            self.pump();
            tokio::task::yield_now().await;
        }
        std::mem::take(&mut self.received)
    }
}

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT.into(), future)
        .await
        .expect("timed out")
}

/// Two allowed CPUs for the two lcores (the same one twice if only one).
fn two_cpus() -> (usize, usize) {
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &mut affinity) },
        0
    );
    let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &affinity) })
        .collect();
    (cpus[0], *cpus.get(1).unwrap_or(&cpus[0]))
}

#[test]
fn udp_sockets_through_a_worker_lcore() {
    let (main_cpu, worker_cpu) = two_cpus();
    eal::init(&[
        "udp-worker-test",
        "--no-huge",
        "--no-pci",
        "--no-shconf",
        "--no-telemetry",
        "--lcores",
        &format!("0@{main_cpu},1@{worker_cpu}"),
        "--main-lcore",
        "0",
    ])
    .unwrap();
    {
        let (worker_port_id, peer_port_id) = cross_connected_ports();
        let pool = |name| Mempool::new(name, 4095, 0, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
        let (rx_pool, tx_pool, peer_pool) = (pool("udpw-rx"), pool("udpw-tx"), pool("udpw-peer"));
        let worker_port = EthPort::init(worker_port_id, &rx_pool, 256, 256, 1500, -1).unwrap();
        assert!(worker_port.udp_steered(), "one queue steers trivially");
        let worker_mac = worker_port.mac_addr().unwrap();
        let mut peer_side = Peer {
            port: EthPort::init(peer_port_id, &peer_pool, 256, 256, 1500, -1).unwrap(),
            pool: peer_pool,
            worker_mac,
            received: Vec::new(),
            arp_requests: 0,
        };
        let engine = TcpEngine::new(EngineConfig {
            local_ip: LOCAL_IP,
            local_mac: worker_mac,
            gateway: None,
        });
        let (handle, join) = WorkerHandle::spawn(engine, worker_port, tx_pool, 1).unwrap();
        assert!(handle.udp_steered());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut survivor = runtime.block_on(async {
            let wire = &mut peer_side;
            // Bind, and a second bind of the same port is refused.
            let mut socket = within(UdpSocket::bind(&handle, 7000)).await.unwrap();
            assert_eq!(socket.local_addr(), SocketAddrV4::new(LOCAL_IP, 7000));
            assert_eq!(socket.max_datagram_size(), 1472);
            let error = within(UdpSocket::bind(&handle, 7000))
                .await
                .err()
                .expect("the port is taken");
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);

            // A send resolves the peer's MAC first, then goes out whole.
            within(socket.send_to(Bytes::from_static(b"hello"), peer(9000)))
                .await
                .unwrap();
            let sent = wire.expect(1).await;
            assert_eq!(
                sent,
                [Sent {
                    src: SocketAddrV4::new(LOCAL_IP, 7000),
                    dst: peer(9000),
                    payload: b"hello".to_vec(),
                }]
            );
            assert!(wire.arp_requests >= 1);
            let largest = vec![0xa5; 1472];
            within(socket.send_to_slice(&largest, peer(9000)))
                .await
                .unwrap();
            assert_eq!(wire.expect(1).await[0].payload, largest);
            let error = socket
                .try_send_to(Bytes::from(vec![0; 1473]), peer(9000))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            // Datagrams the peer sends arrive in order, uncopied.
            for n in 0..200u32 {
                wire.inject(peer(9000), 7000, &n.to_be_bytes());
            }
            for n in 0..200u32 {
                let datagram = within(socket.recv_from()).await.unwrap();
                assert_eq!(datagram.src, peer(9000));
                assert_eq!(datagram.dst, SocketAddrV4::new(LOCAL_IP, 7000));
                assert_eq!(&datagram.data[..], &n.to_be_bytes());
            }
            assert_eq!(
                socket.stats(),
                UdpStatsSnapshot {
                    rx_datagrams: 200,
                    rx_bytes: 800,
                    tx_datagrams: 2,
                    tx_bytes: 5 + 1472,
                    ..UdpStatsSnapshot::default()
                }
            );

            // Connected: only the peer's datagrams are delivered. (Whether
            // the worker drops the stranger's or the socket skips it
            // depends on which reaches the worker first.)
            within(socket.connect(peer(9000))).await.unwrap();
            wire.inject(SocketAddrV4::new(OTHER_IP, 9000), 7000, b"stranger");
            wire.inject(peer(9000), 7000, b"friend");
            let datagram = within(socket.recv()).await.unwrap();
            assert_eq!(&datagram.data[..], b"friend");
            within(socket.send(Bytes::from_static(b"reply")))
                .await
                .unwrap();
            assert_eq!(wire.expect(1).await[0].payload, b"reply");

            // Split: a Sink and a Stream.
            let (mut tx, mut rx) = socket.split();
            let batch = (0..3u8).map(|n| Ok((Bytes::from(vec![n; 3]), peer(9001))));
            within(tx.send_all(&mut futures::stream::iter(batch)))
                .await
                .unwrap();
            let sent = wire.expect(3).await;
            assert_eq!(
                sent.iter().map(|s| s.payload.clone()).collect::<Vec<_>>(),
                [[0; 3], [1; 3], [2; 3]].map(Vec::from)
            );
            assert!(sent.iter().all(|s| s.dst == peer(9001)));
            for n in 0..3u8 {
                wire.inject(peer(9000), 7000, &[n]);
            }
            for n in 0..3u8 {
                let datagram = within(rx.next()).await.unwrap().unwrap();
                assert_eq!(&datagram.data[..], &[n]);
            }

            // Dropping both halves unbinds: the port is free at once.
            drop(tx);
            drop(rx);
            let rebound = within(UdpSocket::bind(&handle, 7000)).await.unwrap();
            drop(rebound);

            // Port 0: distinct ephemeral ports, and they are used.
            let mut first = within(UdpSocket::bind(&handle, 0)).await.unwrap();
            let second = within(UdpSocket::bind(&handle, 0)).await.unwrap();
            let ephemeral = EPHEMERAL_FIRST..=EPHEMERAL_LAST;
            assert!(ephemeral.contains(&first.local_addr().port()));
            assert!(ephemeral.contains(&second.local_addr().port()));
            assert_ne!(first.local_addr(), second.local_addr());
            within(first.send_to(Bytes::from_static(b"eph"), peer(9000)))
                .await
                .unwrap();
            assert_eq!(wire.expect(1).await[0].src, first.local_addr());
            drop(first);
            second
        });

        // The worker stops with the handle: the socket's receiver learns
        // of it, rather than waiting forever.
        drop(handle);
        join.wait();
        runtime.block_on(async {
            let error = within(survivor.recv_from()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            let error = survivor
                .try_send_to(Bytes::from_static(b"late"), peer(9000))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            let (_tx, mut rx) = survivor.split();
            assert!(rx.next().await.is_none(), "the stream ends");
        });
        // Drain what the worker sent last (ARP repeats, nothing else).
        peer_side.pump();
        assert!(peer_side.received.is_empty());
    }
    eal::cleanup();
}

//! Minimal echo-server example wiring the DPDK port to the TCP stack.
//!
//! DPDK is Linux-only: build and run this inside the devcontainer
//! (.devcontainer/), which has the DPDK dev packages installed. See
//! README.md for details.
//!
//! Usage with a real NIC:
//!   tcp -l 0-1 -n 4 -- 192.168.1.10 7
//! (EAL args before `--`, then this app's own local IP and listen port.)
//!
//! Smoke test without hugepages or hardware (e.g. in the devcontainer):
//!   tcp --no-huge --vdev=net_null0 -- 10.0.0.1 7

use std::env;
use std::time::Instant;

use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
use httpio::dpdk::{self, EthPort, Mempool};
use httpio::tcp::engine::{EngineConfig, TcpEngine};
use httpio::tcp::socket::TcpSocket;
use httpio::tcp::state::TcpState;

const PORT_ID: u16 = 0;
const MBUF_POOL_SIZE: u32 = 8192;
const MBUF_CACHE_SIZE: u32 = 256;
const NB_RX_DESC: u16 = 1024;
const NB_TX_DESC: u16 = 1024;
const DEFAULT_MTU: u32 = 1500;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Standard DPDK convention: EAL args, then `--`, then application args.
    let split = args.iter().position(|a| a == "--");
    let (eal_args, app_args): (&[String], &[String]) = match split {
        Some(idx) => (&args[..idx], &args[idx + 1..]),
        None => (&args[..], &[]),
    };
    let eal_args: Vec<&str> = eal_args.iter().map(String::as_str).collect();

    let consumed = dpdk::eal::init(&eal_args).expect("EAL initialization failed");
    println!("EAL initialized, consumed {consumed} argv entries");

    let local_ip = app_args
        .first()
        .map(|s| parse_ipv4(s))
        .unwrap_or([192, 168, 1, 10]);
    let listen_port: u16 = app_args.get(1).and_then(|s| s.parse().ok()).unwrap_or(7);

    let pool = Mempool::create(
        "tcp_mbuf_pool",
        MBUF_POOL_SIZE,
        MBUF_CACHE_SIZE,
        DEFAULT_MBUF_DATA_ROOM_SIZE,
        -1,
    )
    .expect("failed to create mbuf pool");

    assert!(EthPort::count_avail() > 0, "no DPDK-bound NICs available");

    let port = EthPort::init(PORT_ID, &pool, NB_RX_DESC, NB_TX_DESC, DEFAULT_MTU, -1)
        .expect("failed to initialize ethdev port");
    let mac = port.mac_addr().expect("failed to read MAC address");

    println!(
        "port {PORT_ID}: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, local ip {}.{}.{}.{}, listening on :{listen_port}",
        mac.addr_bytes[0],
        mac.addr_bytes[1],
        mac.addr_bytes[2],
        mac.addr_bytes[3],
        mac.addr_bytes[4],
        mac.addr_bytes[5],
        local_ip[0],
        local_ip[1],
        local_ip[2],
        local_ip[3],
    );

    let mut engine = TcpEngine::new(EngineConfig {
        local_mac: mac.addr_bytes,
        local_ip,
    });
    engine.listen(listen_port);

    let mut connections: Vec<TcpSocket> = Vec::new();

    // Run-to-completion poll loop, the standard DPDK pattern: no blocking
    // I/O anywhere in this loop. In production this lcore would be
    // isolated/pinned (`-l` EAL arg) so nothing else preempts it.
    loop {
        let now = Instant::now();
        let events = engine.poll(&port, &pool, now);
        for (tuple, event) in events {
            println!("{tuple:?}: {event:?}");
        }

        while let Some(socket) = TcpSocket::accept(&mut engine, listen_port) {
            println!("accepted {:?}", socket.0);
            // Echoes are latency-sensitive and always sub-MSS: disable
            // Nagle so each reply leaves immediately instead of waiting
            // for the previous one to be acked.
            socket.set_nodelay(&mut engine, true);
            connections.push(socket);
        }

        // Echo: bounce back whatever each connection sent, and close it
        // once the peer has finished sending and there's nothing left
        // buffered to read.
        connections.retain(|socket| {
            let data = socket.recv(&mut engine, 4096);
            if !data.is_empty() {
                // `data` is a refcounted `Bytes`; echoing it back moves it
                // to the send buffer without copying.
                socket.send(&mut engine, data);
            }
            match socket.state(&engine) {
                Some(TcpState::CloseWait) if socket.readable_len(&engine) == 0 => {
                    socket.close(&mut engine);
                    true
                }
                _ if socket.is_closed(&engine) => false,
                _ => true,
            }
        });
    }
}

fn parse_ipv4(s: &str) -> [u8; 4] {
    let mut octets = [0u8; 4];
    for (i, part) in s.split('.').enumerate().take(4) {
        octets[i] = part.parse().unwrap_or(0);
    }
    octets
}

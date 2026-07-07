//! WebSocket echo check over the DPDK TCP stack: connects to a ws:// or
//! wss:// URL, sends one text message, prints the echoed reply to stdout
//! (status/progress goes to stderr), performs the close handshake, exits.
//!
//! Usage:
//!   ws_client <EAL args> -- <LOCAL_IP> <URL> [--ca <PEM>]... \
//!       [--resolve HOST=IP]... [--send MSG]
//!
//! Example (in the devcontainer, kernel-visible tap interface):
//!   ws_client -l 0-1 --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1 \
//!       wss://test.local:8444/ --ca ca.pem --resolve test.local=10.9.0.2 \
//!       --send "hello over wss"

use std::env;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use bypio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
use bypio::dpdk::{self, EthPort, PktMbufPool};
use bypio::http::client::builder::Builder;
use bypio::http::ws::Message;
use bypio::tcp::engine::{EngineConfig, TcpEngine};
use bypio::tcp::worker::WorkerHandle;

const PORT_ID: u16 = 0;
const MBUF_POOL_SIZE: u32 = 8192;
const MBUF_CACHE_SIZE: u32 = 256;
const NB_RX_DESC: u16 = 1024;
const NB_TX_DESC: u16 = 1024;
const DEFAULT_MTU: u32 = 1500;
const TIMEOUT: Duration = Duration::from_secs(15);

struct AppArgs {
    local_ip: [u8; 4],
    url: String,
    ca_files: Vec<String>,
    resolves: Vec<(String, Ipv4Addr)>,
    send: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let split = args.iter().position(|a| a == "--");
    let (eal_args, app_args): (&[String], &[String]) = match split {
        Some(idx) => (&args[..idx], &args[idx + 1..]),
        None => (&args[..], &[]),
    };

    let app = match parse_app_args(app_args) {
        Ok(app) => app,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!(
                "usage: ws_client <EAL args> -- <LOCAL_IP> <URL> [--ca <PEM>]... \
                 [--resolve HOST=IP]... [--send MSG]"
            );
            return ExitCode::FAILURE;
        }
    };

    let eal_args: Vec<&str> = eal_args.iter().map(String::as_str).collect();
    dpdk::eal::init(&eal_args).expect("EAL initialization failed");

    let pool = PktMbufPool::create(
        "ws_mbuf_pool",
        MBUF_POOL_SIZE,
        MBUF_CACHE_SIZE,
        DEFAULT_MBUF_DATA_ROOM_SIZE,
        -1,
    )
    .expect("failed to create mbuf pool");
    assert!(EthPort::count_avail() > 0, "no DPDK ports available");
    let port = EthPort::init(PORT_ID, &pool, NB_RX_DESC, NB_TX_DESC, DEFAULT_MTU, -1)
        .expect("failed to initialize ethdev port");
    let mac = port.mac_addr().expect("failed to read MAC address");

    let engine = TcpEngine::new(EngineConfig {
        local_mac: mac.addr_bytes,
        local_ip: app.local_ip,
    });

    let Some(worker_lcore) = dpdk::first_worker_lcore() else {
        eprintln!(
            "error: no worker lcore available; start EAL with at least two lcores (e.g. `-l 0-1`)"
        );
        return ExitCode::FAILURE;
    };
    let (worker, worker_join) = match WorkerHandle::spawn(engine, port, pool, worker_lcore) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("TCP engine running on worker lcore {worker_lcore}");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime");

    let result = runtime.block_on(async {
        match tokio::time::timeout(TIMEOUT, run(&app, worker)).await {
            Ok(result) => result,
            Err(_) => {
                eprintln!("error: timed out after {TIMEOUT:?}");
                ExitCode::FAILURE
            }
        }
    });

    worker_join.wait();
    dpdk::eal::cleanup();
    result
}

async fn run(app: &AppArgs, worker: WorkerHandle) -> ExitCode {
    let mut builder = Builder::new();
    for ca in &app.ca_files {
        builder = match builder.add_root_ca_pem_file(ca) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error loading CA file {ca}: {e}");
                return ExitCode::FAILURE;
            }
        };
    }
    for (host, ip) in &app.resolves {
        builder = builder.resolve(host, *ip);
    }
    let client = builder.build(worker);

    let mut ws = match client.websocket(&app.url).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("error: websocket handshake failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("websocket established: {}", app.url);

    if let Err(e) = ws.send(Message::Text(app.send.clone())).await {
        eprintln!("error: send failed: {e}");
        return ExitCode::FAILURE;
    }

    // Wait for the echo (skipping any pings/pongs), print it, then close.
    loop {
        match ws.recv().await {
            Ok(Some(Message::Text(text))) => {
                println!("{text}");
                break;
            }
            Ok(Some(Message::Binary(data))) => {
                eprintln!("received unexpected binary message ({} bytes)", data.len());
            }
            Ok(Some(Message::Ping(_) | Message::Pong(_))) => continue,
            Ok(Some(Message::Close(frame))) => {
                eprintln!("error: server closed before echoing: {frame:?}");
                return ExitCode::FAILURE;
            }
            Ok(None) => {
                eprintln!("error: connection ended before echoing");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("error: recv failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Err(e) = ws.close(None).await {
        eprintln!("error: close failed: {e}");
        return ExitCode::FAILURE;
    }
    // Drain until the close handshake completes (peer's Close or EOF).
    loop {
        match ws.recv().await {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(e) => {
                eprintln!("error: close handshake failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("websocket closed cleanly");
    ExitCode::SUCCESS
}

fn parse_app_args(args: &[String]) -> Result<AppArgs, String> {
    let mut positional = Vec::new();
    let mut ca_files = Vec::new();
    let mut resolves = Vec::new();
    let mut send = String::from("hello over websocket");

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ca" => {
                let path = it.next().ok_or("--ca requires a file path")?;
                ca_files.push(path.clone());
            }
            "--resolve" => {
                let spec = it.next().ok_or("--resolve requires HOST=IP")?;
                let (host, ip) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("bad --resolve {spec:?}, expected HOST=IP"))?;
                let ip: Ipv4Addr = ip
                    .parse()
                    .map_err(|_| format!("invalid IPv4 address {ip:?}"))?;
                resolves.push((host.to_string(), ip));
            }
            "--send" => {
                send = it.next().ok_or("--send requires a message")?.clone();
            }
            other => positional.push(other.to_string()),
        }
    }

    let [local_ip, url] = positional.as_slice() else {
        return Err("expected positional arguments: LOCAL_IP URL".into());
    };
    Ok(AppArgs {
        local_ip: local_ip
            .parse::<Ipv4Addr>()
            .map(|ip| ip.octets())
            .map_err(|_| format!("invalid IPv4 address {local_ip:?}"))?,
        url: url.clone(),
        ca_files,
        resolves,
        send,
    })
}

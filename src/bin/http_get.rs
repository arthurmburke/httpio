//! HTTP(S) fetch over the DPDK TCP stack. Response body goes to stdout;
//! status line and headers go to stderr (so the body pipes cleanly).
//!
//! Usage:
//!   http_get <EAL args> -- <LOCAL_IP> <URL> [--ca <PEM>]... [--resolve HOST=IP]...
//!
//! Example (in the devcontainer, kernel-visible tap interface):
//!   http_get --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1 \
//!       https://test.local:8443/ --ca ca.pem --resolve test.local=10.9.0.2

use std::env;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};

use bypio::http::stream::{FlushHandle, TcpOptions};
use bypio::tcp::engine::TcpEngine;
use bypio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
use bypio::dpdk::{self, EthPort, PktMbufPool};
use bypio::http::client::builder::Builder;
use bypio::tcp::worker::WorkerHandle;
use bypio::tcp::engine::EngineConfig;

const PORT_ID: u16 = 0;
const MBUF_POOL_SIZE: u32 = 8192;
const MBUF_CACHE_SIZE: u32 = 256;
const NB_RX_DESC: u16 = 1024;
const NB_TX_DESC: u16 = 1024;
const DEFAULT_MTU: u32 = 1500;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct AppArgs {
    local_ip: [u8; 4],
    /// Fetched sequentially with one client, so requests to the same
    /// HTTP/2 origin multiplex over a single pooled connection.
    urls: Vec<String>,
    ca_files: Vec<String>,
    resolves: Vec<(String, Ipv4Addr)>,
    tcp_options: TcpOptions,
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
                "usage: http_get <EAL args> -- <LOCAL_IP> <URL>... [--ca <PEM>]... \
                 [--resolve HOST=IP]... [--cork] [--nagle]"
            );
            return ExitCode::FAILURE;
        }
    };

    let eal_args: Vec<&str> = eal_args.iter().map(String::as_str).collect();
    dpdk::eal::init(&eal_args).expect("EAL initialization failed");

    let pool = PktMbufPool::create(
        "http_mbuf_pool",
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

    // The engine runs on a dedicated worker lcore; the tokio runtime (and
    // this thread) stay on the main lcore. Requires at least two EAL
    // lcores, e.g. `-l 0-1`.
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

    let result = runtime.block_on(run_requests(&app, worker));

    // Stopping the worker: dropping the handle signalled the loop to exit;
    // wait for the lcore to finish so its port/pool drop cleanly.
    worker_join.wait();
    result
}

async fn run_requests(app: &AppArgs, worker: bypio::tcp::worker::WorkerHandle) -> ExitCode {
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

    for url in &app.urls {
        let mut request = match Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .body(Bytes::new())
        {
            Ok(request) => request,
            Err(e) => {
                eprintln!("error: bad URL {url}: {e}");
                return ExitCode::FAILURE;
            }
        };
        request.extensions_mut().insert(app.tcp_options);
        // A real caller flushes a corked request the moment it decides to
        // release the held tail. This CLI is non-interactive, so it stands
        // in for that trigger by flushing repeatedly for the request's
        // duration: the tail is released as soon as it's buffered,
        // regardless of handshake/RTT timing, and later flushes are
        // no-ops. The flusher is aborted once the request completes.
        let flusher = if app.tcp_options.cork {
            let flush = FlushHandle::new();
            request.extensions_mut().insert(flush.clone());
            Some(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    flush.flush();
                }
            }))
        } else {
            None
        };

        let outcome = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request)).await;
        if let Some(flusher) = flusher {
            flusher.abort();
        }
        match outcome {
            Err(_) => {
                eprintln!("error: request timed out after {REQUEST_TIMEOUT:?}");
                return ExitCode::FAILURE;
            }
            Ok(Err(e)) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
            Ok(Ok(response)) => {
                eprintln!("{:?} {}", response.version(), response.status());
                for (name, value) in response.headers().iter() {
                    eprintln!("{}: {}", name, String::from_utf8_lossy(value.as_bytes()));
                }
                std::io::stdout()
                    .write_all(response.body())
                    .expect("failed to write body");
            }
        }
    }

    // Reuse observability: with h2 pooling, N same-origin https URLs
    // should report 1 connection, not N.
    eprintln!("connections_opened={}", client.connections_opened());
    ExitCode::SUCCESS
}

fn parse_app_args(args: &[String]) -> Result<AppArgs, String> {
    let mut positional = Vec::new();
    let mut ca_files = Vec::new();
    let mut resolves = Vec::new();
    let mut tcp_options = TcpOptions::default();

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
            // TCP_CORK-style coalescing: hold sub-MSS tails until the
            // protocol's flush points.
            "--cork" => tcp_options.cork = true,
            // Enable Nagle's algorithm (i.e. turn TCP_NODELAY off).
            "--nagle" => tcp_options.nodelay = false,
            other => positional.push(other.to_string()),
        }
    }

    let [local_ip, urls @ ..] = positional.as_slice() else {
        return Err("expected positional arguments: LOCAL_IP URL...".into());
    };
    if urls.is_empty() {
        return Err("expected at least one URL after LOCAL_IP".into());
    }
    Ok(AppArgs {
        local_ip: parse_ipv4(local_ip)?,
        urls: urls.to_vec(),
        ca_files,
        resolves,
        tcp_options,
    })
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    s.parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.octets())
        .map_err(|_| format!("invalid IPv4 address {s:?}"))
}

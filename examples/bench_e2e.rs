//! End-to-end transport benchmark: the same workloads over this crate's
//! DPDK TCP stack and over kernel sockets, against one kernel server.
//!
//! ```text
//! bench_e2e server <BIND_IP> [spin]                kernel server (echo/sink/source)
//! bench_e2e kernel <SERVER_IP> [LABEL]             tokio kernel sockets
//! bench_e2e blocking <SERVER_IP> [LABEL]           std blocking kernel sockets
//! bench_e2e dpdk <EAL args> -- <LOCAL_IP> <SERVER_IP> [LABEL]
//! bench_e2e raw <EAL args> -- <LOCAL_IP> <SERVER_IP> [LABEL]
//! ```
//!
//! `raw` drives the `TcpEngine` from one thread with no worker lcore, rings
//! or async runtime, and also times a bare ARP exchange through the port.
//! Comparing it with `dpdk` splits a latency into link, engine and
//! application-crossing shares.
//!
//! ```text
//! ```
//!
//! `server ... spin` makes the echo handler busy-poll its socket instead of
//! sleeping in `read()`, which takes the server's wake-up out of every
//! round trip. `BENCH_WORKLOADS=latency` skips the bulk transfers and
//! `BENCH_WORKLOADS=short` runs only the short fresh-connection uploads.
//! The last workload repeats the 64-byte round trip with 1000 idle
//! connections open. `BENCH_WORKLOADS=bulk` runs only the bulk transfers, and `BENCH_BULK_MB`
//! sets their size (default 64).
//!
//! Output is one tab-separated row per measurement:
//! `label  workload  metric  value`. See `scripts/bench.sh` for the wiring.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream as StdStream};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ECHO_PORT: u16 = 7001;
const SINK_PORT: u16 = 7002;
const SOURCE_PORT: u16 = 7003;

const CONNECTS: usize = 300;
/// Connections held open and idle for the last round-trip workload.
const IDLE_CONNECTIONS: usize = 1000;
/// Bytes per bulk transfer: 64 MB, or `BENCH_BULK_MB` megabytes.
fn bulk_bytes() -> u64 {
    std::env::var("BENCH_BULK_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(64)
        * 1024
        * 1024
}
const CHUNK: usize = 64 * 1024;
/// (payload bytes, round trips)
const RTT_CASES: [(usize, usize); 3] = [(64, 20_000), (1400, 20_000), (16 * 1024, 5_000)];
const SHORT_BYTES: usize = 128 * 1024;
const SHORT_TRANSFERS: usize = 500;
const PIPELINE_DEPTH: usize = 64;
const PIPELINE_MESSAGES: usize = 200_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ip = |s: &String| s.parse::<Ipv4Addr>().expect("bad IPv4 address");
    match args.get(1).map(String::as_str) {
        Some("server") => server(ip(&args[2]), args.get(3).is_some_and(|a| a == "spin")),
        Some("kernel") => {
            let label = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| "kernel-tokio".into());
            kernel_tokio(ip(&args[2]), &label);
        }
        Some("blocking") => {
            let label = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| "kernel-blocking".into());
            kernel_blocking(ip(&args[2]), &label).expect("blocking benchmark failed");
        }
        Some("dpdk") => dpdk_mode::run(&args[2..]),
        Some("raw") => dpdk_mode::run_raw(&args[2..]),
        _ => {
            eprintln!("usage: bench_e2e server|kernel|blocking|dpdk ... (see the file header)");
            std::process::exit(2);
        }
    }
}

// ---- reporting ---------------------------------------------------------

fn row(label: &str, workload: &str, metric: &str, value: f64) {
    println!("{label}\t{workload}\t{metric}\t{value:.2}");
}

/// Reports a latency distribution in microseconds.
fn report_latency(label: &str, workload: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let us = |d: Duration| d.as_nanos() as f64 / 1e3;
    let at = |q: f64| us(samples[((samples.len() - 1) as f64 * q) as usize]);
    let mean = us(samples.iter().sum::<Duration>()) / samples.len() as f64;
    row(label, workload, "mean_us", mean);
    row(label, workload, "p50_us", at(0.50));
    row(label, workload, "p99_us", at(0.99));
    row(label, workload, "p99.9_us", at(0.999));
}

fn report_throughput(label: &str, workload: &str, bytes: u64, elapsed: Duration) {
    let mbit = bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64();
    row(label, workload, "mbit_s", mbit);
}

// ---- the kernel server -------------------------------------------------

/// Whether the bulk-transfer workloads run (`BENCH_WORKLOADS=latency`
/// leaves them out).
fn bulk_enabled() -> bool {
    std::env::var("BENCH_WORKLOADS").map_or(true, |v| v != "latency")
}

fn server(bind: Ipv4Addr, spin: bool) {
    let spawn = |port: u16, handler: fn(StdStream) -> io::Result<()>| {
        let listener = TcpListener::bind(SocketAddr::from((bind, port))).expect("bind failed");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = stream.set_nodelay(true);
                    let _ = handler(stream);
                });
            }
        })
    };
    let handles = [
        spawn(ECHO_PORT, if spin { serve_echo_spin } else { serve_echo }),
        spawn(SINK_PORT, serve_sink),
        spawn(SOURCE_PORT, serve_source),
    ];
    eprintln!("bench server listening on {bind}");
    for handle in handles {
        let _ = handle.join();
    }
}

fn serve_echo(mut stream: StdStream) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n])?;
    }
}

/// Echo without ever sleeping: the handler spins on a non-blocking socket.
fn serve_echo_spin(mut stream: StdStream) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::hint::spin_loop();
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut sent = 0;
        while sent < n {
            match stream.write(&buf[sent..n]) {
                Ok(m) => sent += m,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::hint::spin_loop(),
                Err(e) => return Err(e),
            }
        }
    }
}

/// Reads to EOF, then reports how many bytes arrived.
fn serve_sink(mut stream: StdStream) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    stream.write_all(&total.to_be_bytes())
}

/// Reads a byte count, then sends that many bytes.
fn serve_source(mut stream: StdStream) -> io::Result<()> {
    let mut want = [0u8; 8];
    stream.read_exact(&mut want)?;
    let mut left = u64::from_be_bytes(want);
    let buf = vec![0x5au8; CHUNK];
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        stream.write_all(&buf[..n])?;
        left -= n as u64;
    }
    Ok(())
}

// ---- async workloads (tokio kernel sockets and the DPDK stream) ---------
//
// Order matters: everything that needs a quiet stack runs before the
// connection churn, and the 64-byte round trip is then repeated to show
// what recently closed connections cost.

/// Request/response latency on one warm connection.
async fn rtt_async<S, C>(
    label: &str,
    name: &str,
    connect: &mut C,
    size: usize,
    rounds: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: AsyncFnMut(u16) -> io::Result<S>,
{
    let mut stream = connect(ECHO_PORT).await?;
    let msg = vec![0xa5u8; size];
    let mut reply = vec![0u8; size];
    for _ in 0..rounds / 10 {
        stream.write_all(&msg).await?;
        stream.read_exact(&mut reply).await?;
    }
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let start = Instant::now();
        stream.write_all(&msg).await?;
        stream.read_exact(&mut reply).await?;
        samples.push(start.elapsed());
    }
    report_latency(label, name, samples);
    stream.shutdown().await
}

async fn run_async<S, C>(label: &str, mut connect: C) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
    C: AsyncFnMut(u16) -> io::Result<S>,
{
    if std::env::var("BENCH_WORKLOADS").is_ok_and(|v| v == "short") {
        return short_transfers(label, &mut connect).await;
    }
    let bulk_only = std::env::var("BENCH_WORKLOADS").is_ok_and(|v| v == "bulk");
    for (size, rounds) in RTT_CASES {
        if bulk_only {
            break;
        }
        rtt_async(label, &format!("rtt_{size}B"), &mut connect, size, rounds).await?;
    }

    // Small-message throughput with a window of requests in flight.
    if !bulk_only {
        let mut stream = connect(ECHO_PORT).await?;
        let msg = [0xa5u8; 64];
        let batch = vec![0xa5u8; msg.len() * PIPELINE_DEPTH];
        let mut reply = vec![0u8; batch.len()];
        let start = Instant::now();
        for _ in 0..PIPELINE_MESSAGES / PIPELINE_DEPTH {
            for chunk in batch.chunks(msg.len()) {
                stream.write_all(chunk).await?;
            }
            stream.read_exact(&mut reply).await?;
        }
        let sent = (PIPELINE_MESSAGES / PIPELINE_DEPTH * PIPELINE_DEPTH) as f64;
        row(
            label,
            "pipelined_64B",
            "msgs_s",
            sent / start.elapsed().as_secs_f64(),
        );
        stream.shutdown().await?;
    }

    if bulk_enabled() {
        let bulk_bytes = bulk_bytes();
        // Bulk upload: the server acknowledges the byte count after our FIN.
        let mut stream = connect(SINK_PORT).await?;
        let buf = vec![0x5au8; CHUNK];
        let start = Instant::now();
        let mut left = bulk_bytes;
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            stream.write_all(&buf[..n]).await?;
            left -= n as u64;
        }
        stream.shutdown().await?;
        let mut total = [0u8; 8];
        stream.read_exact(&mut total).await?;
        assert_eq!(u64::from_be_bytes(total), bulk_bytes, "upload truncated");
        report_throughput(label, "upload", bulk_bytes, start.elapsed());

        // Bulk download.
        let mut stream = connect(SOURCE_PORT).await?;
        let mut buf = vec![0u8; CHUNK];
        let start = Instant::now();
        stream.write_all(&bulk_bytes.to_be_bytes()).await?;
        let mut got = 0u64;
        while got < bulk_bytes {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got += n as u64;
        }
        assert_eq!(got, bulk_bytes, "download truncated");
        report_throughput(label, "download", bulk_bytes, start.elapsed());
    }
    if bulk_only {
        return Ok(());
    }

    // Connection setup: handshake to first usable stream. Each connection
    // is closed at once, so later samples run with the earlier ones still
    // winding down.
    let mut samples = Vec::with_capacity(CONNECTS);
    for _ in 0..CONNECTS {
        let start = Instant::now();
        let mut stream = connect(ECHO_PORT).await?;
        samples.push(start.elapsed());
        stream.shutdown().await?;
    }
    report_latency(label, "connect_first20", samples[..20].to_vec());
    report_latency(label, "connect_all300", samples);

    rtt_async(label, "rtt_64B_after_300_closes", &mut connect, 64, 20_000).await?;

    short_transfers(label, &mut connect).await?;

    // The same round trip with idle connections held open beside it, each
    // in its own task with a read outstanding (as a pooled HTTP connection
    // has while it watches for the peer closing): what waiting streams
    // cost the one that is busy.
    let mut idle = Vec::with_capacity(IDLE_CONNECTIONS);
    for _ in 0..IDLE_CONNECTIONS {
        idle.push(connect(ECHO_PORT).await?);
    }
    let mut stream = connect(ECHO_PORT).await?;
    let tasks = tokio::task::LocalSet::new();
    let samples = tasks
        .run_until(async move {
            let idle: Vec<_> = idle
                .into_iter()
                .map(|mut stream| {
                    tokio::task::spawn_local(async move {
                        let mut byte = [0u8; 1];
                        let _ = stream.read(&mut byte).await;
                    })
                })
                .collect();
            let busy = tokio::task::spawn_local(async move {
                let msg = [0xa5u8; 64];
                let mut reply = [0u8; 64];
                let mut samples = Vec::with_capacity(20_000);
                for round in 0..22_000 {
                    let start = Instant::now();
                    stream.write_all(&msg).await?;
                    stream.read_exact(&mut reply).await?;
                    if round >= 2_000 {
                        samples.push(start.elapsed());
                    }
                }
                stream.shutdown().await?;
                io::Result::Ok(samples)
            });
            let samples = busy.await.expect("round-trip task panicked");
            // Dropping the idle streams closes them; give the stack a
            // moment to send the FINs before the process exits, so the
            // server is not left holding a thousand dead connections.
            for task in idle {
                task.abort();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            samples
        })
        .await?;
    report_latency(
        label,
        &format!("rtt_64B_with_{IDLE_CONNECTIONS}_idle"),
        samples,
    );
    Ok(())
}

/// A short transfer on a fresh connection: handshake, slow start from the
/// initial window, close, and the server's count back. The first twenty
/// are also reported alone, before closed connections have piled up.
async fn short_transfers<S, C>(label: &str, connect: &mut C) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: AsyncFnMut(u16) -> io::Result<S>,
{
    let buf = vec![0x5au8; SHORT_BYTES];
    let mut samples = Vec::with_capacity(SHORT_TRANSFERS);
    for _ in 0..SHORT_TRANSFERS {
        let start = Instant::now();
        let mut stream = connect(SINK_PORT).await?;
        stream.write_all(&buf).await?;
        stream.shutdown().await?;
        let mut total = [0u8; 8];
        stream.read_exact(&mut total).await?;
        assert_eq!(u64::from_be_bytes(total), SHORT_BYTES as u64);
        samples.push(start.elapsed());
    }
    report_latency(
        label,
        "fresh_conn_upload_128KB_first20",
        samples[..20].to_vec(),
    );
    report_latency(label, "fresh_conn_upload_128KB", samples);
    Ok(())
}

fn kernel_tokio(server: Ipv4Addr, label: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    runtime
        .block_on(run_async(label, async |port: u16| {
            let stream = tokio::net::TcpStream::connect(SocketAddr::from((server, port))).await?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }))
        .expect("kernel benchmark failed");
}

// ---- blocking kernel sockets: a thread asleep in recv(), woken by the
// ---- kernel when the packet's interrupt/softirq delivers the data. The
// ---- latency workloads only; throughput matches the tokio rows. ---------

fn kernel_blocking(server: Ipv4Addr, label: &str) -> io::Result<()> {
    let connect = |port: u16| -> io::Result<StdStream> {
        let stream = StdStream::connect(SocketAddr::from((server, port)))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    };
    let rtt = |name: &str, size: usize, rounds: usize| -> io::Result<()> {
        let mut stream = connect(ECHO_PORT)?;
        let msg = vec![0xa5u8; size];
        let mut reply = vec![0u8; size];
        for _ in 0..rounds / 10 {
            stream.write_all(&msg)?;
            stream.read_exact(&mut reply)?;
        }
        let mut samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let start = Instant::now();
            stream.write_all(&msg)?;
            stream.read_exact(&mut reply)?;
            samples.push(start.elapsed());
        }
        report_latency(label, name, samples);
        Ok(())
    };

    for (size, rounds) in RTT_CASES {
        rtt(&format!("rtt_{size}B"), size, rounds)?;
    }
    let mut samples = Vec::with_capacity(CONNECTS);
    for _ in 0..CONNECTS {
        let start = Instant::now();
        let stream = connect(ECHO_PORT)?;
        samples.push(start.elapsed());
        stream.shutdown(std::net::Shutdown::Write)?;
    }
    report_latency(label, "connect_first20", samples[..20].to_vec());
    report_latency(label, "connect_all300", samples);
    rtt("rtt_64B_after_300_closes", 64, 20_000)
}

// ---- the DPDK stack ----------------------------------------------------

#[cfg(not(dpdk))]
mod dpdk_mode {
    pub fn run(_args: &[String]) {
        eprintln!("bench_e2e dpdk needs the DPDK stack; build inside the devcontainer.");
        std::process::exit(1);
    }
    pub fn run_raw(args: &[String]) {
        run(args)
    }
}

#[cfg(dpdk)]
mod dpdk_mode {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU16, Ordering};

    use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
    use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
    use httpio::dpdk::tcp::stream::{TcpOptions, TcpStream};
    use httpio::dpdk::tcp::worker::WorkerHandle;
    use httpio::dpdk::{self, EthPort, Mempool};

    /// Splits `<EAL args> -- <LOCAL_IP> <SERVER_IP> [LABEL]` and starts EAL.
    fn init(args: &[String], default_label: &str) -> (Ipv4Addr, Ipv4Addr, String) {
        let split = args
            .iter()
            .position(|a| a == "--")
            .expect("usage: bench_e2e dpdk|raw <EAL args> -- <LOCAL_IP> <SERVER_IP> [LABEL]");
        let mut eal_args = vec!["bench_e2e"];
        eal_args.extend(args[..split].iter().map(String::as_str));
        let app = &args[split + 1..];
        let local_ip: Ipv4Addr = app[0].parse().expect("bad local IP");
        let server: Ipv4Addr = app[1].parse().expect("bad server IP");
        let label = app.get(2).cloned().unwrap_or_else(|| default_label.into());
        dpdk::eal::init(&eal_args).expect("EAL initialization failed");
        (local_ip, server, label)
    }

    /// One thread owns the port and the engine and spins on them: no worker
    /// lcore, no rings, no async runtime.
    pub fn run_raw(args: &[String]) {
        use std::time::Instant;

        use bytes::Bytes;
        use httpio::dpdk::Mbuf;
        use httpio::dpdk::net::eth::{self, EthAddr};
        use httpio::dpdk::net::{arp, ipv4, tcp};
        use httpio::dpdk::tcp::tcb::Event;

        const ROUNDS: usize = 20_000;

        let (local_ip, server, label) = init(args, "dpdk-raw");
        {
            let pool = Mempool::create("bench_pool", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1)
                .expect("failed to create mbuf pool");
            let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).expect("port init failed");
            let local_mac = port.mac_addr().expect("no MAC address");

            // The link's own round trip: an ARP request the peer's kernel
            // answers from its receive path, with no thread to wake.
            let mut samples = Vec::with_capacity(ROUNDS);
            let mut polls = 0u64;
            let mut peer_mac = EthAddr::ZERO;
            for _ in 0..ROUNDS {
                let mut request = Mbuf::alloc(&pool).expect("mbuf pool exhausted");
                let frame = request
                    .append((eth::ETH_HDR_LEN + arp::ARP_HDR_LEN) as u16)
                    .unwrap();
                eth::EthHeader {
                    dst: EthAddr::BROADCAST,
                    src: local_mac,
                    ethertype: arp::ETHERTYPE_ARP,
                }
                .write(frame);
                arp::ArpPacket {
                    operation: arp::OP_REQUEST,
                    sender_mac: local_mac,
                    sender_ip: local_ip,
                    target_mac: EthAddr::ZERO,
                    target_ip: server,
                }
                .write(&mut frame[eth::ETH_HDR_LEN..]);
                let start = Instant::now();
                assert!(port.tx_burst(vec![request]).is_empty());
                'reply: loop {
                    polls += 1;
                    for packet in port.rx_packets(64) {
                        let header = eth::EthHeader::parse(packet.data());
                        if let Some(header) = header
                            && header.ethertype == arp::ETHERTYPE_ARP
                        {
                            peer_mac = header.src;
                            break 'reply;
                        }
                    }
                    assert!(start.elapsed().as_secs() < 5, "no ARP reply");
                }
                samples.push(start.elapsed());
            }
            super::row(&label, "arp_rtt", "rx_polls", polls as f64 / ROUNDS as f64);
            super::report_latency(&label, "arp_rtt", samples);

            // The same, through the peer's IP and TCP input: a SYN to a
            // closed port, which its kernel answers with a reset. Still no
            // thread to wake and none of this crate's TCP code.
            let mut samples = Vec::with_capacity(ROUNDS);
            let mut polls = 0u64;
            let mut tx_time = std::time::Duration::ZERO;
            let syn = tcp::TcpHeader {
                src_port: 29_999,
                dst_port: 9,
                seq: 1,
                ack: 0,
                flags: tcp::flags::SYN,
                window: 1024,
                urgent_pointer: 0,
                options: tcp::TcpOptions::default(),
            };
            let ip_len = ipv4::IPV4_HDR_LEN + syn.wire_len();
            for _ in 0..ROUNDS {
                let mut probe = Mbuf::alloc(&pool).expect("mbuf pool exhausted");
                let frame = probe.append((eth::ETH_HDR_LEN + ip_len) as u16).unwrap();
                eth::EthHeader {
                    dst: peer_mac,
                    src: local_mac,
                    ethertype: eth::ETHERTYPE_IPV4,
                }
                .write(frame);
                let ip = &mut frame[eth::ETH_HDR_LEN..];
                ipv4::Ipv4Header {
                    dscp_ecn: 0,
                    total_length: ip_len as u16,
                    identification: 0,
                    flags_fragment_offset: 0x4000,
                    ttl: 64,
                    protocol: ipv4::PROTO_TCP,
                    src: local_ip,
                    dst: server,
                }
                .write(ip, false);
                syn.write(&mut ip[ipv4::IPV4_HDR_LEN..], &[], local_ip, server, false);
                let start = Instant::now();
                assert!(port.tx_burst(vec![probe]).is_empty());
                tx_time += start.elapsed();
                'reset: loop {
                    polls += 1;
                    for packet in port.rx_packets(64) {
                        let is_ip = eth::EthHeader::parse(packet.data())
                            .is_some_and(|h| h.ethertype == eth::ETHERTYPE_IPV4);
                        if is_ip {
                            break 'reset;
                        }
                    }
                    assert!(start.elapsed().as_secs() < 5, "no reset for the probe");
                }
                samples.push(start.elapsed());
            }
            super::row(
                &label,
                "tcp_rst_rtt",
                "rx_polls",
                polls as f64 / ROUNDS as f64,
            );
            super::row(
                &label,
                "tcp_rst_rtt",
                "tx_burst_mean_us",
                tx_time.as_nanos() as f64 / 1e3 / ROUNDS as f64,
            );
            super::report_latency(&label, "tcp_rst_rtt", samples);

            let mut engine = TcpEngine::new(EngineConfig {
                local_mac,
                local_ip,
                gateway: None,
            });
            // Echo round trip on one warm connection; `transmit_poll` is
            // the first poll of each round, the one that sends the request.
            let echo_rtt = |engine: &mut TcpEngine, name: &str, local_port: u16| {
                let mut events = Vec::new();
                let tuple = engine
                    .connect(server, super::ECHO_PORT, local_port)
                    .expect("tuple in use");
                engine.set_nodelay(tuple, true);
                let message = Bytes::from_static(&[0xa5u8; 64]);
                let mut samples = Vec::with_capacity(ROUNDS);
                let mut polls = 0u64;
                let mut first_poll = std::time::Duration::ZERO;
                for round in 0..ROUNDS + ROUNDS / 10 {
                    let start = Instant::now();
                    engine.send(tuple, message.clone());
                    engine.poll_into(&port, &pool, start, &mut events);
                    polls += 1;
                    if round >= ROUNDS / 10 {
                        first_poll += start.elapsed();
                    }
                    let mut got = engine.recv(tuple, usize::MAX).len();
                    while got < message.len() {
                        polls += 1;
                        engine.poll_into(&port, &pool, Instant::now(), &mut events);
                        got += engine.recv(tuple, usize::MAX).len();
                        assert!(start.elapsed().as_secs() < 5, "echo timed out");
                    }
                    if round >= ROUNDS / 10 {
                        samples.push(start.elapsed());
                    }
                }
                super::row(
                    &label,
                    name,
                    "engine_polls",
                    polls as f64 / (ROUNDS + ROUNDS / 10) as f64,
                );
                super::row(
                    &label,
                    name,
                    "transmit_poll_mean_us",
                    first_poll.as_nanos() as f64 / 1e3 / ROUNDS as f64,
                );
                super::report_latency(&label, name, samples);
                engine.close(tuple);
            };
            echo_rtt(&mut engine, "rtt_64B", 30_000);

            // Handshake: no application thread on the server side is
            // involved until accept(), so this is link + engine. Each
            // connection is closed at once and lingers in TIME_WAIT.
            let mut events = Vec::new();
            let mut samples = Vec::with_capacity(super::CONNECTS);
            for i in 0..super::CONNECTS {
                let start = Instant::now();
                let tuple = engine
                    .connect(server, super::ECHO_PORT, 30_001 + i as u16)
                    .expect("tuple in use");
                'established: loop {
                    engine.poll_into(&port, &pool, Instant::now(), &mut events);
                    for (_, event) in events.drain(..) {
                        match event {
                            Event::Established => break 'established,
                            Event::Reset => panic!("connect failed"),
                            Event::PeerClosed | Event::Closed => {}
                        }
                    }
                    assert!(start.elapsed().as_secs() < 5, "connect timed out");
                }
                samples.push(start.elapsed());
                engine.close(tuple);
            }
            super::report_latency(&label, "connect_first20", samples[..20].to_vec());
            super::report_latency(&label, "connect_all300", samples);

            echo_rtt(&mut engine, "rtt_64B_after_300_closes", 31_000);
        }
        dpdk::eal::cleanup();
    }

    pub fn run(args: &[String]) {
        let (local_ip, server, label) = init(args, "dpdk");
        let worker_lcore = dpdk::first_worker_lcore().expect("need two lcores (-l 0-1)");
        let socket = dpdk::lcore::get_core_info(worker_lcore).socket as i32;
        let pool = Mempool::create("bench_pool", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, socket)
            .expect("failed to create mbuf pool");
        let port = EthPort::init(0, &pool, 1024, 1024, 1500, socket).expect("port init failed");
        let engine = TcpEngine::new(EngineConfig {
            local_mac: port.mac_addr().expect("no MAC address"),
            local_ip,
            gateway: None,
        });
        let (worker, join) =
            WorkerHandle::spawn(engine, port, pool, worker_lcore).expect("worker launch failed");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build tokio runtime");
        let next_port = AtomicU16::new(20_000);
        let result = runtime.block_on(super::run_async(&label, async |port: u16| {
            let local_port = next_port.fetch_add(1, Ordering::Relaxed);
            TcpStream::connect(
                &worker,
                server,
                port,
                local_port,
                TcpOptions::default(),
                None,
            )
            .await
        }));
        drop(worker);
        join.wait();
        dpdk::eal::cleanup();
        result.expect("dpdk benchmark failed");
    }
}

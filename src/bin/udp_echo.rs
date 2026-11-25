//! UDP echo over the DPDK stack: a server that bounces every datagram back
//! to its sender, or a client that sends numbered datagrams to an echo
//! server and measures their round trips.
//!
//! Usage:
//!   udp_echo <EAL args> -- <LOCAL_IP[/PREFIX]> [--gateway IP] [--workers N] \
//!       server <PORT> [--count N]
//!   udp_echo <EAL args> -- <LOCAL_IP[/PREFIX]> [--gateway IP] [--workers N] \
//!       client <PEER_IP:PORT> [--count N] [--size BYTES] [--port LOCAL_PORT] \
//!       [--timeout-ms MS]
//!
//! `--gateway` sends peers outside LOCAL_IP/PREFIX through that router.
//! `--workers` runs that many workers (one per EAL worker lcore, each on
//! its own NIC queue). A server port below 49152, or any port when the NIC
//! refused the UDP flow rules (`UDP steered per port: false`), is bound on
//! all of them, since RSS may hash its datagrams to any queue. An
//! ephemeral-range port on a steered NIC goes to its one steered worker
//! (see `docs/udp.md`).
//!
//! Server: echoes until it has echoed `--count` datagrams (forever without
//! it). It prints `listening on IP:PORT` to stderr once the port is bound,
//! which scripts wait for before sending.
//!
//! Client: binds `--port` (an ephemeral port by default), connects to the
//! peer and sends `--count` datagrams (default 10) of `--size` bytes
//! (default 64, at least 8) one at a time, each carrying its sequence
//! number in its first 8 bytes. A reply must come back with the same
//! payload within `--timeout-ms` (default 1000), or the datagram counts as
//! lost; replies to earlier, already-lost datagrams are skipped. The first
//! round trip includes ARP resolution of the next hop. Prints the round-
//! trip summary to stdout and exits non-zero if any datagram was lost.
//!
//! Example (in the devcontainer, kernel-visible tap interface, with a
//! kernel-side echo server on 10.9.0.2:7007):
//!   udp_echo -l 0-1 --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1 \
//!       client 10.9.0.2:7007 --count 100
//!
//! Requires the DPDK stack (the `dpdk` cfg, set by build.rs when libdpdk is
//! present); without it this binary is a stub that just reports as much.

#[cfg(not(dpdk))]
fn main() {
    eprintln!(
        "`udp_echo` requires the DPDK stack, but libdpdk was not found at build time; \
         build where libdpdk is available (the devcontainer)."
    );
    std::process::exit(1);
}

#[cfg(dpdk)]
fn main() -> std::process::ExitCode {
    dpdk_app::main()
}

#[cfg(dpdk)]
mod dpdk_app {
    use std::env;
    use std::net::SocketAddrV4;
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use bytes::{BufMut, Bytes, BytesMut};

    use httpio::dpdk::net::eth::EthAddr;
    use httpio::dpdk::tcp::engine::EngineConfig;
    use httpio::dpdk::tcp::stack::Stack;
    use httpio::dpdk::tcp::worker::WorkerHandle;
    use httpio::dpdk::udp::UdpSocket;
    use httpio::dpdk::{self, lcore};

    const PORT_ID: u16 = 0;
    /// Receive mbufs per worker. Smaller than the stack's default so that
    /// a worker fits EAL's default `--no-huge` memory, as `http_get`'s
    /// pool does; an echo holds at most a socket's queues' worth.
    const POOL_MBUFS: u32 = 8191;
    /// How long the server waits, after its last echo, for the worker to
    /// hand the echoes to the port before stopping it. `send_to` returns
    /// once a datagram is on the worker's ring, not once it is sent.
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    /// Sequence number at the front of every client datagram.
    const SEQ_LEN: usize = 8;

    enum Mode {
        Server {
            port: u16,
            count: Option<u64>,
        },
        Client {
            peer: SocketAddrV4,
            count: u64,
            size: usize,
            local_port: u16,
            timeout: Duration,
        },
    }

    struct AppArgs {
        /// Local IP and route; the MAC is the port's, set by the stack.
        engine: EngineConfig,
        workers: usize,
        mode: Mode,
    }

    const USAGE: &str = "usage: udp_echo <EAL args> -- <LOCAL_IP[/PREFIX]> [--gateway IP] \
        [--workers N] (server <PORT> [--count N] | client <PEER_IP:PORT> [--count N] \
        [--size BYTES] [--port LOCAL_PORT] [--timeout-ms MS])";

    pub fn main() -> ExitCode {
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
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            }
        };

        let eal_args: Vec<&str> = eal_args.iter().map(String::as_str).collect();
        dpdk::eal::init(&eal_args).expect("EAL initialization failed");

        // The workers run on worker lcores; the tokio runtime (and this
        // thread) stay on the main lcore.
        let lcores = worker_lcores(app.workers);
        if lcores.len() < app.workers {
            eprintln!(
                "error: {} worker(s) requested but EAL has {} worker lcore(s); \
                 start EAL with more (e.g. `-l 0-{}`)",
                app.workers,
                lcores.len(),
                app.workers
            );
            return ExitCode::FAILURE;
        }

        let mut builder = Stack::builder(PORT_ID, app.engine.local_ip)
            .lcores(&lcores)
            .pool_mbufs(POOL_MBUFS);
        if let Some(gateway) = app.engine.gateway {
            builder = builder.gateway(gateway);
        }
        let (worker, join) = match builder.build() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!(
            "stack running on worker lcore(s) {lcores:?}; UDP steered per port: {}",
            worker.udp_steered()
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build tokio runtime");
        let result = runtime.block_on(async move {
            match app.mode {
                Mode::Server { port, count } => serve(worker, port, count).await,
                Mode::Client {
                    peer,
                    count,
                    size,
                    local_port,
                    timeout,
                } => ping(worker, peer, count, size, local_port, timeout).await,
            }
        });

        // The handle is gone, so the workers are stopping: wait for their
        // lcores so the port and pools drop cleanly, then release EAL (and
        // the tap device, for the next process on it).
        join.wait();
        dpdk::eal::cleanup();
        result
    }

    /// The first `n` worker lcores, in order.
    fn worker_lcores(n: usize) -> Vec<u32> {
        let main = lcore::main_lcore_id();
        let mut lcores = Vec::with_capacity(n);
        let mut next = dpdk::first_worker_lcore();
        while let Some(lcore) = next {
            if lcores.len() == n {
                break;
            }
            if lcore != main {
                lcores.push(lcore);
            }
            next = lcore::next_lcore(lcore);
        }
        lcores
    }

    async fn serve(worker: WorkerHandle, port: u16, count: Option<u64>) -> ExitCode {
        let mut socket = match UdpSocket::bind(&worker, port).await {
            Ok(socket) => socket,
            Err(e) => {
                eprintln!("error: bind UDP port {port}: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("listening on {}", socket.local_addr());

        let mut echoed = 0u64;
        while count.is_none_or(|count| echoed < count) {
            let datagram = match socket.recv_from().await {
                Ok(datagram) => datagram,
                Err(e) => {
                    eprintln!("error: recv: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let src = datagram.src;
            if src.port() == 0 || src.ip().is_unspecified() {
                // Source port 0 means no reply is expected (RFC 768), and
                // 0.0.0.0 cannot be replied to: skip it rather than fail.
                continue;
            }
            // The payload goes back out as the very mbuf it arrived in
            // (`into_bytes` is a view, not a copy); the stack attaches it
            // to the reply or copies it, whichever the port supports.
            if let Err(e) = socket.send_to(datagram.into_bytes(), src).await {
                eprintln!("error: send to {src}: {e}");
                return ExitCode::FAILURE;
            }
            echoed += 1;
        }

        // Let the worker transmit the last echoes before the handle drops
        // and stops it.
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        loop {
            let stats = socket.stats();
            if stats.tx_datagrams + stats.tx_dropped >= echoed || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // The port has the frames; give the PMD a moment to put them on
        // the wire before the port is stopped.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats = socket.stats();
        eprintln!("echoed={echoed} stats={stats:?}");
        ExitCode::SUCCESS
    }

    async fn ping(
        worker: WorkerHandle,
        peer: SocketAddrV4,
        count: u64,
        size: usize,
        local_port: u16,
        timeout: Duration,
    ) -> ExitCode {
        let mut socket = match UdpSocket::bind(&worker, local_port).await {
            Ok(socket) => socket,
            Err(e) => {
                eprintln!("error: bind UDP port {local_port}: {e}");
                return ExitCode::FAILURE;
            }
        };
        if size > socket.max_datagram_size() {
            eprintln!(
                "error: --size {size} exceeds the largest datagram, {}",
                socket.max_datagram_size()
            );
            return ExitCode::FAILURE;
        }
        if let Err(e) = socket.connect(peer).await {
            eprintln!("error: connect {peer}: {e}");
            return ExitCode::FAILURE;
        }
        eprintln!(
            "{} -> {peer}: {count} datagram(s) of {size} bytes",
            socket.local_addr()
        );

        let mut rtts = Vec::with_capacity(count as usize);
        let mut lost = 0u64;
        for seq in 0..count {
            let payload = payload(seq, size);
            let start = Instant::now();
            if let Err(e) = socket.send(payload.clone()).await {
                eprintln!("error: send: {e}");
                return ExitCode::FAILURE;
            }
            let deadline = tokio::time::Instant::from_std(start + timeout);
            loop {
                match tokio::time::timeout_at(deadline, socket.recv()).await {
                    Err(_) => {
                        lost += 1;
                        eprintln!("seq {seq}: no reply within {timeout:?}");
                        break;
                    }
                    Ok(Err(e)) => {
                        eprintln!("error: recv: {e}");
                        return ExitCode::FAILURE;
                    }
                    Ok(Ok(reply)) if reply.data.as_slice() == &payload[..] => {
                        rtts.push(start.elapsed());
                        break;
                    }
                    // A late reply to an earlier, already-lost datagram, or
                    // a stray: keep waiting for this one.
                    Ok(Ok(_)) => {}
                }
            }
        }

        let stats = socket.stats();
        eprintln!("stats={stats:?}");
        report(count, lost, &mut rtts);
        if lost == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }

    /// `seq` big-endian, then a pattern derived from it, `size` bytes in
    /// all, so that a reply matches exactly one datagram.
    fn payload(seq: u64, size: usize) -> Bytes {
        let mut buf = BytesMut::with_capacity(size);
        buf.put_u64(seq);
        buf.extend((SEQ_LEN..size).map(|i| (seq as usize).wrapping_add(i) as u8));
        buf.freeze()
    }

    fn report(sent: u64, lost: u64, rtts: &mut [Duration]) {
        println!("sent={sent} received={} lost={lost}", rtts.len());
        if rtts.is_empty() {
            return;
        }
        rtts.sort_unstable();
        let us = |d: Duration| d.as_secs_f64() * 1e6;
        let pct = |p: usize| rtts[(rtts.len() - 1) * p / 100];
        let avg = rtts.iter().sum::<Duration>() / rtts.len() as u32;
        println!(
            "rtt_us min={:.1} avg={:.1} p50={:.1} p99={:.1} max={:.1}",
            us(rtts[0]),
            us(avg),
            us(pct(50)),
            us(pct(99)),
            us(rtts[rtts.len() - 1]),
        );
    }

    fn parse_app_args(args: &[String]) -> Result<AppArgs, String> {
        fn value<'a>(
            it: &mut impl Iterator<Item = &'a String>,
            flag: &str,
        ) -> Result<&'a str, String> {
            it.next()
                .map(String::as_str)
                .ok_or_else(|| format!("{flag} requires a value"))
        }
        fn number<T: std::str::FromStr>(text: &str, flag: &str) -> Result<T, String> {
            text.parse()
                .map_err(|_| format!("invalid value {text:?} for {flag}"))
        }

        let mut positional = Vec::new();
        let mut gateway = None;
        let mut workers = 1usize;
        let mut count = None;
        let mut size = 64usize;
        let mut local_port = 0u16;
        let mut timeout = Duration::from_millis(1000);

        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--gateway" => gateway = Some(value(&mut it, arg)?.to_string()),
                "--workers" => workers = number(value(&mut it, arg)?, arg)?,
                "--count" => count = Some(number::<u64>(value(&mut it, arg)?, arg)?),
                "--size" => size = number(value(&mut it, arg)?, arg)?,
                "--port" => local_port = number(value(&mut it, arg)?, arg)?,
                "--timeout-ms" => {
                    timeout = Duration::from_millis(number(value(&mut it, arg)?, arg)?)
                }
                other => positional.push(other),
            }
        }
        if workers == 0 {
            return Err("--workers must be at least 1".into());
        }

        let mode = match positional.as_slice() {
            [_, "server", port] => Mode::Server {
                port: number::<u16>(port, "PORT").and_then(|port| match port {
                    0 => Err("server PORT must not be 0".to_string()),
                    port => Ok(port),
                })?,
                count,
            },
            [_, "client", peer] => {
                if size < SEQ_LEN {
                    return Err(format!("--size must be at least {SEQ_LEN}"));
                }
                Mode::Client {
                    peer: number(peer, "PEER_IP:PORT")?,
                    count: count.unwrap_or(10),
                    size,
                    local_port,
                    timeout,
                }
            }
            _ => return Err("expected LOCAL_IP followed by `server PORT` or `client PEER`".into()),
        };
        Ok(AppArgs {
            engine: EngineConfig::from_cli(EthAddr::ZERO, positional[0], gateway.as_deref())?,
            workers,
            mode,
        })
    }
}

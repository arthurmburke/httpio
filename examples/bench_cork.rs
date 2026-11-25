//! Reaction time of a corked request: from `FlushHandle::flush()` to the
//! held segment being handed to the NIC. See scripts/bench_cork.sh.
//!
//! ```text
//! bench_cork <EAL args> -- <LOCAL_IP> <SERVER_IP>
//! ```
//!
//! The server is `bench_h2 server`. Each round stages one request -- a
//! 64-byte POST through the crate's HTTP client with `TcpOptions::cork`
//! set, so connection setup, the TLS handshake, encoding and encryption
//! are all done and the request sits in the TCP engine as one held segment
//! -- waits for the connection to go quiet, then flushes and asks the
//! worker's transmit probe (`dpdk::probe`) when the segment left.
//!
//! Before measuring, it checks that a flush cannot come too early:
//! requests flushed at every stage of being staged (before the connection
//! exists, during its handshakes, once held) must all be answered.
//!
//! Likewise for calling a request off: terminated through its handle at
//! each of those stages, it must fail, and the server's count of requests
//! received must not move.
//!
//! Two times are reported per case, both from the instant before
//! `flush()`:
//!
//! - `ready`: the packet is built and about to be handed to the driver.
//!   This is the stack's own reaction time.
//! - `sent`: the driver call returned. For a poll-mode NIC the two are
//!   nearly the same; for `af_packet` the difference is a system call.
//!
//! `prebuilt` counts the flushes whose segment went out as the packet the
//! engine had built while it was held, rather than one built at the flush.
//!
//! What the flushing task does next matters, so each corked case runs
//! twice: `yield`, where it yields to the runtime at once, and `busy10`,
//! where it works for 10 microseconds first (a caller that has more to do
//! at the moment it decides to send). `terminate` calls the request off
//! instead: the packet timed is the reset, and nothing of the request is
//! sent. `h2-reused` is the alternative to
//! corking for comparison: an HTTP/2 request sent, from scratch, on a
//! connection that is already open.
//!
//! BENCH_CORK_CASE (`cork-h1`, `cork-h1-tls`, `h2-reused`) and
//! BENCH_CORK_TRIGGER (`yield`, `busy10`) select cases.
//! BENCH_CORK_ROUNDS and BENCH_CORK_WARMUP override the samples per case;
//! BENCH_CORK_HOLD_MS keeps each request staged that much longer before
//! the flush (it is flushed as soon as the connection has been quiet for
//! 3 ms otherwise), with the calling thread asleep for the hold, or busy
//! if BENCH_CORK_HOLD_SPIN=1.

fn main() {
    #[cfg(all(dpdk, feature = "tx-probe"))]
    run::main();
    #[cfg(not(all(dpdk, feature = "tx-probe")))]
    panic!("bench_cork needs libdpdk and `--features tx-probe`; use the devcontainer");
}

#[cfg(all(dpdk, feature = "tx-probe"))]
mod run {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{Request, StatusCode, Version};
    use httpio::dpdk::http::client::Client;
    use httpio::dpdk::http::client::builder::Builder;
    use httpio::dpdk::mempool::{DEFAULT_MBUF_DATA_ROOM_SIZE, MAX_CACHE_SIZE, transmit_mbufs};
    use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
    use httpio::dpdk::tcp::stream::{FlushHandle, TcpOptions};
    use httpio::dpdk::tcp::worker::WorkerHandle;
    use httpio::dpdk::{self, EthPort, Mempool, probe};
    use httpio::http::codec::Raw;

    const CA: &[u8] = include_bytes!("../src/dpdk/tls_testdata/ca.pem");
    const H1_PORT: u16 = 7481;
    const H1_TLS_PORT: u16 = 7444;
    const H2_TLS_PORT: u16 = 7443;
    const BODY: usize = 64;
    /// The worker has transmitted nothing for this long: handshakes are
    /// over, delayed ACKs have gone, and whatever is still unsent is held.
    const QUIET: Duration = Duration::from_millis(3);

    fn setting(name: &str, default: usize) -> usize {
        std::env::var(name).map_or(default, |v| v.parse().expect("invalid benchmark setting"))
    }

    async fn quiet() {
        loop {
            let before = probe::bursts();
            tokio::time::sleep(QUIET).await;
            if probe::bursts() == before {
                return;
            }
        }
    }

    fn post(url: &str) -> Request<Raw> {
        Request::post(format!("{url}/{BODY}"))
            .header("content-type", "application/octet-stream")
            .body(Raw(Bytes::from(vec![0x5a; BODY])))
            .unwrap()
    }

    /// Waits for the armed probe, yielding to the runtime between looks.
    async fn fired() -> (u64, u64) {
        let deadline = probe::now_ns() + 5_000_000_000;
        loop {
            if let Some(times) = probe::fired() {
                return times;
            }
            assert!(probe::now_ns() < deadline, "nothing was transmitted");
            tokio::task::yield_now().await;
        }
    }

    /// A flush cannot come too early: flushed after `yields` turns of the
    /// runtime -- before the connection exists, during its handshakes, or
    /// once it is staged -- the request must still be answered.
    async fn flushed_early(client: &Client, url: &str, yields: usize) {
        let flush = FlushHandle::new();
        let mut request = post(url);
        request.extensions_mut().insert(TcpOptions {
            cork: true,
            ..TcpOptions::default()
        });
        request.extensions_mut().insert(flush.clone());
        let client = client.clone();
        let mut task = tokio::spawn(async move { client.request::<Raw, Raw>(request).await });
        for _ in 0..yields {
            tokio::task::yield_now().await;
        }
        flush.flush();
        let Ok(response) = tokio::time::timeout(Duration::from_secs(3), &mut task).await else {
            task.abort();
            panic!("a flush {yields} turns into {url} was lost: the request is still held");
        };
        let response = response.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body().0.as_ref(), b"ok");
    }

    /// How many requests have reached the server.
    async fn served(client: &Client, plain: &str) -> usize {
        let request = Request::get(format!("{plain}/served"))
            .body(Raw(Bytes::new()))
            .unwrap();
        let response = client.request::<Raw, Raw>(request).await.unwrap();
        std::str::from_utf8(&response.body().0)
            .unwrap()
            .parse()
            .unwrap()
    }

    /// A request called off through its handle after `yields` turns of the
    /// runtime -- before it has a connection, during the handshakes, or
    /// held -- must fail promptly rather than wait or be sent.
    async fn terminated_early(client: &Client, url: &str, yields: usize) {
        let handle = FlushHandle::new();
        let mut request = post(url);
        request.extensions_mut().insert(TcpOptions {
            cork: true,
            ..TcpOptions::default()
        });
        request.extensions_mut().insert(handle.clone());
        let client = client.clone();
        let mut task = tokio::spawn(async move { client.request::<Raw, Raw>(request).await });
        for _ in 0..yields {
            tokio::task::yield_now().await;
        }
        handle.abort();
        let Ok(outcome) = tokio::time::timeout(Duration::from_secs(3), &mut task).await else {
            task.abort();
            panic!("a request terminated {yields} turns into {url} is still waiting");
        };
        assert!(
            outcome.unwrap().is_err(),
            "a request terminated {yields} turns into {url} was answered"
        );
    }

    /// One corked request: staged, then flushed -- or, with `terminate`,
    /// called off, in which case the packet timed is the reset. `busy_ns`
    /// is how long the calling task keeps the thread afterwards before it
    /// yields.
    async fn corked(client: &Client, url: &str, busy_ns: u64, terminate: bool) -> (u64, u64) {
        let flush = FlushHandle::new();
        let mut request = post(url);
        request.extensions_mut().insert(TcpOptions {
            cork: true,
            ..TcpOptions::default()
        });
        request.extensions_mut().insert(flush.clone());
        let client = client.clone();
        let task = tokio::spawn(async move { client.request::<Raw, Raw>(request).await });
        quiet().await;
        // Longer on the shelf, if asked: what a flush touches goes cold.
        let hold = setting("BENCH_CORK_HOLD_MS", 0);
        if hold > 0 && setting("BENCH_CORK_HOLD_SPIN", 0) == 1 {
            // Keep the calling thread busy for the hold instead of asleep.
            let until = probe::now_ns() + hold as u64 * 1_000_000;
            while probe::now_ns() < until {
                tokio::task::yield_now().await;
            }
        } else if hold > 0 {
            tokio::time::sleep(Duration::from_millis(hold as u64)).await;
        }
        assert!(!task.is_finished(), "the request was not held");

        probe::arm();
        let start = probe::now_ns();
        if terminate {
            flush.abort();
        } else {
            flush.flush();
        }
        while probe::now_ns() - start < busy_ns {
            std::hint::spin_loop();
        }
        let (ready, sent) = fired().await;

        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the request neither answered nor failed")
            .unwrap();
        if terminate {
            assert!(outcome.is_err(), "a terminated request was answered");
            return (ready - start, sent - start);
        }
        let response = outcome.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_11);
        assert_eq!(response.body().0.as_ref(), b"ok");
        (ready - start, sent - start)
    }

    /// The same upload as a new stream on an open HTTP/2 connection:
    /// everything a corked request did ahead of time happens now.
    async fn h2_reused(client: &Client, url: &str) -> (u64, u64) {
        quiet().await;
        probe::arm();
        let start = probe::now_ns();
        let response = client.request::<Raw, Raw>(post(url)).await.unwrap();
        let (ready, sent) = probe::fired().expect("the request was transmitted");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);
        (ready - start, sent - start)
    }

    fn report(case: &str, trigger: &str, samples: &[(u64, u64)], prebuilt: u64) {
        let column = |pick: fn(&(u64, u64)) -> u64| {
            let mut values: Vec<u64> = samples.iter().map(pick).collect();
            values.sort_unstable();
            let at = |q: f64| values[((values.len() - 1) as f64 * q) as usize] as f64 / 1e3;
            let mean = values.iter().sum::<u64>() as f64 / values.len() as f64 / 1e3;
            format!(
                "{:.2}\t{:.2}\t{:.2}\t{:.2}\t{:.2}",
                at(0.0),
                at(0.5),
                at(0.9),
                at(0.99),
                mean
            )
        };
        println!(
            "{case}\t{trigger}\t{}\t{}\t{}\t{prebuilt}",
            samples.len(),
            column(|s| s.0),
            column(|s| s.1)
        );
    }

    pub fn main() {
        let args: Vec<_> = std::env::args().collect();
        let split = args
            .iter()
            .position(|s| s == "--")
            .expect("EAL_ARGS -- LOCAL_IP SERVER_IP");
        let mut eal_args = vec!["bench_cork"];
        eal_args.extend(args[1..split].iter().map(String::as_str));
        dpdk::eal::init(&eal_args).unwrap();
        let local_ip = args[split + 1].parse().unwrap();
        let ip: Ipv4Addr = args[split + 2].parse().unwrap();
        let pool = Mempool::new("bench_cork", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
        let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).unwrap();
        let engine = TcpEngine::new(EngineConfig {
            local_ip,
            local_mac: port.mac_addr().unwrap(),
            gateway: None,
        });
        let tx_pool = Mempool::new(
            "bench_cork_tx",
            transmit_mbufs(1024),
            MAX_CACHE_SIZE,
            DEFAULT_MBUF_DATA_ROOM_SIZE,
            -1,
        )
        .unwrap();
        let (worker, join) = WorkerHandle::spawn(
            engine,
            port,
            tx_pool,
            dpdk::first_worker_lcore().expect("two lcores required"),
        )
        .unwrap();

        let rounds = setting("BENCH_CORK_ROUNDS", 500);
        let warmup = setting("BENCH_CORK_WARMUP", 20);
        println!(
            "case\ttrigger\tsamples\tready_min_us\tready_p50_us\tready_p90_us\tready_p99_us\tready_mean_us\tsent_min_us\tsent_p50_us\tsent_p90_us\tsent_p99_us\tsent_mean_us\tprebuilt"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = Builder::new()
                .add_root_ca_pem(CA)
                .unwrap()
                .resolve("test.local", ip)
                .build(worker.clone());
            let plain = format!("http://{ip}:{H1_PORT}");
            let tls = format!("https://test.local:{H1_TLS_PORT}");
            let h2 = format!("https://test.local:{H2_TLS_PORT}");
            // Whenever the flush comes, the request is released.
            for url in [&plain, &tls] {
                for yields in [0, 1, 2, 5, 20, 100, 500, 5_000] {
                    for _ in 0..3 {
                        flushed_early(&client, url, yields).await;
                    }
                }
            }
            eprintln!("flushes at every stage of staging: all answered");
            // Whenever the termination comes, the request fails, and the
            // server never sees it.
            let before = served(&client, &plain).await;
            for url in [&plain, &tls] {
                for yields in [0, 1, 2, 5, 20, 100, 500, 5_000] {
                    for _ in 0..3 {
                        terminated_early(&client, url, yields).await;
                    }
                }
            }
            let reached = served(&client, &plain).await - before;
            assert_eq!(reached, 0, "terminated requests reached the server");
            // And the client is none the worse for it.
            flushed_early(&client, &plain, 500).await;
            flushed_early(&client, &tls, 500).await;
            eprintln!("terminations at every stage of staging: all failed, none sent");
            for (case, url) in [("cork-h1", &plain), ("cork-h1-tls", &tls)] {
                if std::env::var("BENCH_CORK_CASE").is_ok_and(|only| only != case) {
                    continue;
                }
                for (trigger, busy_ns, terminate) in [
                    ("yield", 0, false),
                    ("busy10", 10_000, false),
                    ("terminate", 0, true),
                ] {
                    if std::env::var("BENCH_CORK_TRIGGER").is_ok_and(|only| only != trigger) {
                        continue;
                    }
                    let mut samples = Vec::with_capacity(rounds);
                    let mut prebuilt = 0;
                    for round in 0..warmup + rounds {
                        if round == warmup {
                            prebuilt = probe::prebuilt_sent();
                        }
                        let sample = corked(&client, url, busy_ns, terminate).await;
                        if round >= warmup {
                            samples.push(sample);
                        }
                    }
                    report(case, trigger, &samples, probe::prebuilt_sent() - prebuilt);
                }
            }
            let mut samples = Vec::with_capacity(rounds);
            if std::env::var("BENCH_CORK_CASE").is_ok_and(|only| only != "h2-reused") {
                return;
            }
            for round in 0..warmup + rounds {
                let sample = h2_reused(&client, &h2).await;
                if round >= warmup {
                    samples.push(sample);
                }
            }
            report("h2-reused", "send", &samples, 0);
        });
        drop(worker);
        join.wait();
        dpdk::eal::cleanup();
    }
}

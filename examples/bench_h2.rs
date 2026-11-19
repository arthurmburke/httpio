//! HTTP/2 client benchmark over the DPDK stack: this crate's codec
//! (`dpdk-h2`) against hyper's (`dpdk-hyper`), each on one reused
//! connection to the same kernel server; see scripts/bench_h2.sh.
//!
//! ```text
//! bench_h2 server <IP>
//! bench_h2 dpdk-h2|dpdk-hyper <EAL args> -- <LOCAL_IP> <SERVER_IP>
//! ```
//!
//! Each client runs over TLS (ALPN `h2`, as the HTTP client uses it) and
//! over cleartext with prior knowledge (`h2c`, the codec without the
//! cipher). Per case it reports the wall-clock latency of a request, which
//! is mostly the server's and the link's, and `client_us`: the time spent
//! inside polls of the client's own futures -- the request, the connection
//! driver and whatever tasks the client spawns -- per request. That is the
//! client's processing cost with the waiting taken out: no kernel, no
//! server, no wire. `polls` is how many such polls a request took.
//!
//! BENCH_H2_ROUNDS and BENCH_H2_WARMUP override the samples per case;
//! BENCH_H2_PROTO=tls|h2c, BENCH_H2_METHOD=GET|POST and BENCH_H2_BYTES
//! select cases; BENCH_H2_CONCURRENCY sets the in-flight requests of the
//! concurrent workload (default 32).
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::cell::Cell;
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TLS_PORT: u16 = 7443;
const H2C_PORT: u16 = 7480;
const SIZES: [usize; 3] = [64, 16 * 1024, 1024 * 1024];
const CERT: &[u8] = include_bytes!("../src/dpdk/tls_testdata/server.pem");
const KEY: &[u8] = include_bytes!("../src/dpdk/tls_testdata/server.key");

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |v| v.parse().expect("invalid benchmark setting"))
}

fn selected(name: &str, value: &str) -> bool {
    std::env::var(name).map_or(true, |v| v == value)
}

fn runtime(io: bool) -> tokio::runtime::Runtime {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder.enable_time();
    if io {
        builder.enable_io();
    }
    builder.build().unwrap()
}

// ---- the kernel server -----------------------------------------------------

async fn serve<S>(io: S, bodies: Arc<Vec<Bytes>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let bodies = bodies.clone();
        async move {
            let size: usize = req.uri().path().trim_start_matches('/').parse().unwrap();
            let index = SIZES.iter().position(|n| *n == size).unwrap();
            let upload = req.method() == http::Method::POST;
            let body = req.into_body().collect().await.unwrap().to_bytes();
            if upload {
                assert_eq!(body.len(), size);
                assert!(body.iter().all(|b| *b == 0x5a));
            } else {
                assert!(body.is_empty());
            }
            let response = Response::builder()
                .header("content-type", "application/octet-stream")
                .body(Full::new(if upload {
                    Bytes::from_static(b"ok")
                } else {
                    bodies[index].clone()
                }))
                .unwrap();
            Ok::<_, Infallible>(response)
        }
    });
    // A client that goes away mid-connection is not the server's failure.
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn server(ip: Ipv4Addr) {
    let certs = rustls_pemfile::certs(&mut &CERT[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let bodies: Arc<Vec<_>> = Arc::new(
        SIZES
            .into_iter()
            .map(|n| Bytes::from(vec![0x5a; n]))
            .collect(),
    );
    let tls = tokio::net::TcpListener::bind((ip, TLS_PORT)).await.unwrap();
    let h2c = tokio::net::TcpListener::bind((ip, H2C_PORT)).await.unwrap();
    eprintln!("HTTP/2 benchmark server ready on {ip}:{TLS_PORT} (tls) and :{H2C_PORT} (h2c)");
    loop {
        tokio::select! {
            accepted = tls.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                let (acceptor, bodies) = (acceptor.clone(), bodies.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(socket).await {
                        serve(stream, bodies).await;
                    }
                });
            }
            accepted = h2c.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                tokio::spawn(serve(socket, bodies.clone()));
            }
        }
    }
}

// ---- measuring ---------------------------------------------------------------

thread_local! {
    /// Seconds spent inside polls of the client's futures on this thread.
    static BUSY: Cell<f64> = const { Cell::new(0.0) };
    static POLLS: Cell<u64> = const { Cell::new(0) };
    /// Polls of this crate's connection driver, of those.
    static DRIVER_POLLS: Cell<u64> = const { Cell::new(0) };
}

/// Runs `future`, charging the time of each of its polls to [`BUSY`].
async fn timed<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    poll_fn(|cx| {
        let start = httpio::core::time::Instant::now();
        let poll = future.as_mut().poll(cx);
        let elapsed = start.elapsed().as_secs_f64();
        BUSY.with(|busy| busy.set(busy.get() + elapsed));
        POLLS.with(|polls| polls.set(polls.get() + 1));
        poll
    })
    .await
}

fn busy() -> (f64, u64) {
    (BUSY.with(Cell::get), POLLS.with(Cell::get))
}

/// Spawns the tasks hyper asks for (its per-request ones included) with
/// their polls charged to the client, like the request's own.
#[derive(Clone)]
struct TimedExecutor;

impl<F> hyper::rt::Executor<F> for TimedExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(timed(future));
    }
}

fn request(base: &str, size: usize, payload: &Bytes) -> Request<Bytes> {
    let method = if payload.is_empty() { "GET" } else { "POST" };
    Request::builder()
        .method(method)
        .uri(format!("{base}/{size}"))
        .header("content-type", "application/octet-stream")
        .body(payload.clone())
        .unwrap()
}

fn check(body: &Bytes, size: usize, upload: bool) {
    if upload {
        assert_eq!(body.as_ref(), b"ok");
    } else {
        assert_eq!(body.len(), size);
        assert!(body.iter().all(|b| *b == 0x5a));
    }
}

fn report(
    label: &str,
    proto: &str,
    workload: &str,
    method: &str,
    size: usize,
    mut samples: Vec<f64>,
    per_sample: usize,
    client: (f64, u64),
) {
    let rounds = samples.len();
    samples.sort_unstable_by(f64::total_cmp);
    let total: f64 = samples.iter().sum();
    let requests = (rounds * per_sample) as f64;
    let at = |q: f64| samples[((rounds - 1) as f64 * q) as usize] / per_sample as f64 * 1e6;
    println!(
        "{label}\t{proto}\t{workload}\t{method}\t{size}\t{rounds}\t{:.2}\t{:.2}\t{:.2}\t{:.3}\t{:.2}\t{:.0}",
        at(0.5),
        at(0.99),
        total / requests * 1e6,
        client.0 / requests * 1e6,
        client.1 as f64 / requests,
        requests / total,
    );
}

/// Runs every case over one connection. `send` performs one exchange and
/// returns the collected body.
async fn measure<F>(label: &str, proto: &str, base: &str, send: F)
where
    F: AsyncFn(Request<Bytes>) -> Bytes,
{
    let warmup = setting("BENCH_H2_WARMUP", 200);
    // One request at a time.
    for upload in [false, true] {
        let method = if upload { "POST" } else { "GET" };
        if !selected("BENCH_H2_METHOD", method) {
            continue;
        }
        for size in SIZES {
            if !selected("BENCH_H2_BYTES", &size.to_string()) {
                continue;
            }
            let rounds = setting(
                "BENCH_H2_ROUNDS",
                if size == 1024 * 1024 { 200 } else { 3000 },
            );
            let payload = if upload {
                Bytes::from(vec![0x5a; size])
            } else {
                Bytes::new()
            };
            let mut samples = Vec::with_capacity(rounds);
            let mut before = busy();
            for i in 0..warmup.min(rounds) + rounds {
                if i == warmup.min(rounds) {
                    before = busy();
                }
                let req = request(base, size, &payload);
                let start = Instant::now();
                let body = tokio::time::timeout(Duration::from_secs(15), timed(send(req)))
                    .await
                    .expect("request timed out");
                let elapsed = start.elapsed();
                check(&body, size, upload);
                if i >= warmup.min(rounds) {
                    samples.push(elapsed.as_secs_f64());
                }
            }
            let after = busy();
            let client = (after.0 - before.0, after.1 - before.1);
            report(label, proto, "sequential", method, size, samples, 1, client);
        }
    }
    // Many requests in flight on the connection at once.
    let concurrency = setting("BENCH_H2_CONCURRENCY", 32);
    if concurrency > 1 && selected("BENCH_H2_METHOD", "GET") {
        for size in [64, 16 * 1024] {
            if !selected("BENCH_H2_BYTES", &size.to_string()) {
                continue;
            }
            let rounds = setting("BENCH_H2_ROUNDS", 3000) / 8;
            let warmup = warmup.min(rounds) / 8 + 1;
            let payload = Bytes::new();
            let mut samples = Vec::with_capacity(rounds);
            let mut before = busy();
            for i in 0..warmup + rounds {
                if i == warmup {
                    before = busy();
                }
                let batch = (0..concurrency).map(|_| send(request(base, size, &payload)));
                let start = Instant::now();
                let bodies = tokio::time::timeout(
                    Duration::from_secs(15),
                    timed(futures::future::join_all(batch)),
                )
                .await
                .expect("batch timed out");
                let elapsed = start.elapsed();
                for body in &bodies {
                    check(body, size, false);
                }
                if i >= warmup {
                    samples.push(elapsed.as_secs_f64());
                }
            }
            let after = busy();
            let client = (after.0 - before.0, after.1 - before.1);
            let workload = format!("concurrent{concurrency}");
            report(
                label,
                proto,
                &workload,
                "GET",
                size,
                samples,
                concurrency,
                client,
            );
        }
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => runtime(true).block_on(server(args[2].parse().unwrap())),
        Some("dpdk-h2" | "dpdk-hyper") => dpdk_run(&args),
        _ => panic!(
            "usage: bench_h2 server IP, or dpdk-h2|dpdk-hyper EAL_ARGS -- LOCAL_IP SERVER_IP"
        ),
    }
}

#[cfg(not(dpdk))]
fn dpdk_run(_: &[String]) {
    panic!("DPDK mode requires libdpdk; use the devcontainer");
}

#[cfg(dpdk)]
fn dpdk_run(args: &[String]) {
    use httpio::dpdk::http::h2;
    use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
    use httpio::dpdk::tcp::{
        engine::{EngineConfig, TcpEngine},
        stream::{TcpOptions, TcpStream},
        worker::WorkerHandle,
    };
    use httpio::dpdk::tls::{self, TlsStream};
    use httpio::dpdk::{self, EthPort, Mempool};
    use httpio::http::codec::EncodedBody;
    use hyper::client::conn::http2;
    use rustls::pki_types::ServerName;

    const CA: &[u8] = include_bytes!("../src/dpdk/tls_testdata/ca.pem");

    let split = args.iter().position(|s| s == "--").unwrap();
    let mut eal_args = vec!["bench_h2"];
    eal_args.extend(args[2..split].iter().map(String::as_str));
    dpdk::eal::init(&eal_args).unwrap();
    let local_ip = args[split + 1].parse().unwrap();
    let ip: Ipv4Addr = args[split + 2].parse().unwrap();
    let pool = Mempool::create("bench_h2", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
    let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).unwrap();
    let engine = TcpEngine::new(EngineConfig {
        local_ip,
        local_mac: port.mac_addr().unwrap(),
        gateway: None,
    });
    let tx_pool = Mempool::create_for_transmit("bench_h2_tx", 1024, -1).unwrap();
    let (worker, join) = WorkerHandle::spawn(
        engine,
        port,
        tx_pool,
        dpdk::first_worker_lcore().expect("two lcores required"),
    )
    .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &CA[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let config = Arc::new(config);

    let ours = args[1] == "dpdk-h2";
    let label = args[1].as_str();
    println!(
        "backend\tproto\tworkload\tmethod\tbytes\tsamples\twall_p50_us\twall_p99_us\twall_mean_us\tclient_us\tpolls\treq_s"
    );
    runtime(false).block_on(async {
        let mut local_port = 49152u16;
        let mut connect = async |port: u16| {
            local_port += 1;
            TcpStream::connect(&worker, ip, port, local_port, TcpOptions::default(), None)
                .await
                .unwrap()
        };
        let secure = async |tcp: TcpStream| -> TlsStream {
            let name = ServerName::try_from("test.local").unwrap();
            let stream = tls::connect(config.clone(), name, tcp).await.unwrap();
            assert_eq!(stream.alpn_protocol(), Some(b"h2".as_slice()));
            stream
        };
        // This crate's codec: owned buffers to and from the transport.
        async fn ours_over<T>(label: &str, proto: &str, base: &str, io: T)
        where
            T: h2::Transport + Send + 'static,
        {
            let (sender, connection) = h2::handshake(io);
            let mut connection = Box::pin(connection);
            let driver = tokio::spawn(timed(poll_fn(move |cx| {
                DRIVER_POLLS.with(|polls| polls.set(polls.get() + 1));
                connection.as_mut().poll(cx)
            })));
            measure(label, proto, base, async |req: Request<Bytes>| {
                let (parts, body) = req.into_parts();
                let response = sender
                    .send(parts, EncodedBody::Full(body))
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.into_body().collect().await.unwrap()
            })
            .await;
            drop(sender);
            driver.await.unwrap().unwrap();
            eprintln!(
                "{label} {proto}: driver polls {}",
                DRIVER_POLLS.with(Cell::take)
            );
        }
        // hyper's, through the stream's AsyncRead/AsyncWrite face.
        async fn hyper_over<S>(label: &str, proto: &str, base: &str, io: S)
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        {
            let (sender, connection) = http2::Builder::new(TimedExecutor)
                .handshake(TokioIo::new(io))
                .await
                .unwrap();
            let driver = tokio::spawn(timed(connection));
            measure(label, proto, base, async |req: Request<Bytes>| {
                let mut sender = sender.clone();
                let response = sender.send_request(req.map(Full::new)).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.into_body().collect().await.unwrap().to_bytes()
            })
            .await;
            drop(sender);
            driver.abort();
        }

        if selected("BENCH_H2_PROTO", "tls") {
            let base = format!("https://test.local:{TLS_PORT}");
            let stream = secure(connect(TLS_PORT).await).await;
            if ours {
                ours_over(label, "tls", &base, stream).await;
            } else {
                hyper_over(label, "tls", &base, stream).await;
            }
        }
        if selected("BENCH_H2_PROTO", "h2c") {
            let base = format!("http://{ip}:{H2C_PORT}");
            let stream = connect(H2C_PORT).await;
            if ours {
                ours_over(label, "h2c", &base, stream).await;
            } else {
                hyper_over(label, "h2c", &base, stream).await;
            }
        }
    });
    drop(worker);
    join.wait();
    dpdk::eal::cleanup();
}

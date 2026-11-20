//! HTTP client benchmark over the DPDK stack: this crate's codecs
//! (`dpdk-h2`) against hyper's over the same DPDK streams (`dpdk-hyper`) and
//! against hyper over kernel sockets (`kernel`), all talking to the same
//! kernel server; see scripts/bench_h2.sh.
//!
//! ```text
//! bench_h2 server <IP>
//! bench_h2 kernel <SERVER_IP>
//! bench_h2 dpdk-h2|dpdk-hyper|dpdk-client <EAL args> -- <LOCAL_IP> <SERVER_IP>
//! ```
//!
//! Protocols: `tls` is HTTP/2 over TLS (ALPN `h2`, as the HTTP client uses
//! it), `h2c` is HTTP/2 in cleartext with prior knowledge (the codec
//! without the cipher), and `h1` is HTTP/1.1 in cleartext.
//!
//! Workloads: `sequential` and `concurrentN` reuse one connection, which
//! is how HTTP/2 is used. `fresh` opens a connection for every request --
//! TCP handshake, protocol preface, one exchange -- which is the only way
//! this crate's HTTP/1.1 codec is used, and puts HTTP/2 on the same
//! footing for comparison.
//!
//! Per case it reports the wall-clock latency of a request, which is
//! mostly the server's and the link's, and `client_us`: the time spent
//! inside polls of the client's own futures -- the request, the connection
//! driver and whatever tasks the client spawns -- per request. For the
//! DPDK clients that is the client's processing cost with the waiting
//! taken out: no kernel, no server, no wire (the TCP work is on the worker
//! lcore and is not counted). For `kernel` the polls contain the socket
//! system calls, so its `client_us` includes the kernel's TCP work on the
//! client side. `polls` is how many such polls a request took.
//!
//! `dpdk-client` runs the TLS cases through the crate's HTTP client
//! (`dpdk::http::client::Client`) instead of the codec's own API: the
//! pool, the body codecs and all. It first checks that streamed uploads
//! ride the pooled HTTP/2 connection, and at the end that the whole run
//! used one connection. Its `client_us` leaves out the connection driver,
//! which the client spawns itself.
//!
//! BENCH_H2_ROUNDS, BENCH_H2_FRESH_ROUNDS and BENCH_H2_WARMUP override the
//! samples per case; BENCH_H2_PROTO=tls|h2c|h1, BENCH_H2_WORKLOAD=reused|fresh,
//! BENCH_H2_METHOD=GET|POST and BENCH_H2_BYTES select cases;
//! BENCH_H2_CONCURRENCY sets the in-flight requests of the concurrent
//! workload (default 32).
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
const H1_PORT: u16 = 7481;
/// HTTP/1.1 over TLS, for `bench_cork` (a corked request is HTTP/1.1).
const H1_TLS_PORT: u16 = 7444;
const CA: &[u8] = include_bytes!("../src/dpdk/tls_testdata/ca.pem");
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

async fn serve<S>(io: S, bodies: Arc<Vec<Bytes>>, h1: bool)
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
            let mut response = Response::builder();
            if h1 {
                // One request per connection, as the clients use it.
                response = response.header("connection", "close");
            }
            let response = response
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
    if h1 {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .await;
    } else {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    }
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
    let mut h1_config = config.clone();
    h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let h1_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(h1_config));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let bodies: Arc<Vec<_>> = Arc::new(
        SIZES
            .into_iter()
            .map(|n| Bytes::from(vec![0x5a; n]))
            .collect(),
    );
    let tls = tokio::net::TcpListener::bind((ip, TLS_PORT)).await.unwrap();
    let h2c = tokio::net::TcpListener::bind((ip, H2C_PORT)).await.unwrap();
    let h1 = tokio::net::TcpListener::bind((ip, H1_PORT)).await.unwrap();
    let h1_tls = tokio::net::TcpListener::bind((ip, H1_TLS_PORT))
        .await
        .unwrap();
    eprintln!(
        "HTTP benchmark server ready on {ip}:{TLS_PORT} (tls), :{H2C_PORT} (h2c) and :{H1_PORT} (h1)"
    );
    loop {
        tokio::select! {
            accepted = tls.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                let (acceptor, bodies) = (acceptor.clone(), bodies.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(socket).await {
                        serve(stream, bodies, false).await;
                    }
                });
            }
            accepted = h2c.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                tokio::spawn(serve(socket, bodies.clone(), false));
            }
            accepted = h1_tls.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                let (acceptor, bodies) = (h1_acceptor.clone(), bodies.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(socket).await {
                        serve(stream, bodies, true).await;
                    }
                });
            }
            accepted = h1.accept() => {
                let (socket, _) = accepted.unwrap();
                socket.set_nodelay(true).unwrap();
                tokio::spawn(serve(socket, bodies.clone(), true));
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

/// Whether `send` reuses one connection or opens one per request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Workload {
    Reused,
    Fresh,
}

fn tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &CA[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// HTTP/1.1 wants an origin-form target and a `Host` header, which
/// neither hyper's connection API nor this crate's codec adds.
fn origin_form(mut request: Request<Bytes>) -> Request<Bytes> {
    let host = request.uri().authority().unwrap().as_str().parse().unwrap();
    request.headers_mut().insert(http::header::HOST, host);
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    request
}

/// hyper's HTTP/2 client on one reused connection over `io`.
async fn hyper_h2_reused<S>(label: &str, proto: &str, base: &str, io: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper::client::conn::http2;
    let (sender, connection) = http2::Builder::new(TimedExecutor)
        .handshake(TokioIo::new(io))
        .await
        .unwrap();
    let driver = tokio::spawn(timed(connection));
    measure(
        label,
        proto,
        Workload::Reused,
        base,
        async |req: Request<Bytes>| {
            let mut sender = sender.clone();
            let response = sender.send_request(req.map(Full::new)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await.unwrap().to_bytes()
        },
    )
    .await;
    drop(sender);
    driver.abort();
}

/// One request over a connection of its own with hyper's HTTP/2 client.
/// Timing stops at the end of the body: the connection is dropped, not
/// shut down.
async fn hyper_h2_once<S>(io: S, req: Request<Bytes>) -> Bytes
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TimedExecutor)
        .handshake(TokioIo::new(io))
        .await
        .unwrap();
    let driver = tokio::spawn(timed(connection));
    let response = sender.send_request(req.map(Full::new)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    driver.abort();
    body
}

/// One request over a connection of its own with hyper's HTTP/1.1 client.
async fn hyper_h1_once<S>(io: S, req: Request<Bytes>) -> Bytes
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    let driver = tokio::spawn(timed(connection));
    let request = origin_form(req).map(Full::new);
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    driver.abort();
    body
}

/// hyper over kernel sockets: the reference both DPDK clients are up
/// against.
async fn kernel_run(ip: Ipv4Addr) {
    let label = "kernel";
    let connect = async |port: u16| {
        let socket = tokio::net::TcpStream::connect((ip, port)).await.unwrap();
        socket.set_nodelay(true).unwrap();
        socket
    };
    if selected("BENCH_H2_WORKLOAD", "reused") {
        if selected("BENCH_H2_PROTO", "tls") {
            let connector = tokio_rustls::TlsConnector::from(tls_client_config());
            let name = rustls::pki_types::ServerName::try_from("test.local").unwrap();
            let stream = connector
                .connect(name, connect(TLS_PORT).await)
                .await
                .unwrap();
            let base = format!("https://test.local:{TLS_PORT}");
            hyper_h2_reused(label, "tls", &base, stream).await;
        }
        if selected("BENCH_H2_PROTO", "h2c") {
            let base = format!("http://{ip}:{H2C_PORT}");
            hyper_h2_reused(label, "h2c", &base, connect(H2C_PORT).await).await;
        }
    }
    if selected("BENCH_H2_WORKLOAD", "fresh") {
        if selected("BENCH_H2_PROTO", "h1") {
            let base = format!("http://{ip}:{H1_PORT}");
            measure(label, "h1", Workload::Fresh, &base, async |req| {
                hyper_h1_once(connect(H1_PORT).await, req).await
            })
            .await;
        }
        if selected("BENCH_H2_PROTO", "h2c") {
            let base = format!("http://{ip}:{H2C_PORT}");
            measure(label, "h2c", Workload::Fresh, &base, async |req| {
                hyper_h2_once(connect(H2C_PORT).await, req).await
            })
            .await;
        }
    }
}

/// Runs every case. `send` performs one exchange and returns the
/// collected body.
async fn measure<F>(label: &str, proto: &str, workload: Workload, base: &str, send: F)
where
    F: AsyncFn(Request<Bytes>) -> Bytes,
{
    let fresh = workload == Workload::Fresh;
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
            let large = size == 1024 * 1024;
            let rounds = if fresh {
                setting("BENCH_H2_FRESH_ROUNDS", if large { 100 } else { 1000 })
            } else {
                setting("BENCH_H2_ROUNDS", if large { 200 } else { 3000 })
            };
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
            let name = if fresh { "fresh" } else { "sequential" };
            report(label, proto, name, method, size, samples, 1, client);
        }
    }
    // Many requests in flight on the connection at once.
    let concurrency = setting("BENCH_H2_CONCURRENCY", 32);
    if !fresh && concurrency > 1 && selected("BENCH_H2_METHOD", "GET") {
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

const HEADER: &str = "backend\tproto\tworkload\tmethod\tbytes\tsamples\twall_p50_us\twall_p99_us\twall_mean_us\tclient_us\tpolls\treq_s";

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => runtime(true).block_on(server(args[2].parse().unwrap())),
        Some("kernel") => {
            println!("{HEADER}");
            runtime(true).block_on(kernel_run(args[2].parse().unwrap()));
        }
        Some("dpdk-h2" | "dpdk-hyper" | "dpdk-client") => dpdk_run(&args),
        _ => panic!(
            "usage: bench_h2 server|kernel IP, or dpdk-h2|dpdk-hyper|dpdk-client EAL_ARGS -- LOCAL_IP SERVER_IP"
        ),
    }
}

#[cfg(not(dpdk))]
fn dpdk_run(_: &[String]) {
    panic!("DPDK mode requires libdpdk; use the devcontainer");
}

#[cfg(dpdk)]
fn dpdk_run(args: &[String]) {
    use httpio::dpdk::http::{h1, h2};
    use httpio::dpdk::mempool::{DEFAULT_MBUF_DATA_ROOM_SIZE, MAX_CACHE_SIZE, transmit_mbufs};
    use httpio::dpdk::tcp::{
        engine::{EngineConfig, TcpEngine},
        stream::{TcpOptions, TcpStream},
        worker::WorkerHandle,
    };
    use httpio::dpdk::tls::{self, TlsStream};
    use httpio::dpdk::{self, EthPort, Mempool};
    use httpio::http::codec::EncodedBody;
    use rustls::pki_types::ServerName;

    let split = args.iter().position(|s| s == "--").unwrap();
    let mut eal_args = vec!["bench_h2"];
    eal_args.extend(args[2..split].iter().map(String::as_str));
    dpdk::eal::init(&eal_args).unwrap();
    let local_ip = args[split + 1].parse().unwrap();
    let ip: Ipv4Addr = args[split + 2].parse().unwrap();
    let pool = Mempool::new("bench_h2", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
    let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).unwrap();
    let engine = TcpEngine::new(EngineConfig {
        local_ip,
        local_mac: port.mac_addr().unwrap(),
        gateway: None,
    });
    let tx_pool = Mempool::new(
        "bench_h2_tx",
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

    let config = tls_client_config();

    let ours = args[1] == "dpdk-h2";
    let label = args[1].as_str();
    println!("{HEADER}");
    runtime(false).block_on(async {
        // Below the range `Client` hands out, which `dpdk-client` uses.
        let local_port = Cell::new(20_000u16);
        let connect = async |port: u16| {
            local_port.set(local_port.get() + 1);
            let local = local_port.get();
            TcpStream::connect(&worker, ip, port, local, TcpOptions::default(), None)
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
            measure(
                label,
                proto,
                Workload::Reused,
                base,
                async |req: Request<Bytes>| {
                    let (parts, body) = req.into_parts();
                    let response = sender
                        .send(parts, EncodedBody::Full(body))
                        .unwrap()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    response.into_body().collect().await.unwrap()
                },
            )
            .await;
            drop(sender);
            driver.await.unwrap().unwrap();
            eprintln!(
                "{label} {proto}: driver polls {}",
                DRIVER_POLLS.with(Cell::take)
            );
        }
        // One request over a connection of its own with this crate's
        // HTTP/2 codec; like `hyper_h2_once`, it stops at the end of the
        // body.
        async fn ours_h2_once(tcp: TcpStream, req: Request<Bytes>) -> Bytes {
            let (sender, connection) = h2::handshake(tcp);
            let driver = tokio::spawn(timed(connection));
            let (parts, body) = req.into_parts();
            let response = sender
                .send(parts, EncodedBody::Full(body))
                .unwrap()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap();
            drop(sender);
            driver.abort();
            body
        }
        // And with its HTTP/1.1 codec.
        async fn ours_h1_once(tcp: TcpStream, req: Request<Bytes>) -> Bytes {
            let (parts, body) = origin_form(req).into_parts();
            let response = h1::send_over_tcp(tcp, parts, EncodedBody::Full(body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await.unwrap()
        }

        if label == "dpdk-client" {
            use httpio::dpdk::http::client::builder::Builder;
            use httpio::http::codec::{ByteStream, Raw};
            let client = Builder::new()
                .add_root_ca_pem(CA)
                .unwrap()
                .resolve("test.local", ip)
                .build(worker.clone());
            let base = format!("https://test.local:{TLS_PORT}");
            // Streamed uploads, on the connection the first one pools.
            for size in [16 * 1024, 1024 * 1024] {
                for _ in 0..3 {
                    let chunks: Vec<Bytes> = vec![0x5a; size]
                        .chunks(7_000)
                        .map(Bytes::copy_from_slice)
                        .collect();
                    let body = ByteStream::from(futures::stream::iter(chunks));
                    let req = request(&base, size, &Bytes::from_static(b"x")).map(|_| body);
                    let response = client.request::<_, Raw>(req).await.unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.version(), http::Version::HTTP_2);
                    assert_eq!(response.body().0.as_ref(), b"ok");
                }
            }
            assert_eq!(
                worker.connections_opened(),
                1,
                "streamed uploads must share the pooled connection"
            );
            eprintln!("dpdk-client: streamed uploads over the pooled HTTP/2 connection ok");
            measure(
                label,
                "tls",
                Workload::Reused,
                &base,
                async |req: Request<Bytes>| {
                    let response = client.request::<Raw, Raw>(req.map(Raw)).await.unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.version(), http::Version::HTTP_2);
                    response.into_body().0
                },
            )
            .await;
            assert_eq!(
                worker.connections_opened(),
                1,
                "every request must reuse one connection"
            );
            return;
        }
        if selected("BENCH_H2_WORKLOAD", "reused") {
            if selected("BENCH_H2_PROTO", "tls") {
                let base = format!("https://test.local:{TLS_PORT}");
                let stream = secure(connect(TLS_PORT).await).await;
                if ours {
                    ours_over(label, "tls", &base, stream).await;
                } else {
                    hyper_h2_reused(label, "tls", &base, stream).await;
                }
            }
            if selected("BENCH_H2_PROTO", "h2c") {
                let base = format!("http://{ip}:{H2C_PORT}");
                let stream = connect(H2C_PORT).await;
                if ours {
                    ours_over(label, "h2c", &base, stream).await;
                } else {
                    hyper_h2_reused(label, "h2c", &base, stream).await;
                }
            }
        }
        if selected("BENCH_H2_WORKLOAD", "fresh") {
            if selected("BENCH_H2_PROTO", "h1") {
                let base = format!("http://{ip}:{H1_PORT}");
                measure(label, "h1", Workload::Fresh, &base, async |req| {
                    let tcp = connect(H1_PORT).await;
                    if ours {
                        ours_h1_once(tcp, req).await
                    } else {
                        hyper_h1_once(tcp, req).await
                    }
                })
                .await;
            }
            if selected("BENCH_H2_PROTO", "h2c") {
                let base = format!("http://{ip}:{H2C_PORT}");
                measure(label, "h2c", Workload::Fresh, &base, async |req| {
                    let tcp = connect(H2C_PORT).await;
                    if ours {
                        ours_h2_once(tcp, req).await
                    } else {
                        hyper_h2_once(tcp, req).await
                    }
                })
                .await;
            }
        }
    });
    drop(worker);
    join.wait();
    dpdk::eal::cleanup();
}

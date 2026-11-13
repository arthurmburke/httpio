//! Fresh-connection HTTP/1.1 benchmark; see scripts/bench_h1.sh.
//! Modes: server <IP>, kernel <IP>, dpdk-h1|dpdk-hyper <EAL args> -- <LOCAL_IP> <SERVER_IP>.
//! BENCH_H1_ROUNDS overrides samples per case; BENCH_H1_WARMUP defaults to 20.
use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

const PORT: u16 = 7080;
const SIZES: [usize; 3] = [64, 16 * 1024, 1024 * 1024];

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |v| v.parse().expect("invalid benchmark setting"))
}

fn runtime(io: bool) -> tokio::runtime::Runtime {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder.enable_time();
    if io {
        builder.enable_io();
    }
    builder.build().unwrap()
}

async fn server(ip: Ipv4Addr) {
    let listener = tokio::net::TcpListener::bind((ip, PORT)).await.unwrap();
    let bodies: Vec<_> = SIZES
        .into_iter()
        .map(|n| Bytes::from(vec![0x5a; n]))
        .collect();
    eprintln!("HTTP benchmark server ready on {ip}:{PORT}");
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let bodies = bodies.clone();
        tokio::spawn(async move {
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
                        .header("connection", "close")
                        .body(Full::new(if upload {
                            Bytes::from_static(b"ok")
                        } else {
                            bodies[index].clone()
                        }))
                        .unwrap();
                    Ok::<_, Infallible>(response)
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .unwrap();
        });
    }
}

async fn hyper_request<S>(stream: S, mut request: Request<Bytes>) -> Response<Bytes>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Match the optimized client's origin-form request target.
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = sender.send_request(request.map(Full::new)).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    drop(sender);
    // Stop timing at body completion, without waiting for TCP teardown.
    driver.abort();
    Response::from_parts(parts, body)
}

async fn measure<F>(label: &str, ip: Ipv4Addr, mut request: F)
where
    F: AsyncFnMut(Request<Bytes>) -> Response<Bytes>,
{
    println!("backend\tmethod\tbytes\tsamples\tp50_us\tp99_us\tmean_us\treq_s\tpayload_mbit_s");
    for upload in [false, true] {
        for size in SIZES {
            let rounds = setting(
                "BENCH_H1_ROUNDS",
                if size == 1024 * 1024 { 30 } else { 300 },
            );
            assert!(rounds > 0);
            let warmup = setting("BENCH_H1_WARMUP", 20);
            let payload = if upload {
                Bytes::from(vec![0x5a; size])
            } else {
                Bytes::new()
            };
            let method = if upload { "POST" } else { "GET" };
            let mut samples = Vec::with_capacity(rounds);
            for i in 0..warmup + rounds {
                let req = Request::builder()
                    .method(method)
                    .uri(format!("http://{ip}:{PORT}/{size}"))
                    .header("host", format!("{ip}:{PORT}"))
                    .header("connection", "close")
                    .header("content-type", "application/octet-stream")
                    .body(payload.clone())
                    .unwrap();
                let start = Instant::now();
                let response = tokio::time::timeout(Duration::from_secs(15), request(req))
                    .await
                    .expect("request timed out");
                let elapsed = start.elapsed();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.version(), Version::HTTP_11);
                if upload {
                    assert_eq!(response.body().as_ref(), b"ok");
                } else {
                    assert_eq!(response.body().len(), size);
                    assert!(response.body().iter().all(|b| *b == 0x5a));
                }
                if i >= warmup {
                    samples.push(elapsed.as_secs_f64());
                }
            }
            samples.sort_unstable_by(f64::total_cmp);
            let total: f64 = samples.iter().sum();
            let at = |q: f64| samples[((rounds - 1) as f64 * q) as usize] * 1e6;
            println!(
                "{label}\t{method}\t{size}\t{rounds}\t{:.2}\t{:.2}\t{:.2}\t{:.2}\t{:.2}",
                at(0.5),
                at(0.99),
                total / rounds as f64 * 1e6,
                rounds as f64 / total,
                size as f64 * rounds as f64 * 8.0 / total / 1e6
            );
        }
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => runtime(true).block_on(server(args[2].parse().unwrap())),
        Some("kernel") => {
            let ip = args[2].parse().unwrap();
            runtime(true).block_on(measure("kernel-hyper", ip, async |req| {
                let socket = tokio::net::TcpStream::connect((ip, PORT)).await.unwrap();
                socket.set_nodelay(true).unwrap();
                hyper_request(socket, req).await
            }));
        }
        Some("dpdk-h1" | "dpdk-hyper") => dpdk_run(&args),
        _ => panic!(
            "usage: bench_h1 server|kernel IP, or dpdk-h1|dpdk-hyper EAL_ARGS -- LOCAL_IP SERVER_IP"
        ),
    }
}

#[cfg(not(dpdk))]
fn dpdk_run(_: &[String]) {
    panic!("DPDK mode requires libdpdk; use the devcontainer");
}

#[cfg(dpdk)]
fn dpdk_run(args: &[String]) {
    use httpio::dpdk::http::client::builder::Builder;
    use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
    use httpio::dpdk::tcp::{
        engine::{EngineConfig, TcpEngine},
        stream::{TcpOptions, TcpStream},
        worker::WorkerHandle,
    };
    use httpio::dpdk::{self, EthPort, Mempool};
    use httpio::http::codec::Raw;
    let split = args.iter().position(|s| s == "--").unwrap();
    let mut eal_args = vec!["bench_h1"];
    eal_args.extend(args[2..split].iter().map(String::as_str));
    dpdk::eal::init(&eal_args).unwrap();
    let local_ip = args[split + 1].parse().unwrap();
    let ip = args[split + 2].parse().unwrap();
    let pool = Mempool::create("bench_h1", 8192, 256, DEFAULT_MBUF_DATA_ROOM_SIZE, -1).unwrap();
    let port = EthPort::init(0, &pool, 1024, 1024, 1500, -1).unwrap();
    let engine = TcpEngine::new(EngineConfig {
        local_ip,
        local_mac: port.mac_addr().unwrap(),
        gateway: None,
    });
    let (worker, join) = WorkerHandle::spawn(
        engine,
        port,
        pool,
        dpdk::first_worker_lcore().expect("two lcores required"),
    )
    .unwrap();
    let config = httpio::dpdk::tcp::worker::SendConfig {
        capacity: setting(
            "BENCH_SEND_CAPACITY",
            httpio::dpdk::tcp::worker::SEND_CAPACITY,
        )
        .try_into()
        .unwrap(),
        initial_window_segments: u16::try_from(setting("BENCH_INITIAL_WINDOW", 10))
            .unwrap()
            .try_into()
            .unwrap(),
    };
    eprintln!(
        "send_capacity={} initial_window_segments={}",
        config.capacity, config.initial_window_segments
    );
    let worker = worker.with_send_config(config);
    runtime(false).block_on(async {
        if args[1] == "dpdk-h1" {
            let client = Builder::new().build(worker.clone());
            measure("dpdk-h1", ip, async |req| {
                client
                    .request::<Raw, Raw>(req.map(Raw))
                    .await
                    .unwrap()
                    .map(|raw| raw.0)
            })
            .await;
        } else {
            let mut local_port = 49152u16;
            measure("dpdk-hyper", ip, async |req| {
                let port = local_port;
                local_port = local_port
                    .checked_add(1)
                    .expect("too many benchmark connections");
                let stream =
                    TcpStream::connect(&worker, ip, PORT, port, TcpOptions::default(), None)
                        .await
                        .unwrap();
                hyper_request(stream, req).await
            })
            .await;
        }
        eprintln!("connections_opened={}", worker.connections_opened());
    });
    drop(worker);
    join.wait();
    dpdk::eal::cleanup();
}

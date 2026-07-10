//! Streaming-response example: GETs a URL with `R = ByteStream` and writes
//! body chunks to stdout *as they arrive* (nothing is buffered or collected).
//! Chunk sizes/count go to stderr so the streaming is observable.
//!
//! Usage (in the devcontainer):
//!   cargo run --example stream_get -- -l 0-1 --no-huge \
//!       --vdev=net_tap0,iface=dtap0 -- 10.9.0.1 http://10.9.0.2:8080/file
//!
//! Requires the DPDK stack (the `dpdk` cfg, set by build.rs when libdpdk is
//! present); without it this example is a stub that just reports as much.

#[cfg(not(dpdk))]
fn main() {
    eprintln!(
        "`stream_get` requires the DPDK stack, but libdpdk was not found at build time; \
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
    use std::io::Write;
    use std::process::ExitCode;
    use std::time::Duration;

    use futures::StreamExt;
    use http::{Method, Request};

    use httpio::dpdk::http::client::builder::Builder;
    use httpio::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE;
    use httpio::dpdk::tcp::engine::{EngineConfig, TcpEngine};
    use httpio::dpdk::tcp::worker::WorkerHandle;
    use httpio::dpdk::{self, EthPort, Mempool};
    use httpio::http::codec::{ByteStream, Empty};

    const TIMEOUT: Duration = Duration::from_secs(30);

    pub fn main() -> ExitCode {
        let args: Vec<String> = env::args().collect();
        let split = args.iter().position(|a| a == "--");
        let (eal_args, app_args): (&[String], &[String]) = match split {
            Some(idx) => (&args[..idx], &args[idx + 1..]),
            None => (&args[..], &[]),
        };
        let [local_ip, url] = app_args else {
            eprintln!("usage: stream_get <EAL args> -- <LOCAL_IP> <URL>");
            return ExitCode::FAILURE;
        };
        let local_ip = local_ip
            .parse::<std::net::Ipv4Addr>()
            .expect("invalid local IP")
            .octets();

        let eal_args: Vec<&str> = eal_args.iter().map(String::as_str).collect();
        dpdk::eal::init(&eal_args).expect("EAL initialization failed");
        let worker_lcore = dpdk::first_worker_lcore().expect("need two lcores, e.g. -l 0-1");
        let socket_id = dpdk::lcore::get_core_info(worker_lcore).socket;

        let pool = Mempool::create(
            "stream_mbuf_pool",
            8192,
            256,
            DEFAULT_MBUF_DATA_ROOM_SIZE,
            socket_id as i32,
        )
        .expect("failed to create mbuf pool");
        assert!(EthPort::count_avail() > 0, "no DPDK ports available");
        let port =
            EthPort::init(0, &pool, 1024, 1024, 1500, socket_id as i32).expect("port init failed");
        let mac = port.mac_addr().expect("failed to read MAC address");

        let engine = TcpEngine::new(EngineConfig {
            local_mac: mac.addr_bytes,
            local_ip,
        });
        let (worker, worker_join) =
            WorkerHandle::spawn(engine, port, pool, worker_lcore).expect("worker spawn failed");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build tokio runtime");
        let result = runtime.block_on(async {
            match tokio::time::timeout(TIMEOUT, run(url, worker)).await {
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

    async fn run(url: &str, worker: WorkerHandle) -> ExitCode {
        let client = Builder::new().build(worker);
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Empty)
            .expect("bad URL");

        // R = ByteStream: the response resolves at the headers; the body
        // is consumed below, chunk by chunk, without ever being collected.
        let response = match client.request::<Empty, ByteStream>(request).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("{:?} {}", response.version(), response.status());

        let mut chunks = response.into_body().into_inner();
        let mut stdout = std::io::stdout();
        let (mut count, mut total) = (0u64, 0u64);
        while let Some(chunk) = chunks.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                // The error channel: a mid-body transport failure arrives
                // here (truncation is not a silent EOF).
                Err(e) => {
                    eprintln!("error: body stream failed after {total} bytes: {e}");
                    return ExitCode::FAILURE;
                }
            };
            count += 1;
            total += chunk.len() as u64;
            stdout.write_all(&chunk).expect("failed to write chunk");
        }
        eprintln!("streamed {total} bytes in {count} chunks");
        ExitCode::SUCCESS
    }
}

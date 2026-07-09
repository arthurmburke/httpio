//! An HTTP/1.1 + HTTP/2 client (hyper + rustls) that uses the DPDK TCP
//! stack as its transport instead of the kernel's sockets.
//!
//! Integration model: the TCP engine runs on a dedicated worker lcore
//! (see `crate::tcp::worker`). The async transport adapter (`TcpStream`)
//! never touches the engine directly -- it exchanges data with the worker
//! over per-connection lock-free SPSC rings. Reads/writes busy-poll (self
//! -wake + `Pending`) while the worker lcore likewise spins, which is
//! DPDK's run-to-completion model. Run the client under a `current_thread`
//! tokio runtime.
//!
//! Name resolution: this stack has no UDP, hence no DNS. URLs must either
//! use IP-literal hosts or be mapped explicitly with
//! `HttpClientBuilder::resolve(host, ip)` (curl `--resolve` style); the
//! hostname is still used for SNI and certificate validation.

pub mod client;
pub mod stream;
pub mod websocket;

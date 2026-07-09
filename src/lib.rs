//! A userspace TCP/IP stack over raw DPDK FFI bindings, plus an HTTP/1.1
//! + HTTP/2 client (hyper + rustls) that uses it as its transport.
//! See README.md.

pub mod core;
/// The userspace DPDK TCP/IP stack and the HTTP/WebSocket client built on
/// it. Gated on the `dpdk` cfg, which `build.rs` sets when libdpdk is found
/// on the compiling system; without it the crate is just [`core`] and the
/// transport-agnostic [`http`] traits.
#[cfg(dpdk)]
pub mod dpdk;
pub mod http;

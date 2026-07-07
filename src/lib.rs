//! A userspace TCP/IP stack over raw DPDK FFI bindings, plus an HTTP/1.1
//! + HTTP/2 client (hyper + rustls) that uses it as its transport.
//! See README.md.

pub mod core;
pub mod dpdk;
pub mod http;
pub mod net;
pub mod tcp;
pub mod tokio;

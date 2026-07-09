//! Raw DPDK FFI + safe wrappers. See `ffi.rs` for the ABI notes on why some
//! functions are declared directly and others go through `csrc/shim.c`.

pub mod eal;
pub mod ffi;
pub mod http;
pub mod lcore;
pub mod mbuf;
pub mod mempool;
pub mod net;
pub mod port;
pub mod tcp;
pub mod tokio;

pub use lcore::{WorkerJoin, first_worker_lcore, launch};
pub use mbuf::Mbuf;
pub use mempool::Mempool;
pub use port::EthPort;

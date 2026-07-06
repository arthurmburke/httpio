//! Raw DPDK FFI + safe wrappers. See `ffi.rs` for the ABI notes on why some
//! functions are declared directly and others go through `csrc/shim.c`.

pub mod eal;
pub mod ffi;
pub mod lcore;
pub mod mbuf;
pub mod mempool;
pub mod port;

pub use lcore::{WorkerJoin, first_worker_lcore, launch};
pub use mbuf::Mbuf;
pub use mempool::PktMbufPool;
pub use port::EthPort;

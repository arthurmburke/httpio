//! Raw DPDK FFI + safe wrappers. See `ffi.rs` for the ABI notes on why some
//! functions are declared directly and others go through `csrc/shim.c`.

pub mod dma;
pub use dma::{DmaBuffer, DmaWriter};
pub mod eal;
pub mod ffi;
pub mod http;
pub mod lcore;
pub mod mbuf;
pub mod mempool;
#[cfg(feature = "tcp-metrics")]
mod metrics;
pub mod net;
pub mod port;
#[cfg(feature = "tx-probe")]
pub mod probe;
pub mod steering;
pub mod tcp;
#[cfg(test)]
pub(crate) mod testing;
pub mod tls;
pub mod tokio;
pub mod udp;

pub use lcore::{WorkerJoin, first_worker_lcore, launch};
pub use mbuf::{Mbuf, MbufSlice};
pub use mempool::Mempool;
pub use port::EthPort;

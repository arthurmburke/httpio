//! UDP over the DPDK stack.
//!
//! There is no separate UDP worker. Each worker lcore owns one NIC queue
//! exclusively, and with it the queue's receive burst, its ARP table and
//! its transmit batch, all of which live in that worker's
//! [`TcpEngine`](crate::dpdk::tcp::engine::TcpEngine). A second loop on
//! the same queue would have to share them. So UDP is a layer of the same
//! engine instead: [`UdpEngine`] is a field of `TcpEngine`, reached with
//! [`TcpEngine::udp`](crate::dpdk::tcp::engine::TcpEngine::udp) and
//! [`udp_mut`](crate::dpdk::tcp::engine::TcpEngine::udp_mut). The engine's
//! receive loop hands it every IPv4 datagram of protocol 17, and its poll
//! lets it transmit through the same next-hop routing, ARP resolver, pool
//! and transmit batch as TCP, with the same stall handling. The TCP
//! per-packet path pays one protocol branch for this, and an idle UDP
//! layer costs a poll a few loads and two emptiness checks.
//!
//! [`UdpEngine`] is synchronous and engine-owned, like
//! [`TcpSocket`](crate::dpdk::tcp::socket::TcpSocket) is for TCP:
//! whatever runs the engine's loop calls it directly.

//!
//! Applications use [`UdpSocket`] instead, through a
//! [`WorkerHandle`](crate::dpdk::tcp::worker::WorkerHandle): the worker
//! loop runs the engine's sockets for it (see [`worker`] and [`socket`]).

pub mod engine;
pub mod socket;
pub(crate) mod worker;

pub use engine::{Datagram, UdpEngine, UdpEngineCounters, UdpError, UdpStats, UdpStatsSnapshot};
pub use socket::{UdpReceiver, UdpSender, UdpSocket};

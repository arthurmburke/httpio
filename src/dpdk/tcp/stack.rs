//! Brings up the whole TCP stack on a port in one call: its queues, their
//! mbuf pools, the NIC's steering, one engine and worker lcore per queue,
//! and the single [`WorkerHandle`] the application uses for all of them.
//!
//! ```ignore
//! let (worker, join) = Stack::builder(0, "10.0.1.25".parse()?)
//!     .gateway(Gateway { ip: "10.0.1.1".parse()?, prefix_len: 24 })
//!     .lcores(&[1, 2, 3, 4])
//!     .build()?;
//! let client = Builder::new().build(worker);
//! ```
//!
//! The application never learns how many workers there are or which one
//! serves a connection. [`WorkerHandle::spawn`] remains for a caller that
//! wants to build a single worker from its own engine, port and pool.

use std::net::Ipv4Addr;

use super::engine::{EngineConfig, Gateway, TcpEngine};
use super::worker::WorkerHandle;
use crate::dpdk::lcore::LaunchError;
use crate::dpdk::mempool::{DEFAULT_MBUF_DATA_ROOM_SIZE, MempoolCreateError};
use crate::dpdk::port::{PortError, QueueSteering};
use crate::dpdk::{EthPort, Mempool, WorkerJoin};

/// Why [`StackBuilder::build`] failed. Nothing is left running.
#[derive(Debug)]
pub enum StackError {
    /// No lcore was given to run a worker on.
    NoLcores,
    Pool(MempoolCreateError),
    /// The device could not be configured as asked: too few queues, or
    /// (with more than one worker) no support for the flow rules that
    /// steer each connection to its worker.
    Port(PortError),
    Launch(LaunchError),
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLcores => write!(f, "no lcores to run TCP workers on"),
            Self::Pool(error) => error.fmt(f),
            Self::Port(error) => error.fmt(f),
            Self::Launch(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StackError {}

/// Namespace for [`Stack::builder`].
pub struct Stack;

impl Stack {
    /// A stack on DPDK port `port_id` with local address `local_ip`,
    /// running one worker until [`StackBuilder::lcores`] says otherwise.
    pub fn builder(port_id: u16, local_ip: Ipv4Addr) -> StackBuilder {
        StackBuilder {
            port_id,
            local_ip,
            gateway: None,
            lcores: Vec::new(),
            mtu: 1500,
            rx_descriptors: 1024,
            tx_descriptors: 1024,
            pool_mbufs: 16383,
            steering: QueueSteering::FlowRules,
            configure: None,
        }
    }
}

pub struct StackBuilder {
    port_id: u16,
    local_ip: Ipv4Addr,
    gateway: Option<Gateway>,
    lcores: Vec<u32>,
    mtu: u32,
    rx_descriptors: u16,
    tx_descriptors: u16,
    pool_mbufs: u32,
    steering: QueueSteering,
    configure: Option<Configure>,
}

/// Applied to each worker's engine before it starts.
type Configure = Box<dyn FnMut(&mut TcpEngine)>;

impl StackBuilder {
    /// The worker lcores: one worker, with its own receive queue, engine
    /// and mbuf pool, on each. Choose lcores on the device's NUMA socket
    /// ([`EthPort::socket`]); the pools are allocated there. Without this
    /// call the stack runs one worker on the first worker lcore.
    pub fn lcores(mut self, lcores: &[u32]) -> Self {
        self.lcores = lcores.to_vec();
        self
    }

    /// Default route; see [`EngineConfig::gateway`].
    pub fn gateway(mut self, gateway: Gateway) -> Self {
        self.gateway = Some(gateway);
        self
    }

    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// RX and TX descriptors per queue.
    pub fn descriptors(mut self, rx: u16, tx: u16) -> Self {
        self.rx_descriptors = rx;
        self.tx_descriptors = tx;
        self
    }

    /// Mbufs in each worker's pool. A worker's pool holds what it has
    /// received and not yet handed over or freed, and what it is sending.
    pub fn pool_mbufs(mut self, mbufs: u32) -> Self {
        self.pool_mbufs = mbufs;
        self
    }

    /// How the device is made to deliver each connection to its worker
    /// when there are several. The default programs it with flow rules.
    pub fn steering(mut self, steering: QueueSteering) -> Self {
        self.steering = steering;
        self
    }

    /// Runs on every worker's engine before it starts: to listen, or to
    /// change budgets and windows.
    pub fn configure(mut self, configure: impl FnMut(&mut TcpEngine) + 'static) -> Self {
        self.configure = Some(Box::new(configure));
        self
    }

    /// Starts the port and the workers. The handle is all the application
    /// needs; dropping its last clone stops the workers, and the join
    /// handle then waits for them.
    pub fn build(mut self) -> Result<(WorkerHandle, StackJoin), StackError> {
        if self.lcores.is_empty() {
            self.lcores.extend(crate::dpdk::first_worker_lcore());
        }
        if self.lcores.is_empty() {
            return Err(StackError::NoLcores);
        }
        let socket = EthPort::socket(self.port_id);
        let pools = (0..self.lcores.len())
            .map(|queue| {
                Mempool::create(
                    &format!("tcp-p{}-q{queue}", self.port_id),
                    self.pool_mbufs,
                    256,
                    DEFAULT_MBUF_DATA_ROOM_SIZE,
                    socket,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(StackError::Pool)?;
        let queues = EthPort::init_queues(
            self.port_id,
            &pools.iter().collect::<Vec<_>>(),
            self.rx_descriptors,
            self.tx_descriptors,
            self.mtu,
            socket,
            self.steering,
        )
        .map_err(StackError::Port)?;
        let config = EngineConfig {
            local_mac: queues[0].mac_addr().map_err(StackError::Port)?,
            local_ip: self.local_ip,
            gateway: self.gateway,
        };
        let workers = queues
            .into_iter()
            .zip(pools)
            .zip(&self.lcores)
            .map(|((queue, pool), &lcore)| {
                let mut engine = TcpEngine::new(config);
                if let Some(configure) = &mut self.configure {
                    configure(&mut engine);
                }
                (engine, queue, pool, lcore)
            })
            .collect();
        let (handle, joins) = WorkerHandle::spawn_all(workers).map_err(StackError::Launch)?;
        Ok((handle, StackJoin(joins)))
    }
}

/// Waits for every worker of a [`Stack`]; see [`StackJoin::wait`].
pub struct StackJoin(Vec<WorkerJoin>);

impl StackJoin {
    /// Blocks until every worker has returned, which they do once the last
    /// clone of the [`WorkerHandle`] is dropped. Main lcore only.
    pub fn wait(self) {
        for join in self.0 {
            join.wait();
        }
    }
}

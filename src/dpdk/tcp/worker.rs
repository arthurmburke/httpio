//! Runs the `TcpEngine` on a dedicated DPDK worker lcore and exposes it
//! to application (tokio) threads over lock-free SPSC rings.
//!
//! Threading model:
//!  - The **worker lcore** owns the `TcpEngine`, `EthPort`, and mbuf
//!    `PktMbufPool` outright. It busy-polls in a run-to-completion loop:
//!    service notified command rings, pump the engine (rx burst -> state
//!    machines/timers -> tx burst), then deliver data for changed connections.
//!    Application writes, reads and drops publish coalesced notifications
//!    through a bounded MPSC queue. Only queue overflow falls back to a scan.
//!    No locks.
//!  - The **application thread** (the tokio `current_thread` runtime
//!    driving the HTTP client) never touches the engine. It talks to the
//!    worker only through rings: one process-wide *control* ring to open
//!    connections, then a dedicated command/inbound ring pair per
//!    connection.
//!
//! Why a ring pair per connection: the rings in `core::ring` are SPSC.
//! Each `TcpStream` is the sole producer of its command ring and the sole
//! consumer of its inbound ring, so the single-producer/single-consumer
//! invariant holds without any shared/locked sender. The `Tx`/`Rx`
//! endpoints are `Send`, so a fresh pair is created on the app thread and
//! one half of each is shipped to the worker inside the control message.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;

use crate::core::hashmap::HashMap;
use crate::core::hashset::HashSet;
use crate::core::mpsc;
use crate::core::mpsc::{MpscRx, MpscTx};
use crate::core::spsc;
use crate::core::spsc::{SpscRx, SpscTx};
use crate::dpdk::{self, EthPort, Mempool, WorkerJoin};

use super::app_wake::{self, AppNotifier, AppReady, AppWake};
use super::engine::TcpEngine;
use super::state::TcpState;
use super::tcb::{Event, FourTuple};

/// Control ring depth (concurrent connection opens in flight).
const CTRL_CAP: usize = 256;
/// Per-connection command ring depth (queued writes/control ops).
const CMD_CAP: usize = 1024;
/// Per-connection inbound ring depth (queued received chunks + events).
const IN_CAP: usize = 1024;
/// Bytes pulled from the engine per connection per iteration.
const RECV_CHUNK: usize = 64 * 1024;
/// How long to wait for a peer FIN before reaping a connection whose app-side handle is gone.
const REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// Per-connection rings stay SPSC: exactly one thread owns each end (the
// thread driving that connection's `TcpStream`, and the worker lcore).
/// Default limit on queued plus unacknowledged application bytes per connection.
pub const SEND_CAPACITY: usize = 256 * 1024;

/// Send-side limits for connections opened through a worker handle.
/// Credit bounds queued plus unacknowledged bytes; it does not preallocate
/// payload memory or override congestion control or the peer's receive window.
#[derive(Debug, Clone, Copy)]
pub struct SendConfig {
    /// Logical byte credit per connection, allocated only as data is queued.
    pub capacity: std::num::NonZeroUsize,
    /// Initial congestion window in segments. The default is ten; larger
    /// values are an explicit opt-in for provisioned, controlled networks.
    /// Loss recovery still reduces the window, including to one MSS on RTO.
    pub initial_window_segments: std::num::NonZeroU16,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            capacity: std::num::NonZeroUsize::new(SEND_CAPACITY).unwrap(),
            initial_window_segments: std::num::NonZeroU16::new(10).unwrap(),
        }
    }
}

const READY_CAP: usize = 4096;
#[derive(Clone)]
struct ReadySender {
    tx: MpscTx<FourTuple, READY_CAP>,
    overflow: Arc<AtomicBool>,
}
struct Wake {
    tuple: FourTuple,
    sender: ReadySender,
    queued: AtomicBool,
}

pub(crate) struct SendCredit {
    wake: Option<Wake>,
    capacity: usize,
    app_gone: AtomicBool,
    pub(crate) bytes: AtomicUsize,
    pub(crate) failed: AtomicBool,
}

impl SendCredit {
    fn notify(&self) {
        if let Some(wake) = &self.wake {
            if !wake.queued.swap(true, Ordering::AcqRel) && wake.sender.tx.push(wake.tuple).is_err()
            {
                // A saturated notification queue must never lose a wakeup.
                wake.sender.overflow.store(true, Ordering::Release);
            }
        }
    }
    fn clear_notification(&self) {
        if let Some(wake) = &self.wake {
            wake.queued.store(false, Ordering::Release);
        }
    }
}

pub struct CmdTx {
    ring: SpscTx<Command, CMD_CAP>,
    outstanding: Arc<SendCredit>,
}

impl CmdTx {
    pub fn failed(&self) -> bool {
        self.outstanding.failed.load(Ordering::Acquire)
    }
    pub fn available_bytes(&self) -> usize {
        self.outstanding
            .capacity
            .saturating_sub(self.outstanding.bytes.load(Ordering::Acquire))
    }
    pub fn len(&self) -> usize {
        self.ring.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }
    pub fn is_closed(&self) -> bool {
        self.ring.is_closed()
    }

    /// Send commands also reserve byte credit, released only after ACK or discard.
    pub fn push(&self, cmd: Command) -> Result<(), Command> {
        let bytes = match &cmd {
            Command::Send(b) => b.len(),
            _ => 0,
        };
        if self.is_closed() || self.failed() || bytes > self.available_bytes() {
            return Err(cmd);
        }
        if bytes != 0 {
            self.outstanding.bytes.fetch_add(bytes, Ordering::AcqRel);
        }
        match self.ring.push(cmd) {
            Ok(()) => {
                self.outstanding.notify();
                Ok(())
            }
            Err(cmd) => {
                if bytes != 0 {
                    self.outstanding.bytes.fetch_sub(bytes, Ordering::AcqRel);
                }
                Err(cmd)
            }
        }
    }
}

impl Drop for CmdTx {
    fn drop(&mut self) {
        self.outstanding.app_gone.store(true, Ordering::Release);
        self.outstanding.notify();
    }
}

#[cfg(test)]
pub(crate) fn command_channel() -> (CmdTx, CmdRx, Arc<SendCredit>) {
    command_channel_with_wake(None, SEND_CAPACITY)
}

fn command_channel_with_wake(
    wake: Option<Wake>,
    capacity: usize,
) -> (CmdTx, CmdRx, Arc<SendCredit>) {
    let (ring, rx) = spsc::channel();
    let outstanding = Arc::new(SendCredit {
        wake,
        capacity,
        app_gone: AtomicBool::new(false),
        bytes: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
    });
    (
        CmdTx {
            ring,
            outstanding: outstanding.clone(),
        },
        rx,
        outstanding,
    )
}
pub type CmdRx = SpscRx<Command, CMD_CAP>;
pub type InboundTx = SpscTx<Inbound, IN_CAP>;
pub struct InboundRx {
    ring: SpscRx<Inbound, IN_CAP>,
    signal: Arc<SendCredit>,
}
impl InboundRx {
    pub fn pop(&self) -> Option<Inbound> {
        let value = self.ring.pop();
        if value.is_some() {
            self.signal.notify();
        }
        value
    }
    pub fn is_closed(&self) -> bool {
        self.ring.is_closed()
    }
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
    pub fn len(&self) -> usize {
        self.ring.len()
    }
    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }
}
pub(crate) fn inbound_channel(signal: Arc<SendCredit>) -> (InboundTx, InboundRx) {
    let (tx, ring) = spsc::channel();
    (tx, InboundRx { ring, signal })
}
// The connection-open control ring is MPSC: any number of application
// threads can share one `WorkerHandle` and open connections concurrently
// (multiple producers), while the worker lcore is the sole consumer.
type CtrlTx = MpscTx<NewConn, CTRL_CAP>;
type CtrlRx = MpscRx<NewConn, CTRL_CAP>;

/// App -> worker, per connection.
pub enum Command {
    /// Application data to send (already framed by the HTTP/TLS layers).
    Send(Bytes),
    /// Enable/disable TCP_CORK-style hold. Issued *after* the TLS
    /// handshake (corking earlier would hold the sub-MSS ClientHello and
    /// stall the handshake). Ordered on the same ring as `Send`/`Flush`.
    SetCork(bool),
    /// Release a corked connection's held tail segment now.
    Flush,
    /// Half-close: send a FIN. The connection keeps delivering inbound
    /// data until the peer also closes.
    Close,
}

/// Worker -> app, per connection.
pub enum Inbound {
    /// Handshake complete; the connection is usable.
    Established,
    /// Handshake failed (RST or timeout before ESTABLISHED).
    ConnectFailed,
    /// Received application bytes, in order.
    Data(Bytes),
    /// Peer finished sending (FIN); no more `Data` will follow.
    Eof,
    /// Connection was reset.
    Reset,
    /// The active open was refused locally because its 4-tuple is already
    /// in use (a live or TIME_WAIT connection). Terminal; the caller should
    /// retry with a different local port. The existing connection is
    /// unaffected.
    AddrInUse,
}

/// The control message that registers a new connection with the worker,
/// carrying the worker-side halves of its ring pair.
struct NewConn {
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_port: u16,
    nodelay: bool,
    initial_window_segments: u16,
    cmd_rx: CmdRx,
    outstanding: Arc<SendCredit>,
    inbound_tx: InboundTx,
    app_wake: Arc<AppWake>,
}

/// What the worker still owes the application on a connection's inbound
/// ring. Advances only forward:
///
/// ```text
/// Connecting --Established--> Established --PeerClosed--> Draining
///     |                           |                           |
///     | Reset / Closed            | Reset                     | data drained (Eof) / Reset
///     v                           v                           v
///  Terminal(ConnectFailed)     Terminal(Reset)          Terminal(Eof | Reset)
///                                   \________________________/
///                                               | ring accepts it
///                                               v
///                                             Ended
/// ```
enum Delivery {
    /// The handshake has not completed.
    Connecting,
    /// `Inbound::Established` is on the ring; data flows.
    Established,
    /// The peer sent FIN; `Eof` follows once buffered data has drained.
    Draining,
    /// The one terminal signal (`Eof`/`ConnectFailed`/`Reset`), held until
    /// buffered data has drained and the ring accepts it, so it can never
    /// be lost to a transiently full ring.
    Terminal(Inbound),
    /// The terminal signal has been delivered; nothing more is produced.
    Ended,
}

/// The application side's teardown of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Teardown {
    /// The application holds the connection and has not closed it.
    Open,
    /// The engine has been asked to close (half-close); not repeated.
    Closing,
    /// The application's handle is gone. The engine has been asked to
    /// close, and the connection is aborted at `deadline` if the peer has
    /// not finished by then.
    Orphaned { deadline: Instant },
}

/// Worker-side per-connection state.
struct WorkerConn {
    engine_bytes: usize,
    tuple: FourTuple,
    cmd_rx: CmdRx,
    outstanding: Arc<SendCredit>,
    inbound_tx: InboundTx,
    /// A received chunk the inbound ring was too full to accept; retried
    /// before pulling more from the engine so no bytes are dropped.
    pending_in: Option<Bytes>,
    delivery: Delivery,
    teardown: Teardown,
    /// How the application is told this connection changed; absent only
    /// in tests that drive a connection without a stream.
    app_wake: Option<Arc<AppWake>>,
    /// Something the application may be waiting for changed during this
    /// iteration (inbound message, ring space, send credit, failure). The
    /// loop turns it into one notification at the end of the iteration,
    /// after the change is visible.
    notify_app: bool,
}

impl WorkerConn {
    fn new(
        tuple: FourTuple,
        cmd_rx: CmdRx,
        outstanding: Arc<SendCredit>,
        inbound_tx: InboundTx,
    ) -> Self {
        Self {
            engine_bytes: 0,
            tuple,
            cmd_rx,
            outstanding,
            inbound_tx,
            pending_in: None,
            delivery: Delivery::Connecting,
            teardown: Teardown::Open,
            app_wake: None,
            notify_app: false,
        }
    }

    /// Pushes to the application's inbound ring, noting on success that
    /// the application has something to be woken for.
    fn push_inbound(&mut self, msg: Inbound) -> Result<(), Inbound> {
        let pushed = self.inbound_tx.push(msg);
        self.notify_app |= pushed.is_ok();
        pushed
    }

    /// `Command::Close`: half-close the engine side, once.
    fn close(&mut self, engine: &mut TcpEngine) {
        engine.close(self.tuple);
        if self.teardown == Teardown::Open {
            self.teardown = Teardown::Closing;
        }
    }

    /// Whether the application's handle is gone and the connection is
    /// waiting out its reap deadline.
    fn is_orphaned(&self) -> bool {
        matches!(self.teardown, Teardown::Orphaned { .. })
    }

    /// Moves the terminal signal toward the application: a drained peer
    /// FIN becomes `Eof`, and a held terminal is pushed once no data is
    /// stalled ahead of it.
    fn deliver_terminal(&mut self, engine: &TcpEngine) {
        if self.pending_in.is_some() {
            return;
        }
        if matches!(self.delivery, Delivery::Draining) && engine.readable_len(self.tuple) == 0 {
            self.delivery = Delivery::Terminal(Inbound::Eof);
        }
        self.delivery = match std::mem::replace(&mut self.delivery, Delivery::Ended) {
            Delivery::Terminal(terminal) => match self.push_inbound(terminal) {
                Ok(()) => Delivery::Ended,
                Err(returned) => Delivery::Terminal(returned),
            },
            other => other,
        };
    }

    fn release_credit(&mut self, engine: &TcpEngine) {
        let remaining = engine.buffered_send_bytes(self.tuple);
        let released = self.engine_bytes - remaining;
        if released != 0 {
            self.outstanding.bytes.fetch_sub(released, Ordering::AcqRel);
            self.notify_app = true;
        }
        self.engine_bytes = remaining;
    }

    fn retain_after_drop(&mut self, engine: &mut TcpEngine, now: Instant) -> bool {
        if !self.outstanding.app_gone.load(Ordering::Acquire) {
            return true;
        }
        let deadline = match self.teardown {
            Teardown::Orphaned { deadline } => deadline,
            Teardown::Open | Teardown::Closing => {
                if self.teardown == Teardown::Open {
                    engine.close(self.tuple);
                }
                let deadline = now + REAP_TIMEOUT;
                self.teardown = Teardown::Orphaned { deadline };
                deadline
            }
        };
        if matches!(
            engine.state(self.tuple),
            None | Some(TcpState::Closed | TcpState::TimeWait)
        ) {
            return false;
        }
        if now >= deadline {
            engine.abort(self.tuple);
            return false;
        }
        true
    }

    fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Established => {
                // The ring is empty before the handshake completes, so
                // this push cannot fail in practice.
                if matches!(self.delivery, Delivery::Connecting)
                    && self.push_inbound(Inbound::Established).is_ok()
                {
                    self.delivery = Delivery::Established;
                }
            }
            Event::PeerClosed => {
                if matches!(self.delivery, Delivery::Connecting | Delivery::Established) {
                    self.delivery = Delivery::Draining;
                }
            }
            Event::Reset => {
                self.outstanding.failed.store(true, Ordering::Release);
                self.notify_app = true;
                // Distinguish a failed handshake from a reset of an
                // established connection so the app reports the right
                // error. A terminal already chosen stands.
                match self.delivery {
                    Delivery::Connecting => {
                        self.delivery = Delivery::Terminal(Inbound::ConnectFailed);
                    }
                    Delivery::Established | Delivery::Draining => {
                        self.delivery = Delivery::Terminal(Inbound::Reset);
                    }
                    Delivery::Terminal(_) | Delivery::Ended => {}
                }
            }
            Event::Closed => {
                // A close before ESTABLISHED is a failed active open;
                // an established-then-closed connection is delivered as
                // EOF via the `Draining` path.
                if matches!(self.delivery, Delivery::Connecting) {
                    self.outstanding.failed.store(true, Ordering::Release);
                    self.notify_app = true;
                    self.delivery = Delivery::Terminal(Inbound::ConnectFailed);
                }
            }
        }
    }
}

/// Application-side handle to the worker, used to open connections; each
/// open produces a fresh ring pair whose app-side halves become a
/// `TcpStream`.
///
/// `Send + Sync`: the connection-open path goes through an MPSC control
/// ring, so a single handle (e.g. behind an `Arc`) can be shared by any
/// number of application threads all opening connections concurrently.
#[derive(Clone)]
pub struct WorkerHandle {
    #[cfg(feature = "tcp-metrics")]
    metrics: super::metrics::Report,
    send_config: SendConfig,
    ctrl_tx: CtrlTx,
    ready: ReadySender,
    /// Worker -> application wake-ups for this worker's streams.
    app_ready: Arc<AppReady>,
    /// Whether streams copy writes into DMA memory, for the engine to
    /// attach to packets instead of copying again. On for ports with TSO,
    /// where one attachment replaces copying a segment of tens of
    /// kilobytes into a chain of mbufs (measured: about 160 ns against
    /// 440 ns for 32 KB). Off otherwise: for a single MSS-sized segment
    /// the attachment's extra mbufs cost slightly more than the copy.
    dma_writes: bool,
    local_ip: Ipv4Addr,
    /// Shared only by application-side handles. Dropping the final clone drops
    /// `WorkerLifetime`, which signals the worker without a racy strong-count
    /// check. The worker itself deliberately does not own this token.
    _lifetime: Arc<WorkerLifetime>,
    /// Published by the worker each iteration: total active opens so far.
    /// A cross-core observability counter (e.g. to confirm h2 connection
    /// reuse), not a live count.
    connections_opened: Arc<AtomicU64>,
}

struct WorkerLifetime {
    stop: Arc<AtomicBool>,
}

impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// The app-side endpoints of one connection's ring pair, returned by
/// [`WorkerHandle::open`].
pub struct ConnEndpoints {
    pub cmd_tx: CmdTx,
    pub inbound_rx: InboundRx,
    /// Where the stream stores its waker while it has nothing to do.
    pub(crate) wake: Arc<AppWake>,
    /// Whether writes should be copied into DMA memory (see
    /// [`DmaWriter`](crate::dpdk::DmaWriter)): worthwhile when the port
    /// segments large packets itself.
    pub(crate) dma_writes: bool,
}

impl WorkerHandle {
    #[cfg(feature = "tcp-metrics")]
    pub fn metrics_report(&self) -> super::metrics::Report {
        self.metrics.clone()
    }

    /// Configures future connections opened through this handle. Existing
    /// connections and previously cloned handles retain their settings.
    pub fn with_send_config(mut self, config: SendConfig) -> Self {
        self.send_config = config;
        self
    }

    /// Launches the engine loop on `worker_lcore` and returns the app-side
    /// handle plus the lcore join handle. The engine/port/pool are moved to
    /// the worker lcore and owned there for the loop's lifetime.
    pub fn spawn(
        engine: TcpEngine,
        port: EthPort,
        pool: Mempool,
        worker_lcore: u32,
    ) -> Result<(Self, WorkerJoin), dpdk::lcore::LaunchError> {
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<NewConn, CTRL_CAP>();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let connections_opened = Arc::new(AtomicU64::new(0));
        let worker_opened = connections_opened.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let overflow = Arc::new(AtomicBool::new(false));
        let ready = ReadySender {
            tx: ready_tx,
            overflow: overflow.clone(),
        };
        let local_ip = engine.local_ip();
        let dma_writes = port.offloads().tso_max_payload > 0;
        let (notifier, app_ready) = app_wake::channel();

        #[cfg(feature = "tcp-metrics")]
        let metrics = super::metrics::Report::default();
        #[cfg(feature = "tcp-metrics")]
        let worker_metrics = metrics.clone();
        let join = dpdk::launch(worker_lcore, move || {
            #[cfg(feature = "tcp-metrics")]
            super::metrics::reset();
            #[cfg(feature = "tcp-metrics")]
            let started = Instant::now();
            run(
                engine,
                port,
                pool,
                ctrl_rx,
                worker_stop,
                worker_opened,
                ready_rx,
                overflow,
                notifier,
            );
            #[cfg(feature = "tcp-metrics")]
            {
                super::metrics::record(|m| m.worker_ns = started.elapsed().as_nanos() as u64);
                let _ = worker_metrics.0.set(super::metrics::snapshot());
            }
        })?;

        Ok((
            WorkerHandle {
                #[cfg(feature = "tcp-metrics")]
                metrics,
                send_config: SendConfig::default(),
                ctrl_tx,
                ready,
                app_ready,
                dma_writes,
                local_ip,
                _lifetime: Arc::new(WorkerLifetime { stop }),
                connections_opened,
            },
            join,
        ))
    }

    /// Registers a new connection with the worker and returns the
    /// app-side ring endpoints. The worker performs the active open;
    /// wait for `Inbound::Established` on `inbound_rx` before use.
    ///
    /// Returns `None` if the control ring is full (worker not keeping up
    /// with connection opens) after a bounded number of retries.
    pub fn open(
        &self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        local_port: u16,
        nodelay: bool,
    ) -> Option<ConnEndpoints> {
        let tuple = FourTuple {
            local_ip: self.local_ip,
            local_port,
            remote_ip,
            remote_port,
        };
        let (cmd_tx, cmd_rx, outstanding) = command_channel_with_wake(
            Some(Wake {
                tuple,
                sender: self.ready.clone(),
                queued: AtomicBool::new(false),
            }),
            self.send_config.capacity.get(),
        );
        let (inbound_tx, inbound_rx) = inbound_channel(outstanding.clone());
        let wake = self.app_ready.wake_handle();

        let mut msg = NewConn {
            remote_ip,
            remote_port,
            local_port,
            nodelay,
            initial_window_segments: self.send_config.initial_window_segments.get(),
            cmd_rx,
            outstanding,
            inbound_tx,
            app_wake: wake.clone(),
        };
        // Control-ring pushes only fail if the worker has stalled; a short
        // bounded spin covers a transient full ring without blocking the
        // async runtime indefinitely.
        for _ in 0..1024 {
            match self.ctrl_tx.push(msg) {
                Ok(()) => {
                    return Some(ConnEndpoints {
                        cmd_tx,
                        inbound_rx,
                        wake,
                        dma_writes: self.dma_writes,
                    });
                }
                Err(returned) => {
                    msg = returned;
                    std::hint::spin_loop();
                }
            }
        }
        None
    }

    /// Total active opens the engine has performed so far (published by
    /// the worker lcore). Useful to confirm connection reuse.
    pub fn connections_opened(&self) -> u64 {
        self.connections_opened.load(Ordering::Acquire)
    }
}

/// Drains bounded notifications, visiting the map only on queue overflow.
fn collect_ready(
    ready_rx: &MpscRx<FourTuple, READY_CAP>,
    overflow: &AtomicBool,
    conns: &HashMap<FourTuple, WorkerConn>,
    work: &mut HashSet<FourTuple>,
) {
    for _ in 0..READY_CAP {
        let Some(tuple) = ready_rx.pop() else {
            break;
        };
        if let Some(conn) = conns.get(&tuple) {
            conn.outstanding.clear_notification();
            work.insert(tuple);
        }
    }
    if overflow.swap(false, Ordering::AcqRel) {
        // Rare bounded-queue overflow recovery; normal polls do no global scan.
        for (&tuple, conn) in conns {
            if conn
                .outstanding
                .wake
                .as_ref()
                .is_some_and(|w| w.queued.swap(false, Ordering::AcqRel))
            {
                work.insert(tuple);
            }
        }
    }
}

/// The worker lcore's run-to-completion loop.
fn run(
    mut engine: TcpEngine,
    port: EthPort,
    pool: Mempool,
    ctrl_rx: CtrlRx,
    stop: Arc<AtomicBool>,
    connections_opened: Arc<AtomicU64>,
    ready_rx: MpscRx<FourTuple, READY_CAP>,
    overflow: Arc<AtomicBool>,
    mut notifier: AppNotifier,
) {
    let mut conns: HashMap<FourTuple, WorkerConn> = HashMap::default();
    // Mirror of the last value published to `connections_opened`, so the
    // shared (cross-core) counter is only written when it actually changes
    // rather than on every spin.
    let mut published_opened = 0u64;

    let mut events = Vec::new();
    let mut work = HashSet::default();
    let mut closing = HashSet::default();
    while !stop.load(Ordering::Acquire) {
        #[cfg(feature = "tcp-metrics")]
        super::metrics::record(|m| m.worker_iterations += 1);
        notifier.retry();
        // 1. Register newly opened connections.
        while let Some(nc) = ctrl_rx.pop() {
            let candidate = FourTuple {
                local_ip: engine.local_ip(),
                local_port: nc.local_port,
                remote_ip: nc.remote_ip,
                remote_port: nc.remote_port,
            };
            // Never clobber a live connection: refuse if either the worker
            // or the engine already tracks this 4-tuple. The new conn's
            // rings are dropped after the notification; the existing
            // connection is left untouched.
            let tuple = if conns.contains_key(&candidate) {
                None
            } else {
                engine.connect(nc.remote_ip, nc.remote_port, nc.local_port)
            };
            let Some(tuple) = tuple else {
                // The ring is brand new (empty), so this push cannot fail.
                let _ = nc.inbound_tx.push(Inbound::AddrInUse);
                notifier.notify(&nc.app_wake);
                continue;
            };
            engine.set_nodelay(tuple, nc.nodelay);
            engine.set_initial_window(tuple, nc.initial_window_segments);
            work.insert(tuple);
            nc.outstanding.clear_notification();
            let mut conn = WorkerConn::new(tuple, nc.cmd_rx, nc.outstanding, nc.inbound_tx);
            conn.app_wake = Some(nc.app_wake);
            conns.insert(tuple, conn);
            // A connection was just opened; publish the new count (only
            // here, since this is the only place it changes).
            let opened = engine.connections_opened();
            if opened != published_opened {
                published_opened = opened;
                connections_opened.store(opened, Ordering::Release);
            }
        }

        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        work.extend(closing.iter().copied());
        // 2. Apply commands only to notified connections.
        for tuple in &work {
            let Some(conn) = conns.get_mut(tuple) else {
                continue;
            };
            for _ in 0..CMD_CAP {
                let Some(cmd) = conn.cmd_rx.pop() else {
                    break;
                };
                // Ring space: a writer may be waiting on a full ring.
                conn.notify_app = true;
                match cmd {
                    Command::Send(data) => {
                        conn.engine_bytes += data.len();
                        engine.send(conn.tuple, data);
                    }
                    Command::SetCork(c) => engine.set_cork(conn.tuple, c),
                    Command::Flush => engine.flush(conn.tuple),
                    Command::Close => conn.close(&mut engine),
                }
            }
        }

        for tuple in &work {
            if let Some(conn) = conns.get(tuple) {
                if !conn.cmd_rx.is_empty() {
                    conn.outstanding.notify();
                }
            }
        }

        // 3. Pump the engine: rx burst, state machines, timers, tx burst.
        // One clock read per iteration serves the engine and the reaping
        // below; an iteration is far shorter than any deadline it checks.
        let now = Instant::now();
        engine.poll_into(&port, &pool, now, &mut events);
        work.extend(engine.updated_connections().iter().copied());
        for (tuple, ev) in events.drain(..) {
            work.insert(tuple);
            let Some(conn) = conns.get_mut(&tuple) else {
                continue;
            };
            conn.on_event(ev);
        }

        // 4. Deliver received bytes, then the terminal signal, to the app.
        for tuple in &work {
            let Some(conn) = conns.get_mut(tuple) else {
                continue;
            };
            conn.release_credit(&engine);
            // Retry a previously un-pushable chunk first.
            if let Some(pending) = conn.pending_in.take()
                && let Err(Inbound::Data(b)) = conn.push_inbound(Inbound::Data(pending))
            {
                conn.pending_in = Some(b);
            }
            // Pull more only while nothing is stalled.
            if conn.pending_in.is_none() {
                engine.recv_each(conn.tuple, RECV_CHUNK, |chunk| {
                    if let Err(Inbound::Data(b)) = conn.push_inbound(Inbound::Data(chunk)) {
                        conn.pending_in = Some(b);
                    }
                    conn.pending_in.is_none()
                });
            }
            // Peer FIN, once buffered data is fully delivered, becomes an
            // EOF terminal. The terminal signal goes out only after all
            // data has drained, retrying until the ring accepts it.
            conn.deliver_terminal(&engine);
        }

        // 5. Reap connections whose app-side handle is gone. Close the
        //    engine side (idempotent) and drop the worker state; the
        //    engine finishes any TIME_WAIT on its own.
        for tuple in work.drain() {
            let Some(conn) = conns.get_mut(&tuple) else {
                continue;
            };
            // Everything this iteration changed for the connection is
            // visible to the application by now; tell it once.
            if std::mem::take(&mut conn.notify_app)
                && let Some(wake) = &conn.app_wake
            {
                notifier.notify(wake);
            }
            if !conn.retain_after_drop(&mut engine, now) {
                conns.remove(&tuple);
                closing.remove(&tuple);
            } else if conn.is_orphaned() {
                closing.insert(tuple);
            }
        }
    }

    // Stopping closes every ring, which is how a stream learns the worker
    // is gone. Close them first, then wake the streams so they look:
    // connections already running, and opens still queued.
    let mut wakes: Vec<_> = conns.values().filter_map(|c| c.app_wake.clone()).collect();
    drop(conns);
    while let Some(nc) = ctrl_rx.pop() {
        wakes.push(nc.app_wake.clone());
    }
    for wake in &wakes {
        notifier.notify(wake);
    }
    notifier.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CmdTx, WorkerConn, TcpEngine) {
        fixture_with_wake(None)
    }

    fn fixture_with_wake(wake: Option<Wake>) -> (CmdTx, WorkerConn, TcpEngine) {
        let (tx, cmd_rx, outstanding) = command_channel_with_wake(wake, SEND_CAPACITY);
        let (inbound_tx, _rx) = spsc::channel();
        let mut engine = TcpEngine::new(super::super::engine::EngineConfig::default());
        let tuple = engine
            .connect(Ipv4Addr::new(10, 0, 0, 2), 80, 1234)
            .unwrap();
        let conn = WorkerConn::new(tuple, cmd_rx, outstanding, inbound_tx);
        (tx, conn, engine)
    }

    #[test]
    fn notifications_cover_commands_receive_space_and_drop_without_idle_work() {
        let (_, base, _) = fixture();
        let tuple = base.tuple;
        let (ready_tx, ready_rx) = mpsc::channel();
        let overflow = Arc::new(AtomicBool::new(false));
        let wake = Wake {
            tuple,
            queued: AtomicBool::new(false),
            sender: ReadySender {
                tx: ready_tx,
                overflow: overflow.clone(),
            },
        };
        let (tx, conn, _) = fixture_with_wake(Some(wake));
        let (in_tx, in_rx) = inbound_channel(conn.outstanding.clone());
        let mut conns = HashMap::default();
        conns.insert(tuple, conn);
        let mut work = HashSet::default();
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert!(work.is_empty());
        for _ in 0..10 {
            assert!(tx.push(Command::Flush).is_ok());
        }
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert_eq!(work.len(), 1);
        work.clear();
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert!(work.is_empty(), "idle connections must not be scheduled");
        assert!(in_tx.push(Inbound::Data(Bytes::from_static(b"x"))).is_ok());
        assert!(in_rx.pop().is_some());
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert!(work.remove(&tuple), "reading must wake a stalled delivery");
        drop(tx);
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert!(work.contains(&tuple), "dropping must schedule cleanup");
        assert!(conns[&tuple].outstanding.app_gone.load(Ordering::Acquire));
    }

    #[test]
    fn concurrent_notifications_do_not_strand_commands() {
        let (_, base, _) = fixture();
        let tuple = base.tuple;
        let (ready_tx, ready_rx) = mpsc::channel();
        let overflow = Arc::new(AtomicBool::new(false));
        let wake = Wake {
            tuple,
            queued: AtomicBool::new(false),
            sender: ReadySender {
                tx: ready_tx,
                overflow: overflow.clone(),
            },
        };
        let (tx, conn, _) = fixture_with_wake(Some(wake));
        let mut conns = HashMap::default();
        conns.insert(tuple, conn);
        let producer = std::thread::spawn(move || {
            for _ in 0..10000 {
                while tx.push(Command::Flush).is_err() {
                    std::thread::yield_now();
                }
            }
        });
        let mut work = HashSet::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let mut received = 0;
        while received < 10000 || !conns[&tuple].outstanding.app_gone.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "lost a command/drop notification"
            );
            collect_ready(&ready_rx, &overflow, &conns, &mut work);
            if work.remove(&tuple) {
                while conns[&tuple].cmd_rx.pop().is_some() {
                    received += 1;
                }
            }
            std::thread::yield_now();
        }
        producer.join().unwrap();
        assert_eq!(received, 10000);
    }

    #[test]
    fn full_notification_queue_recovers_without_losing_work() {
        let (_, base, _) = fixture();
        let tuple = base.tuple;
        let (ready_tx, ready_rx) = mpsc::channel();
        let overflow = Arc::new(AtomicBool::new(false));
        let mut unrelated = tuple;
        unrelated.local_port += 1;
        for _ in 0..READY_CAP {
            assert!(ready_tx.push(unrelated).is_ok());
        }
        let wake = Wake {
            tuple,
            queued: AtomicBool::new(false),
            sender: ReadySender {
                tx: ready_tx,
                overflow: overflow.clone(),
            },
        };
        let (tx, conn, _) = fixture_with_wake(Some(wake));
        let mut conns = HashMap::default();
        conns.insert(tuple, conn);
        assert!(tx.push(Command::Flush).is_ok());
        assert!(overflow.load(Ordering::Acquire));
        let mut work = HashSet::default();
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert_eq!(work.len(), 1);
        assert!(work.remove(&tuple));
        assert!(!overflow.load(Ordering::Acquire));
        assert!(tx.push(Command::Flush).is_ok());
        collect_ready(&ready_rx, &overflow, &conns, &mut work);
        assert!(
            work.contains(&tuple),
            "notification must rearm after overflow"
        );
    }

    #[test]
    fn dropped_connection_deadline_is_fixed_and_aborts_live_engine() {
        for already_closing in [false, true] {
            let (tx, mut conn, mut engine) = fixture();
            if already_closing {
                conn.close(&mut engine);
                assert_eq!(conn.teardown, Teardown::Closing);
            }
            drop(tx);
            let now = Instant::now();
            let orphaned = Teardown::Orphaned {
                deadline: now + REAP_TIMEOUT,
            };
            assert!(conn.retain_after_drop(&mut engine, now));
            assert_eq!(conn.teardown, orphaned);
            assert!(conn.retain_after_drop(&mut engine, now + REAP_TIMEOUT / 2));
            assert_eq!(conn.teardown, orphaned, "the deadline must not slide");
            assert!(!conn.retain_after_drop(&mut engine, now + REAP_TIMEOUT));
            assert_eq!(engine.state(conn.tuple), None);
        }
    }

    #[test]
    fn dropped_connection_is_reaped_immediately_when_engine_finishes() {
        let (tx, mut conn, mut engine) = fixture();
        drop(tx);
        let now = Instant::now();
        assert!(conn.retain_after_drop(&mut engine, now));
        engine.abort(conn.tuple);
        assert!(!conn.retain_after_drop(&mut engine, now));
    }

    #[test]
    fn moving_commands_to_engine_does_not_restore_send_credit() {
        let (tx, mut conn, mut engine) = fixture();
        assert!(
            tx.push(Command::Send(Bytes::from(vec![0; SEND_CAPACITY])))
                .is_ok()
        );
        let Some(Command::Send(bytes)) = conn.cmd_rx.pop() else {
            panic!()
        };
        conn.engine_bytes += bytes.len();
        engine.send(conn.tuple, bytes);
        conn.release_credit(&engine);
        assert!(tx.is_empty());
        assert_eq!(tx.available_bytes(), 0);
        assert!(tx.push(Command::Send(Bytes::from_static(b"x"))).is_err());
        // Control commands must still get through when byte credit is exhausted.
        assert!(tx.push(Command::Flush).is_ok());
        engine.abort(conn.tuple);
        conn.release_credit(&engine);
        assert_eq!(tx.available_bytes(), SEND_CAPACITY);
    }

    #[test]
    fn full_command_ring_rolls_back_reserved_credit() {
        let (tx, _rx, _) = command_channel();
        for _ in 0..tx.capacity() {
            assert!(tx.push(Command::Flush).is_ok());
        }
        assert!(tx.push(Command::Send(Bytes::from_static(b"x"))).is_err());
        assert_eq!(tx.available_bytes(), SEND_CAPACITY);
    }

    #[test]
    fn configured_credit_is_bounded_and_replenished() {
        for capacity in [1024, 256 * 1024, 2 * 1024 * 1024] {
            let (tx, rx, credit) = command_channel_with_wake(None, capacity);
            assert_eq!(tx.available_bytes(), capacity);
            assert!(
                tx.push(Command::Send(Bytes::from(vec![0; capacity])))
                    .is_ok()
            );
            assert!(tx.push(Command::Send(Bytes::from_static(b"x"))).is_err());
            // Consuming commands alone does not release their byte reservation.
            rx.pop().unwrap();
            assert_eq!(tx.available_bytes(), 0);
            credit.bytes.fetch_sub(100, Ordering::AcqRel);
            assert_eq!(tx.available_bytes(), 100);
            assert!(tx.push(Command::Send(Bytes::from(vec![0; 100]))).is_ok());
            assert_eq!(tx.available_bytes(), 0);
        }
    }

    #[test]
    fn abort_notifies_both_connecting_and_established_readers() {
        for established in [false, true] {
            let (cmd_tx, cmd_rx, outstanding) = command_channel();
            let (inbound_tx, _inbound_rx) = spsc::channel::<Inbound, IN_CAP>();
            let tuple = FourTuple {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 1234,
                remote_ip: Ipv4Addr::new(10, 0, 0, 2),
                remote_port: 80,
            };
            let mut conn = WorkerConn::new(tuple, cmd_rx, outstanding, inbound_tx);
            if established {
                conn.on_event(Event::Established);
                assert!(matches!(conn.delivery, Delivery::Established));
            }
            conn.on_event(Event::Reset);
            assert!(cmd_tx.failed());
            assert!(
                cmd_tx
                    .push(Command::Send(Bytes::from_static(b"x")))
                    .is_err()
            );
            if established {
                assert!(matches!(conn.delivery, Delivery::Terminal(Inbound::Reset)));
            } else {
                assert!(matches!(
                    conn.delivery,
                    Delivery::Terminal(Inbound::ConnectFailed)
                ));
            }
        }
    }

    #[test]
    fn dropping_a_cloned_handle_does_not_stop_the_worker() {
        let (ctrl_tx, _ctrl_rx) = mpsc::channel::<NewConn, CTRL_CAP>();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = mpsc::channel();
        let handle = WorkerHandle {
            #[cfg(feature = "tcp-metrics")]
            metrics: crate::dpdk::tcp::metrics::Report::default(),
            send_config: SendConfig::default(),
            ctrl_tx,
            local_ip: Ipv4Addr::UNSPECIFIED,
            ready: ReadySender {
                tx,
                overflow: Arc::new(AtomicBool::new(false)),
            },
            app_ready: app_wake::channel().1,
            dma_writes: false,
            _lifetime: Arc::new(WorkerLifetime { stop: stop.clone() }),
            connections_opened: Arc::new(AtomicU64::new(0)),
        };

        drop(handle.clone());
        assert!(!stop.load(Ordering::Acquire));

        drop(handle);
        assert!(stop.load(Ordering::Acquire));
    }
}

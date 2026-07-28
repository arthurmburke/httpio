//! Runs the `TcpEngine` on a dedicated DPDK worker lcore and exposes it
//! to application (tokio) threads over lock-free SPSC rings.
//!
//! Threading model:
//!  - The **worker lcore** owns the `TcpEngine`, `EthPort`, and mbuf
//!    `PktMbufPool` outright. It busy-polls in a run-to-completion loop:
//!    drain per-connection command rings into the engine, pump the engine
//!    (rx burst -> state machines/timers -> tx burst), then drain engine
//!    receive buffers back out to per-connection inbound rings. No locks.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;

use crate::core::hashmap::HashMap;
use crate::core::mpsc;
use crate::core::mpsc::{MpscRx, MpscTx};
use crate::core::spsc;
use crate::core::spsc::{SpscRx, SpscTx};
use crate::dpdk::{self, EthPort, Mempool, WorkerJoin};

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

// Per-connection rings stay SPSC: exactly one thread owns each end (the
// thread driving that connection's `TcpStream`, and the worker lcore).
pub type CmdTx = SpscTx<Command, CMD_CAP>;
pub type CmdRx = SpscRx<Command, CMD_CAP>;
pub type InboundTx = SpscTx<Inbound, IN_CAP>;
pub type InboundRx = SpscRx<Inbound, IN_CAP>;
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
}

/// The control message that registers a new connection with the worker,
/// carrying the worker-side halves of its ring pair.
struct NewConn {
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    nodelay: bool,
    cmd_rx: CmdRx,
    inbound_tx: InboundTx,
}

/// Worker-side per-connection state.
struct WorkerConn {
    tuple: FourTuple,
    cmd_rx: CmdRx,
    inbound_tx: InboundTx,
    /// A received chunk the inbound ring was too full to accept; retried
    /// before pulling more from the engine so no bytes are dropped.
    pending_in: Option<Bytes>,
    established: bool,
    /// Peer sent FIN; deliver an `Eof` once buffered data has drained.
    peer_fin: bool,
    /// The one terminal signal (Eof/ConnectFailed/Reset) to deliver after
    /// buffered data drains. Held (not dropped) until the inbound ring
    /// accepts it, so it can never be lost to a transiently full ring.
    terminal: Option<Inbound>,
    /// The terminal signal has been delivered; stop producing.
    end_sent: bool,
    /// We've asked the engine to close (half-close), so don't repeat it.
    closing: bool,
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
    ctrl_tx: CtrlTx,
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
}

impl WorkerHandle {
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

        let join = dpdk::launch(worker_lcore, move || {
            run(engine, port, pool, ctrl_rx, worker_stop, worker_opened);
        })?;

        Ok((
            WorkerHandle {
                ctrl_tx,
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
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
        nodelay: bool,
    ) -> Option<ConnEndpoints> {
        let (cmd_tx, cmd_rx) = spsc::channel::<Command, CMD_CAP>();
        let (inbound_tx, inbound_rx) = spsc::channel::<Inbound, IN_CAP>();

        let mut msg = NewConn {
            remote_ip,
            remote_port,
            local_port,
            nodelay,
            cmd_rx,
            inbound_tx,
        };
        // Control-ring pushes only fail if the worker has stalled; a short
        // bounded spin covers a transient full ring without blocking the
        // async runtime indefinitely.
        for _ in 0..1024 {
            match self.ctrl_tx.push(msg) {
                Ok(()) => return Some(ConnEndpoints { cmd_tx, inbound_rx }),
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

/// The worker lcore's run-to-completion loop.
fn run(
    mut engine: TcpEngine,
    port: EthPort,
    pool: Mempool,
    ctrl_rx: CtrlRx,
    stop: Arc<AtomicBool>,
    connections_opened: Arc<AtomicU64>,
) {
    let mut conns: HashMap<FourTuple, WorkerConn> = HashMap::default();
    // Mirror of the last value published to `connections_opened`, so the
    // shared (cross-core) counter is only written when it actually changes
    // rather than on every spin.
    let mut published_opened = 0u64;

    while !stop.load(Ordering::Acquire) {
        // 1. Register newly opened connections.
        while let Some(nc) = ctrl_rx.pop() {
            let tuple = engine.connect(nc.remote_ip, nc.remote_port, nc.local_port);
            engine.set_nodelay(tuple, nc.nodelay);
            conns.insert(
                tuple,
                WorkerConn {
                    tuple,
                    cmd_rx: nc.cmd_rx,
                    inbound_tx: nc.inbound_tx,
                    pending_in: None,
                    established: false,
                    peer_fin: false,
                    terminal: None,
                    end_sent: false,
                    closing: false,
                },
            );
            // A connection was just opened; publish the new count (only
            // here, since this is the only place it changes).
            let opened = engine.connections_opened();
            if opened != published_opened {
                published_opened = opened;
                connections_opened.store(opened, Ordering::Release);
            }
        }

        // 2. Apply queued commands from each connection.
        for conn in conns.values_mut() {
            while let Some(cmd) = conn.cmd_rx.pop() {
                match cmd {
                    Command::Send(data) => engine.send(conn.tuple, data),
                    Command::SetCork(c) => engine.set_cork(conn.tuple, c),
                    Command::Flush => engine.flush(conn.tuple),
                    Command::Close => {
                        engine.close(conn.tuple);
                        conn.closing = true;
                    }
                }
            }
        }

        // 3. Pump the engine: rx burst, state machines, timers, tx burst.
        let events = engine.poll(&port, &pool, Instant::now());
        for (tuple, ev) in events {
            let Some(conn) = conns.get_mut(&tuple) else {
                continue;
            };
            match ev {
                Event::Established => {
                    if conn.inbound_tx.push(Inbound::Established).is_ok() {
                        conn.established = true;
                    }
                    // If the ring were somehow full, the app hasn't
                    // consumed anything yet, so it will next iteration.
                }
                Event::PeerClosed => conn.peer_fin = true,
                Event::Reset => {
                    // Distinguish a failed handshake from a reset of an
                    // established connection so the app reports the right
                    // error.
                    conn.terminal.get_or_insert(if conn.established {
                        Inbound::Reset
                    } else {
                        Inbound::ConnectFailed
                    });
                }
                Event::Closed => {
                    // A close before ESTABLISHED is a failed active open;
                    // an established-then-closed connection is delivered as
                    // EOF via the peer_fin path below.
                    if !conn.established {
                        conn.terminal.get_or_insert(Inbound::ConnectFailed);
                    }
                }
            }
        }

        // 4. Deliver received bytes, then the terminal signal, to the app.
        for conn in conns.values_mut() {
            // Retry a previously un-pushable chunk first.
            if let Some(pending) = conn.pending_in.take()
                && let Err(Inbound::Data(b)) = conn.inbound_tx.push(Inbound::Data(pending))
            {
                conn.pending_in = Some(b);
            }
            // Pull more only while nothing is stalled.
            while conn.pending_in.is_none() {
                let chunk = engine.recv(conn.tuple, RECV_CHUNK);
                if chunk.is_empty() {
                    break;
                }
                if let Err(Inbound::Data(b)) = conn.inbound_tx.push(Inbound::Data(chunk)) {
                    conn.pending_in = Some(b);
                }
            }
            // Peer FIN, once buffered data is fully delivered, becomes an
            // EOF terminal.
            if conn.peer_fin
                && conn.terminal.is_none()
                && !conn.end_sent
                && conn.pending_in.is_none()
                && engine.readable_len(conn.tuple) == 0
            {
                conn.terminal = Some(Inbound::Eof);
            }
            // Deliver the terminal signal only after all data has drained,
            // retrying until the ring accepts it (never dropped).
            if !conn.end_sent
                && conn.pending_in.is_none()
                && let Some(terminal) = conn.terminal.take()
            {
                match conn.inbound_tx.push(terminal) {
                    Ok(()) => conn.end_sent = true,
                    Err(returned) => conn.terminal = Some(returned),
                }
            }
        }

        // 5. Reap connections whose app-side handle is gone. Close the
        //    engine side (idempotent) and drop the worker state; the
        //    engine finishes any TIME_WAIT on its own.
        conns.retain(|_, conn| {
            let app_gone = conn.cmd_rx.is_closed();
            if app_gone {
                if !conn.closing {
                    engine.close(conn.tuple);
                }
                // Keep it only until the engine no longer tracks it, so a
                // trailing FIN/ACK still gets sent.
                return matches!(engine.state(conn.tuple), Some(s) if s != TcpState::Closed);
            }
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_cloned_handle_does_not_stop_the_worker() {
        let (ctrl_tx, _ctrl_rx) = mpsc::channel::<NewConn, CTRL_CAP>();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = WorkerHandle {
            ctrl_tx,
            _lifetime: Arc::new(WorkerLifetime { stop: stop.clone() }),
            connections_opened: Arc::new(AtomicU64::new(0)),
        };

        drop(handle.clone());
        assert!(!stop.load(Ordering::Acquire));

        drop(handle);
        assert!(stop.load(Ordering::Acquire));
    }
}

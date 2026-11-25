//! The worker lcore's side of UDP sockets, and the rings that connect it
//! to their application side.
//!
//! There is no UDP worker loop: UDP shares each TCP worker's loop (see
//! the [module docs](super)), which calls [`UdpWorker`] at fixed points
//! of every iteration:
//!
//! ```text
//!  register   new bindings from the control ring -> Bound / AddrInUse
//!  apply      notified sockets' commands -> engine outbound queue
//!  (poll)     the engine receives, and transmits what was queued
//!  deliver    engine receive queues -> each socket's inbound ring
//! ```
//!
//! The rings mirror a TCP connection's: per socket and per worker, one
//! SPSC command ring (application -> worker) and one SPSC inbound ring
//! (worker -> application), registered through an MPSC control ring. The
//! application pushes a command and then notifies the worker through a
//! coalescing flag and a bounded MPSC queue of local ports, falling back
//! to a scan of every socket only when that queue overflows -- the same
//! scheme TCP uses, with its own types, so the TCP path is unchanged.
//!
//! UDP has no flow control, so neither direction ever stalls the worker:
//! - Sending: a command is taken off its ring only while the engine's
//!   outbound queue has room. Otherwise it stays on the ring, which fills
//!   and makes the application wait: backpressure, with nothing dropped.
//! - Receiving: a datagram the inbound ring will not take stays in the
//!   engine's per-binding queue, which drops the newest once full, as a
//!   kernel socket buffer does. The application does not report reading,
//!   so the worker retries such a socket on every iteration until its
//!   queue is empty.
//!
//! A socket is unbound once its application side is gone entirely: the
//! command ring closed and drained, and the inbound ring closed. Each half
//! of a split socket notifies the worker as it drops.

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;

use super::engine::{Datagram, UdpStats};
use crate::core::hashmap::HashMap;
use crate::core::hashset::HashSet;
use crate::core::mpsc::{self, MpscRx, MpscTx};
use crate::core::spsc::{self, SpscRx, SpscTx};
use crate::dpdk::tcp::app_wake::{AppNotifier, AppReady, AppWake};
use crate::dpdk::tcp::engine::TcpEngine;
use crate::dpdk::{EthPort, Mempool};

/// Control ring depth: binds in flight to one worker.
const CTRL_CAP: usize = 256;
/// Per-socket command ring depth (datagrams queued to send).
pub(crate) const CMD_CAP: usize = 1024;
/// Per-socket inbound ring depth (datagrams received and not yet read).
pub(crate) const IN_CAP: usize = 1024;
/// Notifications in flight from sockets to one worker; each socket is
/// queued at most once, so this overflows only with more sockets than
/// slots all active between two worker iterations.
const READY_CAP: usize = 4096;

/// Application -> worker, per socket.
pub(crate) enum UdpCommand {
    /// One datagram, never split.
    SendTo { dst: SocketAddrV4, data: Bytes },
    /// Sets (or clears) the binding's peer filter. Ordered with the sends
    /// on the same ring.
    Connect(Option<SocketAddrV4>),
}

/// Worker -> application, per socket.
pub(crate) enum UdpInbound {
    /// The port is bound on this worker. Always the first message.
    Bound {
        /// The largest datagram the engine accepts whatever memory it is
        /// in (see `UdpEngine::max_payload`).
        max_payload: usize,
    },
    /// The port was already bound on this worker. Terminal.
    AddrInUse,
    Datagram(Datagram),
}

/// How a socket tells its worker it has something to do (commands, or
/// that a half of it went away). Shared by the socket's halves and the
/// worker; one per socket per worker.
pub(crate) struct UdpNotify {
    port: u16,
    tx: MpscTx<u16, READY_CAP>,
    overflow: Arc<AtomicBool>,
    /// A notification for this socket is on its way to the worker.
    queued: AtomicBool,
}

impl UdpNotify {
    /// Call after making the change visible (pushing a command, dropping a
    /// ring). Coalesces; a saturated queue falls back to the overflow scan
    /// rather than losing the wake-up.
    pub(crate) fn notify(&self) {
        if !self.queued.swap(true, Ordering::AcqRel) && self.tx.push(self.port).is_err() {
            self.overflow.store(true, Ordering::Release);
        }
    }

    fn clear(&self) {
        // A swap, not a store: if the application's swap came first, this
        // one reads it and synchronizes with it, so the ring pops that
        // follow see the push it published. A plain store has no acquire
        // edge, and the command could sit unseen with the flag clear (the
        // store-buffer outcome; see `app_wake`).
        self.queued.swap(false, Ordering::AcqRel);
    }
}

/// Notifies the worker when dropped. Declared after the ring it guards in
/// the structs below, so that it runs after the ring has been dropped and
/// the worker sees it closed.
struct NotifyOnDrop(Arc<UdpNotify>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify();
    }
}

/// The application's end of a socket's command ring.
pub(crate) struct UdpCmdTx {
    ring: SpscTx<UdpCommand, CMD_CAP>,
    notify: NotifyOnDrop,
}

impl UdpCmdTx {
    /// Pushes and notifies the worker; `Err` gives the command back when
    /// the ring is full.
    pub(crate) fn push(&self, cmd: UdpCommand) -> Result<(), UdpCommand> {
        self.ring.push(cmd)?;
        self.notify.0.notify();
        Ok(())
    }

    pub(crate) fn is_full(&self) -> bool {
        self.ring.len() >= self.ring.capacity()
    }

    /// The worker dropped its end: it stopped.
    pub(crate) fn is_closed(&self) -> bool {
        self.ring.is_closed()
    }
}

/// The application's end of a socket's inbound ring. As for TCP, reading
/// tells the worker nothing; the worker comes back by itself to a socket
/// whose ring was full.
pub(crate) struct UdpInboundRx {
    ring: SpscRx<UdpInbound, IN_CAP>,
    _notify: NotifyOnDrop,
}

impl UdpInboundRx {
    pub(crate) fn pop(&self) -> Option<UdpInbound> {
        self.ring.pop()
    }

    /// The worker dropped its end: it stopped. Sample this *before*
    /// popping: the worker pushes everything first, so a ring closed then
    /// and empty after the pops has nothing more to give.
    pub(crate) fn is_closed(&self) -> bool {
        self.ring.is_closed()
    }
}

/// The control message that registers a socket with a worker, carrying
/// the worker's ends of its rings.
pub(crate) struct NewUdpBinding {
    pub(crate) local_port: u16,
    /// Peer filter to install with the binding.
    pub(crate) connected: Option<SocketAddrV4>,
    pub(crate) cmd_rx: SpscRx<UdpCommand, CMD_CAP>,
    pub(crate) inbound_tx: SpscTx<UdpInbound, IN_CAP>,
    pub(crate) notify: Arc<UdpNotify>,
    /// Woken when the worker takes commands (ring space for a sender).
    pub(crate) send_wake: Arc<AppWake>,
    /// Woken when the worker pushes to the inbound ring.
    pub(crate) recv_wake: Arc<AppWake>,
    /// Counted into by the engine, read by the application.
    pub(crate) stats: Arc<UdpStats>,
}

/// The application's ends of one socket's rings on one worker.
pub(crate) struct UdpEndpoints {
    pub(crate) cmd_tx: UdpCmdTx,
    pub(crate) inbound_rx: UdpInboundRx,
    pub(crate) send_wake: Arc<AppWake>,
    pub(crate) recv_wake: Arc<AppWake>,
    pub(crate) stats: Arc<UdpStats>,
}

/// The application side's UDP channels to one worker (part of its
/// `WorkerLink`).
pub(crate) struct UdpLink {
    ctrl_tx: MpscTx<NewUdpBinding, CTRL_CAP>,
    ready_tx: MpscTx<u16, READY_CAP>,
    overflow: Arc<AtomicBool>,
}

/// The control ring stayed full: the worker is overloaded or stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Busy;

impl UdpLink {
    /// Asks the worker to bind `local_port`; the reply is the first
    /// message on the returned inbound ring. Fails only if the control
    /// ring stays full through a short bounded spin, as a TCP open does.
    pub(crate) fn bind(
        &self,
        local_port: u16,
        connected: Option<SocketAddrV4>,
        app_ready: &Arc<AppReady>,
    ) -> Result<UdpEndpoints, Busy> {
        let (endpoints, mut msg) = binding(
            local_port,
            connected,
            &self.ready_tx,
            &self.overflow,
            app_ready,
        );
        for _ in 0..1024 {
            match self.ctrl_tx.push(msg) {
                Ok(()) => return Ok(endpoints),
                Err(returned) => {
                    msg = returned;
                    std::hint::spin_loop();
                }
            }
        }
        Err(Busy)
    }
}

/// A fresh socket's ring pairs: the application's ends, and the message
/// that hands the worker its ends.
pub(crate) fn binding(
    local_port: u16,
    connected: Option<SocketAddrV4>,
    ready_tx: &MpscTx<u16, READY_CAP>,
    overflow: &Arc<AtomicBool>,
    app_ready: &Arc<AppReady>,
) -> (UdpEndpoints, NewUdpBinding) {
    let notify = Arc::new(UdpNotify {
        port: local_port,
        tx: ready_tx.clone(),
        overflow: overflow.clone(),
        queued: AtomicBool::new(false),
    });
    let (cmd_tx, cmd_rx) = spsc::channel();
    let (inbound_tx, inbound_rx) = spsc::channel();
    let (send_wake, recv_wake) = (app_ready.wake_handle(), app_ready.wake_handle());
    let stats = Arc::new(UdpStats::default());
    (
        UdpEndpoints {
            cmd_tx: UdpCmdTx {
                ring: cmd_tx,
                notify: NotifyOnDrop(notify.clone()),
            },
            inbound_rx: UdpInboundRx {
                ring: inbound_rx,
                _notify: NotifyOnDrop(notify.clone()),
            },
            send_wake: send_wake.clone(),
            recv_wake: recv_wake.clone(),
            stats: stats.clone(),
        },
        NewUdpBinding {
            local_port,
            connected,
            cmd_rx,
            inbound_tx,
            notify,
            send_wake,
            recv_wake,
            stats,
        },
    )
}

/// One worker's UDP channels: the application's end and the worker's.
pub(crate) fn channel() -> (UdpLink, UdpWorker) {
    let (ctrl_tx, ctrl_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let overflow = Arc::new(AtomicBool::new(false));
    (
        UdpLink {
            ctrl_tx,
            ready_tx,
            overflow: overflow.clone(),
        },
        UdpWorker {
            ctrl_rx,
            ready_rx,
            overflow,
            sockets: HashMap::default(),
            work: HashSet::default(),
            blocked_tx: HashSet::default(),
            blocked_rx: HashSet::default(),
            scratch: Vec::new(),
            visit: Vec::new(),
            turn: 0,
        },
    )
}

/// Worker-side state of one socket.
struct WorkerSocket {
    cmd_rx: SpscRx<UdpCommand, CMD_CAP>,
    /// `None` once the reader is gone: the worker drops its end too, so
    /// that the ring, and the datagrams still on it, are freed then rather
    /// than when the sender goes as well.
    inbound_tx: Option<SpscTx<UdpInbound, IN_CAP>>,
    notify: Arc<UdpNotify>,
    send_wake: Arc<AppWake>,
    recv_wake: Arc<AppWake>,
}

impl WorkerSocket {
    /// Nothing of the application side is left: no sender, no commands
    /// still to apply, no reader.
    fn app_gone(&self) -> bool {
        self.abandoned() && self.cmd_rx.is_empty()
    }

    /// Both halves of the application side were dropped, though commands
    /// may still be waiting on the ring.
    fn abandoned(&self) -> bool {
        self.cmd_rx.is_closed() && self.inbound_tx.as_ref().is_none_or(SpscTx::is_closed)
    }

    /// Drops the worker's end of the inbound ring once the reader has
    /// dropped its own, freeing what it held.
    fn release_closed_inbound(&mut self) {
        if self.inbound_tx.as_ref().is_some_and(SpscTx::is_closed) {
            self.inbound_tx = None;
        }
    }
}

/// The UDP state machine of one worker (see the [module docs](self)).
pub(crate) struct UdpWorker {
    ctrl_rx: MpscRx<NewUdpBinding, CTRL_CAP>,
    ready_rx: MpscRx<u16, READY_CAP>,
    overflow: Arc<AtomicBool>,
    sockets: HashMap<u16, WorkerSocket>,
    /// Sockets notified since their last visit.
    work: HashSet<u16>,
    /// Sockets with commands left on their ring for want of outbound room.
    blocked_tx: HashSet<u16>,
    /// Sockets with datagrams left in the engine for want of ring space.
    blocked_rx: HashSet<u16>,
    /// Ports to deliver to this iteration (reused storage).
    scratch: Vec<u16>,
    /// Ports to apply commands for this iteration (reused storage).
    visit: Vec<u16>,
    /// Rotates which socket `apply` serves first: the hash set's order is
    /// fixed, and the first would otherwise always take the outbound room.
    turn: usize,
}

impl UdpWorker {
    /// Registers sockets bound since the last iteration. An idle call is
    /// one load of the control ring.
    pub(crate) fn register(
        &mut self,
        engine: &mut TcpEngine,
        port: &EthPort,
        pool: &Mempool,
        notifier: &mut AppNotifier,
    ) {
        let Some(first) = self.ctrl_rx.pop() else {
            return;
        };
        // The limit the socket is told must be the port's, which the
        // engine learns only as it polls; this may come before the first.
        engine.udp_mut().refresh_limits(port, pool);
        self.register_one(engine, first, notifier);
        while let Some(msg) = self.ctrl_rx.pop() {
            self.register_one(engine, msg, notifier);
        }
    }

    fn register_one(
        &mut self,
        engine: &mut TcpEngine,
        msg: NewUdpBinding,
        notifier: &mut AppNotifier,
    ) {
        let port = msg.local_port;
        // A socket dropped just before this bind has not been visited yet
        // (its notification may be behind this message). Its rings are
        // closed already, the drop having happened first, so retire it now
        // and the port is free again, as it is in the kernel after close.
        if self.sockets.get(&port).is_some_and(WorkerSocket::abandoned) {
            self.retire(engine, port);
        }
        let capacity = engine.udp().default_rx_queue_capacity();
        let bound = !self.sockets.contains_key(&port)
            && engine
                .udp_mut()
                .bind_with_stats(port, capacity, msg.stats.clone())
                .is_ok();
        let reply = if bound {
            // Cannot fail: just bound.
            let _ = engine.udp_mut().connect(port, msg.connected);
            UdpInbound::Bound {
                max_payload: engine.udp().max_payload(),
            }
        } else {
            UdpInbound::AddrInUse
        };
        // The ring is brand new (empty), so this push cannot fail.
        let _ = msg.inbound_tx.push(reply);
        notifier.notify(&msg.recv_wake);
        if bound {
            msg.notify.clear();
            // Visit it this iteration, as TCP's register does. A
            // notification may have come before the socket was registered,
            // and `collect` drops those (no socket yet): a bind abandoned
            // in that window (cancelled, or refused by another worker)
            // would otherwise stay bound with nothing to retire it. The
            // clear above comes first, so a change after it notifies anew.
            self.work.insert(port);
            self.sockets.insert(
                port,
                WorkerSocket {
                    cmd_rx: msg.cmd_rx,
                    inbound_tx: Some(msg.inbound_tx),
                    notify: msg.notify,
                    send_wake: msg.send_wake,
                    recv_wake: msg.recv_wake,
                },
            );
        }
    }

    /// Drains the notification queue into `work`, visiting every socket
    /// only after the queue overflowed.
    fn collect(&mut self) {
        for _ in 0..READY_CAP {
            let Some(port) = self.ready_rx.pop() else {
                break;
            };
            if let Some(socket) = self.sockets.get(&port) {
                socket.notify.clear();
                self.work.insert(port);
            }
        }
        // A plain load first: the swap is a locked instruction, and the
        // flag is almost never set.
        if self.overflow.load(Ordering::Relaxed) && self.overflow.swap(false, Ordering::AcqRel) {
            for (&port, socket) in &self.sockets {
                if socket.notify.queued.swap(false, Ordering::AcqRel) {
                    self.work.insert(port);
                }
            }
        }
    }

    /// Applies the commands of sockets that notified the worker, or that
    /// still had commands waiting for outbound room, and unbinds sockets
    /// whose application side is gone.
    pub(crate) fn apply(&mut self, engine: &mut TcpEngine, notifier: &mut AppNotifier) {
        self.collect();
        if self.work.is_empty() && self.blocked_tx.is_empty() {
            return;
        }
        let contended = !self.blocked_tx.is_empty();
        self.work.extend(self.blocked_tx.drain());
        self.visit.extend(self.work.drain());
        // Each socket gets a share of the room, and a different one goes
        // first each time, so that one busy sender cannot take all of it on
        // every iteration and starve the rest (a share of 1 when there is
        // less room than sockets: each still gets a turn within `n`). The
        // turn is taken in port order, not the hash set's, which need not
        // stay the same; only when senders are waiting for room is it worth
        // the sort.
        let n = self.visit.len();
        if n > 1 && contended {
            self.visit.sort_unstable();
            self.visit.rotate_left(self.turn % n);
            self.turn = self.turn.wrapping_add(1);
        }
        let quantum = engine.udp().outbound_room().div_ceil(n.max(1)).max(1);
        for port in self.visit.drain(..) {
            let Some(socket) = self.sockets.get_mut(&port) else {
                continue;
            };
            // The reader's drop notifies, so this is where it is seen even
            // when nothing more arrives for `deliver` to notice.
            socket.release_closed_inbound();
            let mut took = false;
            for _ in 0..quantum {
                if engine.udp().outbound_room() == 0 {
                    break;
                }
                let Some(cmd) = socket.cmd_rx.pop() else {
                    break;
                };
                took = true;
                apply_command(engine, port, cmd);
            }
            if !socket.cmd_rx.is_empty() {
                // No room, or this socket's share used: leave them on the
                // ring, whose being full is what makes the sender wait.
                // Come back next iteration.
                self.blocked_tx.insert(port);
            }
            if took {
                // Ring space: a sender may be waiting for it.
                notifier.notify(&socket.send_wake);
            }
            if socket.app_gone() {
                self.sockets.remove(&port);
                self.blocked_rx.remove(&port);
                engine.udp_mut().unbind(port);
            }
        }
    }

    /// Moves what the engine received during its poll to the sockets'
    /// inbound rings, retrying sockets whose ring was full before.
    pub(crate) fn deliver(&mut self, engine: &mut TcpEngine, notifier: &mut AppNotifier) {
        let updated = engine.udp().updated_bindings();
        if updated.is_empty() && self.blocked_rx.is_empty() {
            return;
        }
        self.scratch.extend_from_slice(updated);
        self.scratch.extend(self.blocked_rx.drain());
        for port in self.scratch.drain(..) {
            // Bound through the engine directly, not through a socket.
            let Some(socket) = self.sockets.get_mut(&port) else {
                continue;
            };
            socket.release_closed_inbound();
            let Some(inbound_tx) = socket.inbound_tx.as_ref() else {
                // Nobody reads any more (the receiving half was dropped):
                // free the mbufs rather than hold a queue's worth.
                engine.udp_mut().recv_each(port, |_| Ok(()));
                continue;
            };
            // The ring holds no more than the binding's own queue would,
            // so a smaller capacity bounds what a socket pins: at most
            // twice it, per worker.
            let limit = engine
                .udp()
                .rx_queue_capacity(port)
                .map_or(IN_CAP, |capacity| capacity.min(IN_CAP));
            let mut pushed = false;
            engine.udp_mut().recv_each(port, |datagram| {
                if inbound_tx.len() >= limit {
                    return Err(datagram);
                }
                match inbound_tx.push(UdpInbound::Datagram(datagram)) {
                    Ok(()) => {
                        pushed = true;
                        Ok(())
                    }
                    Err(returned) => Err(into_datagram(returned)),
                }
            });
            if engine.udp().pending_rx(port) > 0 {
                self.blocked_rx.insert(port);
            }
            if pushed {
                notifier.notify(&socket.recv_wake);
            }
        }
    }

    /// Unbinds a socket whose application side is gone, first applying
    /// what it left on its command ring as far as the outbound queue has
    /// room. Commands beyond that are dropped and counted.
    fn retire(&mut self, engine: &mut TcpEngine, port: u16) {
        let Some(socket) = self.sockets.remove(&port) else {
            return;
        };
        self.blocked_tx.remove(&port);
        self.blocked_rx.remove(&port);
        let mut dropped = 0;
        while let Some(cmd) = socket.cmd_rx.pop() {
            if engine.udp().outbound_room() > 0 {
                apply_command(engine, port, cmd);
            } else {
                dropped += 1;
            }
        }
        if dropped != 0
            && let Some(stats) = engine.udp().stats(port)
        {
            stats.count_tx_dropped(dropped);
        }
        engine.udp_mut().unbind(port);
    }

    /// Worker shutdown: closes every socket's rings, including those of
    /// binds still on the control ring, and returns the wake handles to
    /// notify once they are closed.
    pub(crate) fn shutdown(self, wakes: &mut Vec<Arc<AppWake>>) {
        for socket in self.sockets.into_values() {
            wakes.push(socket.send_wake.clone());
            wakes.push(socket.recv_wake.clone());
        }
        while let Some(msg) = self.ctrl_rx.pop() {
            wakes.push(msg.recv_wake.clone());
        }
    }
}

fn apply_command(engine: &mut TcpEngine, port: u16, cmd: UdpCommand) {
    let udp = engine.udp_mut();
    match cmd {
        UdpCommand::SendTo { dst, data } => {
            // Only room was checked; the socket checked the rest against
            // the limit it was given, so this fails only if the port's
            // limits shrank since.
            if udp.send_to(port, dst, data).is_err()
                && let Some(stats) = udp.stats(port)
            {
                stats.count_tx_dropped(1);
            }
        }
        UdpCommand::Connect(peer) => {
            let _ = udp.connect(port, peer);
        }
    }
}

fn into_datagram(msg: UdpInbound) -> Datagram {
    match msg {
        UdpInbound::Datagram(datagram) => datagram,
        _ => unreachable!("deliver pushes only datagrams"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpdk::tcp::app_wake;
    use crate::dpdk::tcp::engine::EngineConfig;
    use std::net::Ipv4Addr;

    fn engine() -> TcpEngine {
        TcpEngine::new(EngineConfig::default())
    }

    fn send(endpoints: &UdpEndpoints, n: u8) -> Result<(), UdpCommand> {
        endpoints.cmd_tx.push(UdpCommand::SendTo {
            dst: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9),
            data: Bytes::from(vec![n]),
        })
    }

    /// Binding, refusal, backpressure from the engine's outbound queue,
    /// and unbinding once both halves of the application side are gone,
    /// after which the port can be bound again at once.
    #[test]
    fn sockets_are_bound_fed_and_retired_through_their_rings() {
        let (link, mut worker) = channel();
        let (mut notifier, ready) = app_wake::channel();
        let mut engine = engine();
        engine.udp_mut().set_outbound_capacity(2);

        let bind = |port| {
            let (endpoints, msg) = binding(port, None, &link.ready_tx, &link.overflow, &ready);
            (endpoints, msg)
        };
        let (first, msg) = bind(5000);
        worker.register_one(&mut engine, msg, &mut notifier);
        assert!(matches!(
            first.inbound_rx.pop(),
            Some(UdpInbound::Bound { max_payload: 1472 })
        ));
        assert!(engine.udp().is_bound(5000));
        let (second, msg) = bind(5000);
        worker.register_one(&mut engine, msg, &mut notifier);
        assert!(matches!(
            second.inbound_rx.pop(),
            Some(UdpInbound::AddrInUse)
        ));
        drop(second);

        // Five sends, room for two: the rest wait on the ring.
        for n in 0..5 {
            assert!(send(&first, n).is_ok());
        }
        worker.apply(&mut engine, &mut notifier);
        assert_eq!(engine.udp().pending_tx(), 2);
        assert!(worker.blocked_tx.contains(&5000));
        // Still no room: nothing more is taken, and nothing is lost.
        worker.apply(&mut engine, &mut notifier);
        assert_eq!(engine.udp().pending_tx(), 2);
        engine.udp_mut().set_outbound_capacity(16);
        worker.apply(&mut engine, &mut notifier);
        assert_eq!(engine.udp().pending_tx(), 5);
        assert!(worker.blocked_tx.is_empty());

        // Half the socket gone: still bound.
        let UdpEndpoints {
            cmd_tx, inbound_rx, ..
        } = first;
        drop(cmd_tx);
        worker.apply(&mut engine, &mut notifier);
        assert!(engine.udp().is_bound(5000));
        drop(inbound_rx);
        worker.apply(&mut engine, &mut notifier);
        assert!(!engine.udp().is_bound(5000));
        assert!(worker.sockets.is_empty());

        // Dropped and rebound before the worker saw the drop: the bind
        // retires the old socket, sending what it had queued.
        let (third, msg) = bind(5001);
        worker.register_one(&mut engine, msg, &mut notifier);
        assert!(send(&third, 9).is_ok());
        drop(third);
        let (fourth, msg) = bind(5001);
        worker.register_one(&mut engine, msg, &mut notifier);
        assert!(matches!(
            fourth.inbound_rx.pop(),
            Some(UdpInbound::Bound { .. })
        ));
        assert_eq!(engine.udp().pending_tx(), 6);
    }

    /// Notifications coalesce while queued, and an overflowed queue is
    /// recovered by the scan without losing a socket's work.
    #[test]
    fn notifications_coalesce_and_survive_overflow() {
        let (link, mut worker) = channel();
        let (mut notifier, ready) = app_wake::channel();
        let mut engine = engine();
        let (endpoints, msg) = binding(6000, None, &link.ready_tx, &link.overflow, &ready);
        worker.register_one(&mut engine, msg, &mut notifier);
        for n in 0..3 {
            assert!(send(&endpoints, n).is_ok());
        }
        worker.collect();
        assert_eq!(worker.work.len(), 1);
        worker.work.clear();
        worker.collect();
        assert!(worker.work.is_empty(), "an idle socket is not visited");

        for _ in 0..READY_CAP {
            assert!(link.ready_tx.push(1).is_ok());
        }
        assert!(send(&endpoints, 3).is_ok());
        assert!(link.overflow.load(Ordering::Acquire));
        worker.collect();
        assert!(worker.work.contains(&6000));
        worker.apply(&mut engine, &mut notifier);
        assert_eq!(engine.udp().pending_tx(), 4);
    }

    /// A bind abandoned before the worker registered it, whose drop
    /// notification the worker took (and dropped) before the bind itself:
    /// the registration visits it anyway, and unbinds it.
    #[test]
    fn a_bind_abandoned_before_registration_is_unbound() {
        let (link, mut worker) = channel();
        let (mut notifier, ready) = app_wake::channel();
        let mut engine = engine();
        let (endpoints, msg) = binding(7000, None, &link.ready_tx, &link.overflow, &ready);
        drop(endpoints);
        worker.collect();
        assert!(worker.work.is_empty(), "no socket yet: the wake is dropped");
        worker.register_one(&mut engine, msg, &mut notifier);
        assert!(engine.udp().is_bound(7000));
        worker.apply(&mut engine, &mut notifier);
        assert!(!engine.udp().is_bound(7000));
        assert!(worker.sockets.is_empty());
    }

    /// With less outbound room than busy senders, each still gets its
    /// turn: the room is shared and the first served rotates.
    #[test]
    fn outbound_room_is_shared_among_blocked_senders() {
        let (link, mut worker) = channel();
        let (mut notifier, ready) = app_wake::channel();
        let mut engine = engine();
        engine.udp_mut().set_outbound_capacity(1);
        let mut sockets = Vec::new();
        for port in [8000, 8001, 8002] {
            let (endpoints, msg) = binding(port, None, &link.ready_tx, &link.overflow, &ready);
            worker.register_one(&mut engine, msg, &mut notifier);
            let _ = endpoints.inbound_rx.pop();
            for n in 0..100 {
                assert!(send(&endpoints, n).is_ok());
            }
            sockets.push(endpoints);
        }
        // One slot of room per iteration, three senders: once they are all
        // waiting, each is served once in every three iterations, whatever
        // the hash order.
        let mut one_slot = |worker: &mut UdpWorker| {
            let pending = engine.udp().pending_tx();
            engine.udp_mut().set_outbound_capacity(pending + 1);
            worker.apply(&mut engine, &mut notifier);
        };
        one_slot(&mut worker);
        let start: Vec<usize> = sockets.iter().map(|e| e.cmd_tx.ring.len()).collect();
        for round in 1..=4 {
            for _ in 0..3 {
                one_slot(&mut worker);
            }
            for (endpoints, start) in sockets.iter().zip(&start) {
                assert_eq!(endpoints.cmd_tx.ring.len(), start - round, "round {round}");
            }
        }
    }

    /// A reader dropped while its ring holds datagrams: the worker drops
    /// its end too, so the ring and what is on it are freed now, not when
    /// the sender goes.
    #[test]
    fn a_dropped_reader_frees_its_inbound_ring() {
        let (link, mut worker) = channel();
        let (mut notifier, ready) = app_wake::channel();
        let mut engine = engine();
        let (endpoints, msg) = binding(9000, None, &link.ready_tx, &link.overflow, &ready);
        worker.register_one(&mut engine, msg, &mut notifier);
        worker.apply(&mut engine, &mut notifier);
        crate::dpdk::testing::init();
        let pool = crate::dpdk::Mempool::new(
            "udp-worker-reader-drop",
            63,
            0,
            crate::dpdk::mempool::DEFAULT_MBUF_DATA_ROOM_SIZE,
            -1,
        )
        .unwrap();
        let available = || unsafe { crate::dpdk::ffi::rte_mempool_avail_count(pool.as_raw()) };
        let free = available();
        let datagram = Datagram {
            src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9),
            dst: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000),
            data: crate::dpdk::MbufSlice::copy_from_slice(&pool, b"held").unwrap(),
        };
        assert_eq!(available(), free - 1);
        let inbound_tx = worker.sockets[&9000].inbound_tx.as_ref().unwrap();
        assert!(inbound_tx.push(UdpInbound::Datagram(datagram)).is_ok());
        let UdpEndpoints {
            cmd_tx, inbound_rx, ..
        } = endpoints;
        drop(inbound_rx);
        worker.apply(&mut engine, &mut notifier);
        assert!(worker.sockets[&9000].inbound_tx.is_none());
        assert!(engine.udp().is_bound(9000), "the sender still has it");
        assert_eq!(available(), free, "the datagram on the ring was freed");
        drop(cmd_tx);
        worker.apply(&mut engine, &mut notifier);
        assert!(!engine.udp().is_bound(9000));
    }
}

//! A thin, ergonomic handle around a connection's `FourTuple`. There's no
//! shared/interior-mutable state here on purpose: this stack is meant to
//! be driven from a single poll loop that owns the `TcpEngine` outright
//! (the standard DPDK run-to-completion model), so every operation just
//! takes `&mut TcpEngine` explicitly rather than hiding it behind
//! `Rc<RefCell<_>>`.

use bytes::Bytes;

use super::engine::TcpEngine;
use super::state::TcpState;
use super::tcb::FourTuple;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpSocket(pub FourTuple);

impl TcpSocket {
    pub fn connect(
        engine: &mut TcpEngine,
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
    ) -> Self {
        Self(engine.connect(remote_ip, remote_port, local_port))
    }

    /// Pops the next fully-established connection accepted on `port`, if
    /// any (non-blocking; call once per poll iteration).
    pub fn accept(engine: &mut TcpEngine, port: u16) -> Option<Self> {
        engine.accept(port).map(Self)
    }

    /// Queues `data` for sending. Takes `Bytes` so the payload travels to
    /// the wire by refcount rather than being copied into the send buffer.
    pub fn send(&self, engine: &mut TcpEngine, data: Bytes) {
        engine.send(self.0, data);
    }

    /// Non-blocking read of up to `max_len` bytes; returns an empty
    /// `Bytes` if nothing is available.
    pub fn recv(&self, engine: &mut TcpEngine, max_len: usize) -> Bytes {
        engine.recv(self.0, max_len)
    }

    pub fn readable_len(&self, engine: &TcpEngine) -> usize {
        engine.readable_len(self.0)
    }

    /// TCP_NODELAY: `true` disables Nagle's algorithm so sub-MSS
    /// segments are sent immediately instead of waiting for in-flight
    /// data to be acked. Default is Nagle on (like a kernel socket).
    pub fn set_nodelay(&self, engine: &mut TcpEngine, nodelay: bool) {
        engine.set_nodelay(self.0, nodelay);
    }

    /// TCP_CORK-style hold: while corked, full-MSS segments still go out
    /// as they fill, but the final partial segment is held until
    /// `flush()` releases it. Uncorking also releases it.
    pub fn set_cork(&self, engine: &mut TcpEngine, corked: bool) {
        engine.set_cork(self.0, corked);
    }

    /// Manual send trigger for a corked socket: releases the held tail
    /// segment now. One-shot -- data buffered afterward is held again
    /// until the next flush.
    pub fn flush(&self, engine: &mut TcpEngine) {
        engine.flush(self.0);
    }

    /// Initiates an orderly close (sends FIN once outstanding data has
    /// drained); does not block. Implicitly flushes any corked/held data.
    pub fn close(&self, engine: &mut TcpEngine) {
        engine.close(self.0);
    }

    pub fn state(&self, engine: &TcpEngine) -> Option<TcpState> {
        engine.state(self.0)
    }

    /// True once the connection is gone or fully closed (it may simply no
    /// longer be tracked by the engine at all, since closed connections
    /// are dropped once they leave TIME_WAIT).
    pub fn is_closed(&self, engine: &TcpEngine) -> bool {
        matches!(self.state(engine), None | Some(TcpState::Closed))
    }
}

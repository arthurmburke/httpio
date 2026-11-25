//! `UdpSocket`: datagrams over the DPDK stack, from application threads.
//!
//! A socket never touches the engine. Like a
//! [`TcpStream`](crate::dpdk::tcp::stream::TcpStream) it talks to its
//! worker only through rings (see [`super::worker`]): sends push commands,
//! receives pop datagrams that are views of the mbufs they arrived in.
//! Nothing is copied on either side unless the caller hands over a
//! borrowed slice.
//!
//! # Workers
//!
//! With several workers a socket is bound on the one worker whose queue
//! the NIC steers its port to, when it does steer it (an ephemeral port on
//! a device that took the UDP flow rules). Otherwise the port's datagrams
//! may reach any queue -- a well-known server port is spread by RSS -- so
//! the socket is bound on every worker and receives from all of them
//! (fan-in). It sends through the first. None of this shows in the API.
//!
//! # Waiting
//!
//! An operation that cannot proceed stores its waker, checks once more and
//! returns `Pending`, and the worker's driver task wakes it when the
//! worker changes something it may be waiting for: the same lost-wakeup-
//! safe scheme as `TcpStream` (see `crate::dpdk::tcp::app_wake`). Run it on
//! a `current_thread` tokio runtime; outside tokio a waiting socket wakes
//! itself.
//!
//! # Halves
//!
//! [`split`](UdpSocket::split) gives a [`UdpSender`], a
//! [`Sink`](futures::Sink), and a [`UdpReceiver`], a
//! [`Stream`](futures::Stream), which can be driven by different tasks or
//! threads. Each owns one end of each ring and its own wake handles. The
//! port stays bound until both are dropped.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;

use super::engine::{Datagram, UdpStats, UdpStatsSnapshot};
use super::worker::{UdpCmdTx, UdpCommand, UdpEndpoints, UdpInbound, UdpInboundRx};
use crate::dpdk::tcp::app_wake::{AppWake, Parker};
use crate::dpdk::tcp::worker::{OpenError, WorkerHandle};

/// Ports tried by [`UdpSocket::bind`] with port 0 before giving up.
const EPHEMERAL_ATTEMPTS: usize = 1024;

/// What both halves of a socket know about it, fixed at bind time.
struct Info {
    local: SocketAddrV4,
    max_payload: usize,
    /// One per worker the socket is bound on.
    stats: Box<[Arc<UdpStats>]>,
}

impl Info {
    fn stats(&self) -> UdpStatsSnapshot {
        self.stats.iter().map(|stats| stats.snapshot()).sum()
    }
}

/// A socket's sending end on one worker.
struct SendEnd {
    cmd: UdpCmdTx,
    wake: Parker,
}

/// A socket's receiving end on one worker.
struct RecvEnd {
    inbound: UdpInboundRx,
    wake: Parker,
    /// The worker closed the ring and everything on it has been read.
    finished: bool,
}

/// Stores `cx`'s waker in every wake handle, for the worker to wake. On
/// `false` nothing can wake the task (no tokio runtime to host the
/// driver), so it has been woken to poll again instead.
fn park<'a>(cx: &mut Context<'_>, wakes: impl Iterator<Item = &'a Arc<AppWake>>) -> bool {
    for wake in wakes {
        if !wake.park(cx.waker()) {
            cx.waker().wake_by_ref();
            return false;
        }
    }
    true
}

/// Try, park, try again: the second attempt sees whatever the worker did
/// between the first one and the waker being stored.
fn poll_parked<'a, T>(
    cx: &mut Context<'_>,
    wakes: impl Iterator<Item = &'a Arc<AppWake>>,
    mut attempt: impl FnMut() -> Poll<T>,
) -> Poll<T> {
    if let Poll::Ready(done) = attempt() {
        return Poll::Ready(done);
    }
    if !park(cx, wakes) {
        return Poll::Pending;
    }
    attempt()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn worker_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the UDP socket's worker stopped")
}

fn not_connected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "UDP socket has no peer: use send_to, or connect first",
    )
}

/// A UDP socket bound on the DPDK stack. See the [module docs](self).
pub struct UdpSocket {
    tx: UdpSender,
    rx: UdpReceiver,
}

/// The sending half of a [`UdpSocket`]; a [`Sink`](futures::Sink) of
/// `(payload, destination)`.
pub struct UdpSender {
    info: Arc<Info>,
    /// Datagrams go through the first; the others carry only peer filters.
    ends: Box<[SendEnd]>,
    peer: Option<SocketAddrV4>,
}

/// The receiving half of a [`UdpSocket`]; a [`Stream`](futures::Stream)
/// of datagrams, which ends when the worker stops.
pub struct UdpReceiver {
    info: Arc<Info>,
    ends: Box<[RecvEnd]>,
    /// The end to read first next time, so that no worker starves another.
    next: usize,
    peer: Option<SocketAddrV4>,
}

impl UdpSocket {
    /// Binds `local_port` on the stack behind `handle`, or with port 0 an
    /// ephemeral port (49152..=65535) not already bound. Resolves once
    /// every worker the socket goes to has bound it.
    ///
    /// Errors: `AddrInUse` if the port is bound already (on any of those
    /// workers), `WouldBlock` if a worker's control ring is full (it is
    /// overloaded or stalled), `BrokenPipe` if a worker stopped first.
    pub async fn bind(handle: &WorkerHandle, local_port: u16) -> io::Result<UdpSocket> {
        if local_port != 0 {
            return Self::bind_port(handle, local_port).await;
        }
        for _ in 0..EPHEMERAL_ATTEMPTS {
            match Self::bind_port(handle, handle.next_udp_port()).await {
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                other => return other,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no free ephemeral UDP port found",
        ))
    }

    async fn bind_port(handle: &WorkerHandle, local_port: u16) -> io::Result<UdpSocket> {
        let endpoints = handle
            .bind_udp(local_port, None)
            .map_err(|error| match error {
                OpenError::Busy | OpenError::PortNotSteered => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP worker control ring is full (worker overloaded or stalled)",
                ),
            })?;
        let local = SocketAddrV4::new(handle.local_ip(), local_port);
        let mut unbound = Unbound::new(endpoints, local);
        let max_payload = poll_fn(|cx| unbound.poll_bound(cx)).await?;
        Ok(unbound.into_socket(max_payload))
    }

    /// The local address: the stack's IP and the bound port.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.tx.local_addr()
    }

    /// The largest payload one datagram may carry: the port's MTU less
    /// the IPv4 and UDP headers (or less, if the stack's buffers are
    /// smaller). Larger sends are refused; nothing is ever fragmented.
    pub fn max_datagram_size(&self) -> usize {
        self.tx.max_datagram_size()
    }

    /// Counters for this socket, summed over the workers it is bound on.
    pub fn stats(&self) -> UdpStatsSnapshot {
        self.tx.stats()
    }

    /// The connected peer, if any.
    pub fn peer_addr(&self) -> Option<SocketAddrV4> {
        self.tx.peer
    }

    /// Sends `data` as one datagram to `dst`, without copying it. Waits
    /// while the socket's command ring is full. `InvalidInput` for a
    /// payload over [`max_datagram_size`](Self::max_datagram_size) or a
    /// destination with port 0 or address 0.0.0.0, `BrokenPipe` if the
    /// worker stopped.
    ///
    /// Done means handed to the worker, not transmitted: the datagram may
    /// still be dropped (and counted in `tx_dropped`) if its next hop does
    /// not resolve, as UDP may drop anything.
    pub async fn send_to(&mut self, data: Bytes, dst: SocketAddrV4) -> io::Result<()> {
        self.tx.send_to(data, dst).await
    }

    /// Poll form of [`send_to`](Self::send_to); `data` is taken once sent.
    pub fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
        dst: SocketAddrV4,
    ) -> Poll<io::Result<()>> {
        self.tx.poll_send_to(cx, data, dst)
    }

    /// [`send_to`](Self::send_to) without waiting: `WouldBlock` if the
    /// ring is full, in which case `data` was not queued.
    pub fn try_send_to(&mut self, data: Bytes, dst: SocketAddrV4) -> io::Result<()> {
        self.tx.try_send_to(data, dst)
    }

    /// [`send_to`](Self::send_to) for borrowed bytes, which are copied to
    /// the heap.
    pub async fn send_to_slice(&mut self, data: &[u8], dst: SocketAddrV4) -> io::Result<()> {
        self.tx.send_to_slice(data, dst).await
    }

    /// Receives the next datagram, a view of the mbuf it arrived in.
    /// `NotConnected` once the worker has stopped and everything it
    /// delivered has been read.
    pub async fn recv_from(&mut self) -> io::Result<Datagram> {
        self.rx.recv_from().await
    }

    /// Poll form of [`recv_from`](Self::recv_from).
    pub fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Datagram>> {
        self.rx.poll_recv_from(cx)
    }

    /// [`recv_from`](Self::recv_from) without waiting: `WouldBlock` if no
    /// datagram is there.
    pub fn try_recv_from(&mut self) -> io::Result<Datagram> {
        self.rx.try_recv_from()
    }

    /// Receives the next datagram into `buf`, returning its length and
    /// sender. A datagram longer than `buf` is truncated and the rest of
    /// it discarded, as the kernel does.
    pub async fn recv_from_buf(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        self.rx.recv_from_buf(buf).await
    }

    /// Sets the socket's peer: [`send`](Self::send) goes to it, and only
    /// datagrams from it are received -- the workers drop others on
    /// arrival, and any already queued are skipped. Waits for ring space
    /// on every worker the socket is bound on.
    pub async fn connect(&mut self, peer: SocketAddrV4) -> io::Result<()> {
        if peer.port() == 0 || peer.ip().is_unspecified() {
            return Err(invalid("invalid UDP peer address"));
        }
        let mut next = 0;
        let tx = &self.tx;
        poll_fn(|cx| {
            poll_parked(cx, tx.ends.iter().map(|end| &end.wake.0), || {
                tx.try_connect(Some(peer), &mut next)
            })
        })
        .await?;
        self.tx.peer = Some(peer);
        self.rx.peer = Some(peer);
        Ok(())
    }

    /// Clears the peer [`connect`](Self::connect) set: [`send`](Self::send)
    /// fails with `NotConnected` again, and datagrams from any source are
    /// received (those the workers dropped while connected stay dropped).
    /// Waits for ring space on every worker the socket is bound on.
    pub async fn disconnect(&mut self) -> io::Result<()> {
        let mut next = 0;
        let tx = &self.tx;
        poll_fn(|cx| {
            poll_parked(cx, tx.ends.iter().map(|end| &end.wake.0), || {
                tx.try_connect(None, &mut next)
            })
        })
        .await?;
        self.tx.peer = None;
        self.rx.peer = None;
        Ok(())
    }

    /// Sends to the connected peer; `NotConnected` without one.
    pub async fn send(&mut self, data: Bytes) -> io::Result<()> {
        self.tx.send(data).await
    }

    /// Receives from the connected peer (any sender if not connected).
    pub async fn recv(&mut self) -> io::Result<Datagram> {
        self.rx.recv_from().await
    }

    /// Splits the socket into halves that can be used independently.
    pub fn split(self) -> (UdpSender, UdpReceiver) {
        (self.tx, self.rx)
    }
}

/// A socket whose workers have not all replied to its bind yet. Dropped
/// on failure, which closes its rings and so unbinds it on the workers
/// that did bind it.
struct Unbound {
    send: Vec<SendEnd>,
    recv: Vec<RecvEnd>,
    stats: Box<[Arc<UdpStats>]>,
    local: SocketAddrV4,
    /// Each worker's payload limit, once it has replied.
    limits: Vec<Option<usize>>,
}

impl Unbound {
    fn new(endpoints: Vec<UdpEndpoints>, local: SocketAddrV4) -> Self {
        let stats = endpoints.iter().map(|e| e.stats.clone()).collect();
        let limits = vec![None; endpoints.len()];
        let (send, recv) = endpoints
            .into_iter()
            .map(|e| {
                (
                    SendEnd {
                        cmd: e.cmd_tx,
                        wake: Parker(e.send_wake),
                    },
                    RecvEnd {
                        inbound: e.inbound_rx,
                        wake: Parker(e.recv_wake),
                        finished: false,
                    },
                )
            })
            .unzip();
        Self {
            send,
            recv,
            stats,
            local,
            limits,
        }
    }

    /// Ready with the smallest payload limit once every worker has bound
    /// the port; an error as soon as one refuses or is gone.
    fn poll_bound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let (recv, limits) = (&self.recv, &mut self.limits);
        poll_parked(cx, recv.iter().map(|end| &end.wake.0), || {
            Self::try_bound(recv, limits)
        })
    }

    fn try_bound(ends: &[RecvEnd], limits: &mut [Option<usize>]) -> Poll<io::Result<usize>> {
        for (end, limit) in ends.iter().zip(limits.iter_mut()) {
            if limit.is_some() {
                continue;
            }
            let closed = end.inbound.is_closed();
            match end.inbound.pop() {
                Some(UdpInbound::Bound { max_payload }) => *limit = Some(max_payload),
                Some(UdpInbound::AddrInUse) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "UDP port already bound",
                    )));
                }
                // The worker registers the socket, and so delivers to it,
                // only after pushing its reply.
                Some(UdpInbound::Datagram(_)) => unreachable!("datagram before the bind reply"),
                None if closed => return Poll::Ready(Err(worker_gone())),
                None => {}
            }
        }
        let mut least = usize::MAX;
        for limit in limits.iter() {
            match limit {
                Some(limit) => least = least.min(*limit),
                None => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(least))
    }

    fn into_socket(self, max_payload: usize) -> UdpSocket {
        let info = Arc::new(Info {
            local: self.local,
            max_payload,
            stats: self.stats,
        });
        UdpSocket {
            tx: UdpSender {
                info: info.clone(),
                ends: self.send.into(),
                peer: None,
            },
            rx: UdpReceiver {
                info,
                ends: self.recv.into(),
                next: 0,
                peer: None,
            },
        }
    }
}

impl UdpSender {
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.info.local
    }

    /// See [`UdpSocket::max_datagram_size`].
    pub fn max_datagram_size(&self) -> usize {
        self.info.max_payload
    }

    /// See [`UdpSocket::stats`].
    pub fn stats(&self) -> UdpStatsSnapshot {
        self.info.stats()
    }

    /// The peer [`send`](Self::send) goes to, set by
    /// [`UdpSocket::connect`] before the split.
    pub fn peer_addr(&self) -> Option<SocketAddrV4> {
        self.peer
    }

    fn check(&self, len: usize, dst: SocketAddrV4) -> io::Result<()> {
        if dst.port() == 0 || dst.ip().is_unspecified() {
            return Err(invalid("invalid UDP destination address"));
        }
        if len > self.info.max_payload {
            return Err(invalid("datagram larger than max_datagram_size"));
        }
        Ok(())
    }

    /// Whether a datagram can be queued now.
    fn try_ready(&self) -> Poll<io::Result<()>> {
        let cmd = &self.ends[0].cmd;
        if cmd.is_closed() {
            Poll::Ready(Err(worker_gone()))
        } else if cmd.is_full() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Ready once a datagram can be queued without waiting (or the worker
    /// is gone, an error).
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let wake = &self.ends[0].wake.0;
        let this = &*self;
        poll_parked(cx, std::iter::once(wake), || this.try_ready())
    }

    /// Queues a datagram after `try_ready` found room. The ring has one
    /// producer, this half, so the room is still there.
    fn push(&mut self, data: Bytes, dst: SocketAddrV4) -> io::Result<()> {
        self.ends[0]
            .cmd
            .push(UdpCommand::SendTo { dst, data })
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }

    /// See [`UdpSocket::send_to`].
    pub async fn send_to(&mut self, data: Bytes, dst: SocketAddrV4) -> io::Result<()> {
        let mut data = Some(data);
        poll_fn(|cx| self.poll_send_to(cx, &mut data, dst)).await
    }

    /// See [`UdpSocket::poll_send_to`].
    pub fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
        dst: SocketAddrV4,
    ) -> Poll<io::Result<()>> {
        let len = data
            .as_ref()
            .expect("poll_send_to polled without a payload")
            .len();
        if let Err(error) = self.check(len, dst) {
            return Poll::Ready(Err(error));
        }
        match self.poll_send_ready(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let data = data.take().expect("checked above");
        Poll::Ready(self.push(data, dst))
    }

    /// See [`UdpSocket::try_send_to`].
    pub fn try_send_to(&mut self, data: Bytes, dst: SocketAddrV4) -> io::Result<()> {
        self.check(data.len(), dst)?;
        match self.try_ready() {
            Poll::Ready(Ok(())) => self.push(data, dst),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// See [`UdpSocket::send_to_slice`]. The copy is made only once there
    /// is room to queue it.
    pub async fn send_to_slice(&mut self, data: &[u8], dst: SocketAddrV4) -> io::Result<()> {
        self.check(data.len(), dst)?;
        poll_fn(|cx| self.poll_send_ready(cx)).await?;
        // To the heap, never to a `DmaWriter`: its `copy` may return a
        // short prefix, and a datagram is never split. Nor would DMA memory
        // help here: a datagram that fits one mbuf is copied into it by the
        // engine, which costs less than attaching it (see `build_udp_frame`).
        // Shared from the start, so the worker never allocates a refcount
        // for it (see `TcpStream`'s writes).
        self.push(Bytes::from_owner(data.to_vec()), dst)
    }

    /// Sends to the connected peer; `NotConnected` without one.
    pub async fn send(&mut self, data: Bytes) -> io::Result<()> {
        let peer = self.peer.ok_or_else(not_connected)?;
        self.send_to(data, peer).await
    }

    /// Pushes `Connect(peer)` to every worker from `next` on, stopping at
    /// a full ring (to resume there).
    fn try_connect(&self, peer: Option<SocketAddrV4>, next: &mut usize) -> Poll<io::Result<()>> {
        while let Some(end) = self.ends.get(*next) {
            if end.cmd.is_closed() {
                return Poll::Ready(Err(worker_gone()));
            }
            if end.cmd.push(UdpCommand::Connect(peer)).is_err() {
                return Poll::Pending;
            }
            *next += 1;
        }
        Poll::Ready(Ok(()))
    }
}

impl UdpReceiver {
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.info.local
    }

    /// See [`UdpSocket::stats`].
    pub fn stats(&self) -> UdpStatsSnapshot {
        self.info.stats()
    }

    /// One pass over the workers' rings, starting where the last one
    /// found a datagram.
    fn try_recv(&mut self) -> Poll<io::Result<Datagram>> {
        let count = self.ends.len();
        let peer = self.peer;
        let mut finished = 0;
        for i in 0..count {
            let index = (self.next + i) % count;
            let end = &mut self.ends[index];
            if end.finished {
                finished += 1;
                continue;
            }
            let closed = end.inbound.is_closed();
            loop {
                match end.inbound.pop() {
                    Some(UdpInbound::Datagram(datagram)) => {
                        // Queued before the worker applied the filter. Not
                        // counted: the stats belong to the worker.
                        if peer.is_some_and(|peer| peer != datagram.src) {
                            continue;
                        }
                        self.next = (index + 1) % count;
                        return Poll::Ready(Ok(datagram));
                    }
                    // Only the first message is a bind reply.
                    Some(UdpInbound::Bound { .. } | UdpInbound::AddrInUse) => continue,
                    None => {
                        if closed {
                            end.finished = true;
                            finished += 1;
                        }
                        break;
                    }
                }
            }
        }
        if finished == count {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the UDP socket's worker stopped",
            )));
        }
        Poll::Pending
    }

    /// See [`UdpSocket::recv_from`].
    pub async fn recv_from(&mut self) -> io::Result<Datagram> {
        poll_fn(|cx| self.poll_recv_from(cx)).await
    }

    /// See [`UdpSocket::poll_recv_from`]. With fan-in it parks on every
    /// worker's wake handle, since any of them may deliver next.
    pub fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Datagram>> {
        if let Poll::Ready(done) = self.try_recv() {
            return Poll::Ready(done);
        }
        if !park(cx, self.ends.iter().map(|end| &end.wake.0)) {
            return Poll::Pending;
        }
        self.try_recv()
    }

    /// See [`UdpSocket::try_recv_from`].
    pub fn try_recv_from(&mut self) -> io::Result<Datagram> {
        match self.try_recv() {
            Poll::Ready(done) => done,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// See [`UdpSocket::recv_from_buf`].
    pub async fn recv_from_buf(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let datagram = self.recv_from().await?;
        let n = datagram.data.len().min(buf.len());
        buf[..n].copy_from_slice(&datagram.data[..n]);
        Ok((n, datagram.src))
    }

    /// See [`UdpSocket::recv`].
    pub async fn recv(&mut self) -> io::Result<Datagram> {
        self.recv_from().await
    }
}

/// Datagrams are queued as they are sent, so there is never anything to
/// flush: `poll_flush` and `poll_close` are ready at once. (The port stays
/// bound until the receiver is dropped too.)
impl futures::Sink<(Bytes, SocketAddrV4)> for UdpSender {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_send_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, (data, dst): (Bytes, SocketAddrV4)) -> io::Result<()> {
        let this = self.get_mut();
        this.check(data.len(), dst)?;
        this.push(data, dst)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Ends (`None`) once the worker has stopped and every datagram it
/// delivered has been read.
impl futures::Stream for UdpReceiver {
    type Item = io::Result<Datagram>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.poll_recv_from(cx) {
            Poll::Ready(Ok(datagram)) => Poll::Ready(Some(Ok(datagram))),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::NotConnected => {
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mpsc;
    use crate::core::spsc::{SpscRx, SpscTx};
    use crate::dpdk::tcp::app_wake::{self, AppNotifier};
    use crate::dpdk::testing::slice;
    use crate::dpdk::udp::worker::{CMD_CAP, IN_CAP, NewUdpBinding, binding};
    use futures::{SinkExt, StreamExt};
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;

    const LOCAL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
    const PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6000);
    const OTHER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 6000);

    /// The worker's ends of one socket's rings on one worker.
    struct WorkerEnds {
        cmd_rx: SpscRx<UdpCommand, CMD_CAP>,
        inbound_tx: SpscTx<UdpInbound, IN_CAP>,
        recv_wake: Arc<AppWake>,
        send_wake: Arc<AppWake>,
        notifier: AppNotifier,
    }

    /// Ends on `workers` workers played by the test, with the bind not
    /// yet replied to.
    fn unbound(workers: usize) -> (Unbound, Vec<WorkerEnds>) {
        let (ready_tx, _ready_rx) = mpsc::channel();
        let overflow = Arc::new(AtomicBool::new(false));
        let mut endpoints = Vec::new();
        let mut ends = Vec::new();
        for _ in 0..workers {
            let (notifier, ready) = app_wake::channel();
            let (e, msg) = binding(LOCAL.port(), None, &ready_tx, &overflow, &ready);
            let NewUdpBinding {
                cmd_rx,
                inbound_tx,
                send_wake,
                recv_wake,
                ..
            } = msg;
            endpoints.push(e);
            ends.push(WorkerEnds {
                cmd_rx,
                inbound_tx,
                recv_wake,
                send_wake,
                notifier,
            });
        }
        (Unbound::new(endpoints, LOCAL), ends)
    }

    /// A socket bound on `workers` workers played by the test, with a
    /// payload limit of 1472.
    fn socket(workers: usize) -> (UdpSocket, Vec<WorkerEnds>) {
        let (mut unbound, ends) = unbound(workers);
        for end in &ends {
            let bound = UdpInbound::Bound { max_payload: 1472 };
            assert!(end.inbound_tx.push(bound).is_ok());
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok(max)) = unbound.poll_bound(&mut cx) else {
            panic!("bound")
        };
        (unbound.into_socket(max), ends)
    }

    fn datagram(src: SocketAddrV4, payload: &[u8]) -> UdpInbound {
        UdpInbound::Datagram(Datagram {
            src,
            dst: LOCAL,
            data: slice(payload),
        })
    }

    fn sent(cmd: Option<UdpCommand>) -> (SocketAddrV4, Bytes) {
        match cmd {
            Some(UdpCommand::SendTo { dst, data }) => (dst, data),
            _ => panic!("expected a SendTo"),
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    /// The worker pushes and then notifies, from another thread, while the
    /// reader waits: every datagram arrives, in order.
    #[test]
    fn a_waiting_receiver_never_misses_datagrams_pushed_from_another_thread() {
        const DATAGRAMS: u32 = 200_000;
        let (socket, mut ends) = socket(1);
        let WorkerEnds {
            cmd_rx,
            inbound_tx,
            recv_wake,
            mut notifier,
            ..
        } = ends.pop().unwrap();
        let (_tx, mut rx) = socket.split();
        let worker = std::thread::spawn(move || {
            let _cmd_rx = cmd_rx;
            let mut next = 0u32;
            while next < DATAGRAMS {
                notifier.retry();
                let Some(data) = crate::dpdk::testing::try_slice(&next.to_be_bytes()) else {
                    std::hint::spin_loop();
                    continue;
                };
                let msg = UdpInbound::Datagram(Datagram {
                    src: PEER,
                    dst: LOCAL,
                    data,
                });
                if inbound_tx.push(msg).is_ok() {
                    notifier.notify(&recv_wake);
                    next += 1;
                    if next.is_multiple_of(61) {
                        for _ in 0..500 {
                            std::hint::spin_loop();
                        }
                    }
                } else {
                    std::hint::spin_loop();
                }
            }
            notifier.flush();
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            runtime().block_on(async {
                for expected in 0..DATAGRAMS {
                    let datagram = rx.recv_from().await.unwrap();
                    assert_eq!(datagram.src, PEER);
                    assert_eq!(&datagram.data[..], &expected.to_be_bytes());
                }
            });
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the receiver stalled: a wake-up was lost");
        worker.join().unwrap();
    }

    /// Fan-in: datagrams from every worker are read, none starved, and the
    /// stream ends only once every worker's ring is closed and drained.
    #[test]
    fn a_fan_in_receiver_reads_every_worker_and_ends_with_the_last() {
        let (socket, mut ends) = socket(3);
        let (_tx, mut rx) = socket.split();
        for (i, end) in ends.iter().enumerate() {
            for n in 0..2u8 {
                assert!(end.inbound_tx.push(datagram(PEER, &[i as u8, n])).is_ok());
            }
        }
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(rx.try_recv_from().unwrap().data.to_vec());
        }
        // Round-robin: one from each worker before a second from any.
        assert_eq!(
            seen,
            [[0, 0], [1, 0], [2, 0], [0, 1], [1, 1], [2, 1]].map(Vec::from)
        );
        assert_eq!(
            rx.try_recv_from().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        // Two workers stop; the third still delivers.
        let last = ends.pop().unwrap();
        ends.clear();
        assert!(last.inbound_tx.push(datagram(PEER, b"late")).is_ok());
        runtime().block_on(async {
            assert_eq!(&rx.next().await.unwrap().unwrap().data[..], b"late");
            drop(last);
            assert!(
                rx.next().await.is_none(),
                "the stream ends with the workers"
            );
        });
        assert_eq!(
            rx.try_recv_from().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn sends_are_checked_queued_in_order_and_wait_for_ring_space() {
        let (mut socket, ends) = socket(1);
        assert_eq!(socket.max_datagram_size(), 1472);
        assert_eq!(socket.local_addr(), LOCAL);

        let too_large = Bytes::from(vec![0; 1473]);
        let error = socket.try_send_to(too_large, PEER).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        for bad in [
            SocketAddrV4::new(*PEER.ip(), 0),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9),
        ] {
            let error = socket.try_send_to(Bytes::new(), bad).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(ends[0].cmd_rx.is_empty(), "nothing invalid is queued");

        assert!(socket.try_send_to(Bytes::from(vec![7; 1472]), PEER).is_ok());
        assert!(socket.try_send_to(Bytes::new(), PEER).is_ok());
        assert_eq!(sent(ends[0].cmd_rx.pop()).1.len(), 1472);
        assert_eq!(sent(ends[0].cmd_rx.pop()), (PEER, Bytes::new()));

        // A full ring: try fails, a send waits until the worker takes one.
        let mut n = 0u32;
        while socket
            .try_send_to(Bytes::copy_from_slice(&n.to_be_bytes()), PEER)
            .is_ok()
        {
            n += 1;
        }
        assert_eq!(n as usize, CMD_CAP - 1);
        let (mut tx, _rx) = socket.split();
        let WorkerEnds {
            cmd_rx,
            send_wake,
            mut notifier,
            ..
        } = ends.into_iter().next().unwrap();
        runtime().block_on(async {
            let worker = tokio::spawn(async move {
                tokio::task::yield_now().await;
                let mut received = Vec::new();
                while received.len() < CMD_CAP {
                    match cmd_rx.pop() {
                        Some(cmd) => {
                            received.push(sent(Some(cmd)).1);
                            notifier.notify(&send_wake);
                        }
                        None => tokio::task::yield_now().await,
                    }
                }
                received
            });
            tx.send_to_slice(b"last", PEER).await.unwrap();
            let received = worker.await.unwrap();
            for (i, data) in received[..CMD_CAP - 1].iter().enumerate() {
                assert_eq!(&data[..], &(i as u32).to_be_bytes());
            }
            assert_eq!(&received[CMD_CAP - 1][..], b"last");
        });
    }

    #[test]
    fn the_sink_queues_datagrams_and_rejects_oversized_ones() {
        let (socket, ends) = socket(1);
        let (mut tx, _rx) = socket.split();
        runtime().block_on(async {
            // `SinkExt::send`: the inherent `send` is to the peer.
            SinkExt::send(&mut tx, (Bytes::from_static(b"one"), PEER))
                .await
                .unwrap();
            tx.feed((Bytes::from_static(b"two"), OTHER)).await.unwrap();
            tx.flush().await.unwrap();
            let error = SinkExt::send(&mut tx, (Bytes::from(vec![0; 1473]), PEER))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        });
        assert_eq!(
            sent(ends[0].cmd_rx.pop()),
            (PEER, Bytes::from_static(b"one"))
        );
        assert_eq!(
            sent(ends[0].cmd_rx.pop()),
            (OTHER, Bytes::from_static(b"two"))
        );
        assert!(ends[0].cmd_rx.pop().is_none());

        // The worker gone: sends fail rather than wait.
        drop(ends);
        let error = tx.try_send_to(Bytes::new(), PEER).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    /// `connect` tells every worker, then `send` goes to the peer and only
    /// the peer's datagrams are received, even those queued before.
    #[test]
    fn a_connected_socket_talks_only_to_its_peer() {
        let (mut socket, ends) = socket(2);
        runtime().block_on(async {
            let error = socket.send(Bytes::from_static(b"x")).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            assert!(ends[0].inbound_tx.push(datagram(OTHER, b"other")).is_ok());
            assert!(ends[1].inbound_tx.push(datagram(PEER, b"peer")).is_ok());

            socket.connect(PEER).await.unwrap();
            for end in &ends {
                assert!(matches!(
                    end.cmd_rx.pop(),
                    Some(UdpCommand::Connect(Some(peer))) if peer == PEER
                ));
            }
            socket.send(Bytes::from_static(b"hi")).await.unwrap();
            assert_eq!(
                sent(ends[0].cmd_rx.pop()),
                (PEER, Bytes::from_static(b"hi"))
            );
            assert!(ends[1].cmd_rx.is_empty(), "sends use the first worker");
            assert_eq!(socket.peer_addr(), Some(PEER));
            let received = socket.recv().await.unwrap();
            assert_eq!((received.src, &received.data[..]), (PEER, &b"peer"[..]));

            // Disconnected: every worker is told, and any source is
            // received again.
            socket.disconnect().await.unwrap();
            for end in &ends {
                assert!(matches!(end.cmd_rx.pop(), Some(UdpCommand::Connect(None))));
            }
            assert_eq!(socket.peer_addr(), None);
            let error = socket.send(Bytes::from_static(b"x")).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            assert!(ends[1].inbound_tx.push(datagram(OTHER, b"any")).is_ok());
            let received = socket.recv().await.unwrap();
            assert_eq!((received.src, &received.data[..]), (OTHER, &b"any"[..]));
        });
    }

    #[test]
    fn a_short_buffer_truncates_the_datagram() {
        let (mut socket, ends) = socket(1);
        assert!(
            ends[0]
                .inbound_tx
                .push(datagram(PEER, b"0123456789"))
                .is_ok()
        );
        assert!(ends[0].inbound_tx.push(datagram(PEER, b"ab")).is_ok());
        runtime().block_on(async {
            let mut buf = [0u8; 4];
            assert_eq!(socket.recv_from_buf(&mut buf).await.unwrap(), (4, PEER));
            assert_eq!(&buf, b"0123");
            // The rest of the first is gone; the next is whole.
            assert_eq!(socket.recv_from_buf(&mut buf).await.unwrap(), (2, PEER));
            assert_eq!(&buf[..2], b"ab");
        });
        assert_eq!(ends[0].inbound_tx.len(), 0);
    }

    /// Without a tokio runtime nothing can wake a parked socket, so it
    /// wakes itself.
    #[test]
    fn without_a_runtime_a_waiting_socket_keeps_itself_awake() {
        let (mut socket, _ends) = socket(1);
        struct Count(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let count = Arc::new(Count(std::sync::atomic::AtomicUsize::new(0)));
        let waker = std::task::Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(socket.poll_recv_from(&mut cx).is_pending());
        assert_eq!(count.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A worker's refusal fails the bind, and a worker that stops before
    /// replying does too; the smallest limit of those that bound wins.
    #[test]
    fn a_bind_fails_on_any_refusal_or_a_worker_gone() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for reply in [Some(UdpInbound::AddrInUse), None] {
            let (mut unbound, mut ends) = unbound(2);
            let first = UdpInbound::Bound { max_payload: 1472 };
            assert!(ends[0].inbound_tx.push(first).is_ok());
            assert!(unbound.poll_bound(&mut cx).is_pending());
            let expected = match reply {
                Some(reply) => {
                    assert!(ends[1].inbound_tx.push(reply).is_ok());
                    io::ErrorKind::AddrInUse
                }
                None => {
                    ends.pop();
                    io::ErrorKind::BrokenPipe
                }
            };
            let Poll::Ready(Err(error)) = unbound.poll_bound(&mut cx) else {
                panic!("the bind must fail");
            };
            assert_eq!(error.kind(), expected);
        }
        let (mut unbound, ends) = unbound(2);
        for (end, max_payload) in ends.iter().zip([1472, 1400]) {
            assert!(
                end.inbound_tx
                    .push(UdpInbound::Bound { max_payload })
                    .is_ok()
            );
        }
        assert!(matches!(unbound.poll_bound(&mut cx), Poll::Ready(Ok(1400))));
    }
}

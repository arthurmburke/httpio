//! `TcpStream`: tokio `AsyncRead`/`AsyncWrite` over a connection managed
//! by the TCP engine on the worker lcore. All I/O crosses the core
//! boundary through this connection's SPSC ring pair (see
//! `crate::tcp::worker`): writes push `Command`s, reads pop `Inbound`
//! messages. There is no lock and no shared engine access on this side.
//!
//! Zero-copy path: [`AsyncRead`]/[`AsyncWrite`] must copy (a borrowed write
//! slice into an owned `Bytes`, an owned `Bytes` into the caller's read
//! buffer), so a caller that already holds -- or wants -- owned [`Bytes`] can
//! use [`send`](TcpStream::send)/[`recv`](TcpStream::recv) instead, which move
//! the `Bytes` straight across the ring with no copy at this boundary. hyper's
//! header/handshake framing keeps using the `AsyncRead`/`AsyncWrite` impls.
//!
//! Busy-poll: when a read has no data yet (or a write can't enqueue
//! because the command ring is momentarily full), the poll self-wakes and
//! returns `Pending`, so the task re-polls promptly. This matches DPDK's
//! run-to-completion model and pairs with the worker lcore likewise
//! spinning. Run the client on a `current_thread` tokio runtime.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::dpdk::tcp::worker::{CmdTx, Command, Inbound, InboundRx, WorkerHandle};

/// Per-connection TCP transport options. Attach to an HTTP request via
/// `http::Extensions` (`request.extensions_mut().insert(TcpOptions {..})`)
/// to control the connection that request uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpOptions {
    /// TCP_NODELAY: disable Nagle's algorithm so sub-MSS segments go out
    /// immediately. Defaults to `true`, like mainstream HTTP clients;
    /// set `false` to let Nagle coalesce small writes.
    pub nodelay: bool,
    /// TCP_CORK-style hold with a *manual* release: the bulk of the
    /// request flows as full-MSS segments, but the final sub-MSS tail is
    /// held back until an explicit [`FlushHandle::flush`] (or the
    /// connection closes, which flushes implicitly). The cork is applied
    /// at connect time, so the TCP/TLS handshakes are unaffected. Since a
    /// manually-held tail is incompatible with a shared multiplexed
    /// connection, corked `https` requests negotiate HTTP/1.1 and are
    /// never pooled. Takes precedence over `nodelay`.
    pub cork: bool,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            nodelay: true,
            cork: false,
        }
    }
}

/// The manual release trigger for a corked request. Create one, clone it
/// into the request's extensions, start the request, and call
/// [`flush`](Self::flush) whenever the held tail should go out.
///
/// It carries a lock-free flag rather than a channel: the paired
/// `TcpStream` observes the flag while it polls and enqueues the actual
/// `Flush` command itself, so the flush stays correctly ordered *after*
/// the request bytes it releases, and the handle stays `Send + Sync`
/// (required to live in `http::Extensions`) without any lock.
///
/// ```ignore
/// let flush = FlushHandle::new();
/// request.extensions_mut().insert(TcpOptions { cork: true, ..Default::default() });
/// request.extensions_mut().insert(flush.clone());
/// let response = client.request(request); // most of the request is on the wire, tail held
/// // ... when ready ...
/// flush.flush(); // release the final segment; the server can now respond
/// ```
#[derive(Clone, Default)]
pub struct FlushHandle {
    requested: Arc<AtomicBool>,
}

impl FlushHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests release of the connection's held tail segment. Fire and
    /// forget: the paired `TcpStream` picks this up on its next poll and
    /// enqueues the flush (ordered after any pending writes). Calling
    /// before the connection exists is fine -- it takes effect once the
    /// request starts.
    pub fn flush(&self) {
        self.requested.store(true, Ordering::Release);
    }

    fn cell(&self) -> Arc<AtomicBool> {
        self.requested.clone()
    }
}

pub struct TcpStream {
    cmd_tx: CmdTx,
    inbound_rx: InboundRx,
    /// Shared with a user `FlushHandle`; observed on each poll to enqueue
    /// an ordered `Command::Flush`.
    flush: Option<Arc<AtomicBool>>,
    /// Handshake completed (worker sent `Established`).
    established: bool,
    /// In-order received chunks not yet delivered to the reader (copied out
    /// by `poll_read`, or handed over as-is by `poll_recv`).
    read_queue: VecDeque<Bytes>,
    /// Peer finished sending; deliver EOF once `read_queue` drains.
    got_eof: bool,
    /// Connection was reset; surface as an error on the next empty read.
    got_reset: bool,
}

impl TcpStream {
    /// Opens a connection via the worker and resolves once the handshake
    /// completes (or errors with `ConnectionRefused` on RST/timeout).
    pub async fn connect(
        worker: &WorkerHandle,
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
        options: TcpOptions,
        flush: Option<&FlushHandle>,
    ) -> io::Result<Self> {
        let endpoints = worker
            .open(remote_ip, remote_port, local_port, options.nodelay)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "TCP worker control ring is full (worker overloaded or stalled)",
                )
            })?;

        let mut stream = Self {
            cmd_tx: endpoints.cmd_tx,
            inbound_rx: endpoints.inbound_rx,
            flush: flush.map(FlushHandle::cell),
            established: false,
            read_queue: VecDeque::new(),
            got_eof: false,
            got_reset: false,
        };
        poll_fn(|cx| stream.poll_established(cx)).await?;
        Ok(stream)
    }

    /// Enables TCP_CORK on this connection. Must be called *after* the TLS
    /// handshake (if any) and before writing the request body: corking
    /// earlier would hold the sub-MSS handshake records. The command is
    /// ordered ahead of subsequent writes on the same ring.
    pub fn request_cork(&self) {
        // Best-effort: the command ring is empty right after connect, so a
        // single push cannot fail here in practice.
        let _ = self.cmd_tx.push(Command::SetCork(true));
    }

    /// Zero-copy write: hands owned `data` straight to the worker as a
    /// `Command::Send`, avoiding the copy the [`AsyncWrite`] path is forced to
    /// make from its borrowed `&[u8]`. Busy-polls (self-waking) while the
    /// command ring is full; errors if the connection was reset.
    ///
    /// Ordering matches the write ring -- these bytes queue behind anything
    /// already written, and a pending cork flush is released once they land.
    pub async fn send(&mut self, data: Bytes) -> io::Result<()> {
        let mut data = Some(data);
        poll_fn(|cx| self.poll_send(cx, &mut data)).await
    }

    /// Poll form of [`send`](Self::send). On success `data` is taken; while
    /// the command ring is full it is left in place for the next poll.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        self.drain_inbound();
        if self.got_reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let bytes = data.take().expect("poll_send polled without a payload");
        match self.cmd_tx.push(Command::Send(bytes)) {
            Ok(()) => {
                self.drain_flush();
                Poll::Ready(Ok(()))
            }
            // Ring full: recover the payload so the caller retries the move.
            Err(Command::Send(bytes)) => {
                *data = Some(bytes);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_) => unreachable!("only Command::Send is pushed here"),
        }
    }

    /// Zero-copy read: pops the next received chunk as owned [`Bytes`] (a
    /// refcounted view), avoiding the copy the [`AsyncRead`] path is forced to
    /// make into the caller's `ReadBuf`. `Ok(None)` is a clean EOF; busy-polls
    /// (self-waking) until a chunk, EOF, or reset is available.
    pub async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Poll form of [`recv`](Self::recv). Buffered data is delivered before a
    /// reset is surfaced, matching [`AsyncRead`].
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        self.drain_flush();
        self.drain_inbound();
        if let Some(chunk) = self.read_queue.pop_front() {
            return Poll::Ready(Ok(Some(chunk)));
        }
        if self.got_reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if self.got_eof {
            // Clean EOF.
            return Poll::Ready(Ok(None));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_established(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain_inbound();
        if self.got_reset {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused or reset during handshake",
            )));
        }
        // The worker emits `Established` before any data, so once we've
        // seen the connection produce anything (data queued or EOF) or an
        // explicit ready signal, it's usable. `Established` itself is
        // consumed in drain_inbound; track readiness via a dedicated flag.
        if self.established {
            Poll::Ready(Ok(()))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// Drains all currently-available inbound messages into local state.
    fn drain_inbound(&mut self) {
        while let Some(msg) = self.inbound_rx.pop() {
            match msg {
                Inbound::Established => self.established = true,
                Inbound::Data(bytes) => {
                    if !bytes.is_empty() {
                        self.read_queue.push_back(bytes);
                    }
                }
                Inbound::Eof => self.got_eof = true,
                Inbound::Reset | Inbound::ConnectFailed => {
                    self.got_reset = true;
                    self.got_eof = true;
                }
            }
        }
        // If the worker dropped its inbound sender (connection reaped),
        // treat as EOF so a stuck reader unblocks.
        if self.inbound_rx.is_closed() {
            self.got_eof = true;
        }
    }

    /// If the user requested a flush, enqueue it now (ordered after any
    /// writes already pushed). Re-arms on a full command ring so it isn't
    /// lost.
    fn drain_flush(&self) {
        if let Some(cell) = &self.flush
            && cell.swap(false, Ordering::AcqRel)
            && self.cmd_tx.push(Command::Flush).is_err()
        {
            cell.store(true, Ordering::Release);
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.drain_flush();
        this.drain_inbound();

        // Copy as much queued data as fits.
        let mut wrote = false;
        while buf.remaining() > 0 {
            let Some(front) = this.read_queue.front_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            wrote = true;
            if front.is_empty() {
                this.read_queue.pop_front();
            }
        }

        if wrote {
            return Poll::Ready(Ok(()));
        }
        if this.got_reset && this.read_queue.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if this.got_eof && this.read_queue.is_empty() {
            // Clean EOF: signalled by a zero-length read.
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.drain_inbound();
        if this.got_reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }

        // One command carries the whole write; the engine's send buffer is
        // unbounded, so backpressure is only the command ring being full.
        match this
            .cmd_tx
            .push(Command::Send(Bytes::copy_from_slice(data)))
        {
            Ok(()) => {
                this.drain_flush();
                Poll::Ready(Ok(data.len()))
            }
            Err(_full) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Deliberately NOT a cork-release point: hyper/rustls flush at
        // their own message boundaries, but a corked connection's tail is
        // released only by the user's FlushHandle. Writes are already
        // enqueued to the worker, so there is nothing to do here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Half-close: enqueue a FIN. Reading may continue afterward.
        match this.cmd_tx.push(Command::Close) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_full) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

// Dropping the stream drops its command sender; the worker observes the
// closed ring and closes the engine-side connection (sending a FIN), so
// no explicit teardown message is needed here.

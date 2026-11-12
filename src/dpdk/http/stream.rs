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
use std::net::Ipv4Addr;
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

/// Where a connection stands as seen from the application side, driven by
/// the worker's [`Inbound`] messages:
///
/// ```text
/// Connecting --Established--> Open --Eof / worker gone--> Eof
///     |                        |                           |
///     |                        +-----------Reset-----------+--> Reset
///     +--ConnectFailed / Reset--> Reset
///     +--AddrInUse--> AddrInUse
///     +--Eof / worker gone--> Aborted
/// ```
///
/// Everything but `Connecting` and `Open` is terminal for the receive
/// side. Bytes already in `read_queue` are still delivered first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// The handshake is in flight.
    Connecting,
    /// The handshake completed and the peer may still send.
    Open,
    /// The peer finished sending (or the worker went away) after the
    /// handshake: reads end cleanly once `read_queue` drains.
    Eof,
    /// The connection was reset, or the handshake failed: reads error once
    /// `read_queue` drains and writes error at once.
    Reset,
    /// The worker refused the open: the 4-tuple is already in use.
    AddrInUse,
    /// The worker went away before the handshake completed.
    Aborted,
}

impl StreamState {
    /// The inbound side ended without an error message: a peer FIN, or
    /// the worker dropping its sender.
    fn on_end_of_input(self) -> Self {
        match self {
            StreamState::Connecting => StreamState::Aborted,
            StreamState::Open => StreamState::Eof,
            terminal => terminal,
        }
    }
}

pub struct TcpStream {
    cmd_tx: CmdTx,
    inbound_rx: InboundRx,
    /// Shared with a user `FlushHandle`; observed on each poll to enqueue
    /// an ordered `Command::Flush`.
    flush: Option<Arc<AtomicBool>>,
    state: StreamState,
    /// In-order received chunks not yet delivered to the reader (copied out
    /// by `poll_read`, or handed over as-is by `poll_recv`).
    read_queue: VecDeque<Bytes>,
}

impl TcpStream {
    /// Opens a connection via the worker and resolves once the handshake
    /// completes. Errors: `ConnectionRefused` on RST/timeout, `AddrInUse` if
    /// the worker refused the 4-tuple because it is already in use (retry
    /// with another local port), and `ConnectionAborted` if the worker went
    /// away before the handshake finished.
    pub async fn connect(
        worker: &WorkerHandle,
        remote_ip: Ipv4Addr,
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
            state: StreamState::Connecting,
            read_queue: VecDeque::new(),
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

    /// Poll form of [`send`](Self::send). On success `data` is taken.
    /// On Pending it holds the unsent suffix; cancellation may leave a prefix sent.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        self.drain_inbound();
        if self.state == StreamState::Reset || self.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        self.drain_flush();
        if self.cmd_tx.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let bytes = data.as_mut().expect("poll_send polled without a payload");
        if bytes.is_empty() {
            data.take();
            return Poll::Ready(Ok(()));
        }
        let n = bytes.len().min(self.cmd_tx.available_bytes());
        if n == 0 || self.cmd_tx.len() == self.cmd_tx.capacity() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        // Retain the unsent suffix in the caller's Option across polls.
        match self.cmd_tx.push(Command::Send(bytes.slice(..n))) {
            Ok(()) => {
                bytes.advance(n);
                if bytes.is_empty() {
                    data.take();
                    self.drain_flush();
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(_) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
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
        match self.state {
            StreamState::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            StreamState::Connecting | StreamState::Open => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            // Clean EOF.
            StreamState::Eof | StreamState::AddrInUse | StreamState::Aborted => {
                Poll::Ready(Ok(None))
            }
        }
    }

    fn poll_established(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain_inbound();
        match self.state {
            StreamState::Connecting => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            // A peer that completed the handshake and already finished
            // sending still yields a usable (write-only) stream.
            StreamState::Open | StreamState::Eof => Poll::Ready(Ok(())),
            StreamState::AddrInUse => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "local address (4-tuple) already in use",
            ))),
            StreamState::Reset => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused or reset during handshake",
            ))),
            // The worker dropped its sender without ever sending
            // `Established` or a failure: it stopped or reaped us.
            StreamState::Aborted => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "worker went away before the handshake completed",
            ))),
        }
    }

    /// Processes control messages, staging at most one data chunk.
    fn drain_inbound(&mut self) {
        // Sample closed-ness *before* draining: the worker pushes its last
        // messages and only then drops its sender, so if the ring is closed
        // now, everything it will ever send is already visible to the pops
        // below. (Sampling after the drain could latch EOF while messages
        // pushed in between are still queued.) `is_closed()` is true when
        // either end is dropped; from the receiver that means the sender.
        let sender_gone = self.inbound_rx.is_closed();
        while self.read_queue.is_empty() {
            let Some(msg) = self.inbound_rx.pop() else {
                break;
            };
            match msg {
                Inbound::Data(bytes) => {
                    if !bytes.is_empty() {
                        self.read_queue.push_back(bytes);
                    }
                }
                control => self.on_control(control),
            }
        }
        // If the worker dropped its inbound sender (connection reaped),
        // treat as EOF so a stuck reader unblocks -- but only because the
        // ring was already closed before the drain above, so it is now
        // known to be empty.
        if sender_gone && self.inbound_rx.is_empty() {
            self.state = self.state.on_end_of_input();
        }
    }

    /// The one place `state` advances on a worker message. The worker
    /// sends at most one terminal message, and nothing after it.
    fn on_control(&mut self, msg: Inbound) {
        self.state = match (self.state, msg) {
            (state, Inbound::Data(_)) => state,
            (StreamState::Connecting, Inbound::Established) => StreamState::Open,
            (state, Inbound::Established) => state,
            (state, Inbound::Eof) => state.on_end_of_input(),
            // The refusal outranks everything, and a reset outranks a clean
            // end, as they did when these were independent flags.
            (_, Inbound::AddrInUse) => StreamState::AddrInUse,
            (StreamState::AddrInUse, Inbound::Reset | Inbound::ConnectFailed) => {
                StreamState::AddrInUse
            }
            (_, Inbound::Reset | Inbound::ConnectFailed) => StreamState::Reset,
        };
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

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

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
        // `read_queue` is empty here: surface how the inbound side ended.
        match this.state {
            StreamState::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            StreamState::Connecting | StreamState::Open => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            // Clean EOF: signalled by a zero-length read.
            StreamState::Eof | StreamState::AddrInUse | StreamState::Aborted => Poll::Ready(Ok(())),
        }
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
        if this.state == StreamState::Reset || this.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }

        this.drain_flush();
        if this.cmd_tx.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Check both limits before allocating or copying the payload.
        if this.cmd_tx.len() == this.cmd_tx.capacity() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = data.len().min(this.cmd_tx.available_bytes());
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        // Copy only the prefix covered by byte credit.
        match this
            .cmd_tx
            .push(Command::Send(Bytes::copy_from_slice(&data[..n])))
        {
            Ok(()) => {
                this.drain_flush();
                Poll::Ready(Ok(n))
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
        if this.cmd_tx.is_closed() || this.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpdk::tcp::worker::SendCredit;
    use crate::dpdk::tcp::worker::inbound_channel;
    use crate::dpdk::tcp::worker::{CmdRx, InboundTx, SEND_CAPACITY, command_channel};

    fn fixture() -> (TcpStream, CmdRx, InboundTx, Arc<SendCredit>) {
        let (cmd_tx, cmd_rx, credit) = command_channel();
        let (inbound_tx, inbound_rx) = inbound_channel(credit.clone());
        (
            TcpStream {
                cmd_tx,
                inbound_rx,
                flush: None,
                state: StreamState::Open,
                read_queue: VecDeque::new(),
            },
            cmd_rx,
            inbound_tx,
            credit,
        )
    }

    #[test]
    fn writes_stop_at_byte_limit_even_after_worker_drains_ring() {
        let (mut stream, rx, _tx, credit) = fixture();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let data = vec![42; SEND_CAPACITY + 10];
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &data),
            Poll::Ready(Ok(SEND_CAPACITY))
        ));
        let Some(Command::Send(sent)) = rx.pop() else {
            panic!()
        };
        assert_eq!(sent.len(), SEND_CAPACITY);
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, &data)
                .is_pending()
        );
        // Simulate the worker publishing ACK credit.
        credit.bytes.fetch_sub(10, Ordering::AcqRel);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &data),
            Poll::Ready(Ok(10))
        ));
    }

    #[test]
    fn owned_send_preserves_suffix_and_order_across_credit_stalls() {
        let (mut stream, rx, _tx, credit) = fixture();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let original = Bytes::from(vec![7; SEND_CAPACITY + 3]);
        let mut data = Some(original.clone());
        assert!(stream.poll_send(&mut cx, &mut data).is_pending());
        let Some(Command::Send(first)) = rx.pop() else {
            panic!()
        };
        assert_eq!(first.len(), SEND_CAPACITY);
        assert_eq!(first.as_ptr(), original.as_ptr());
        assert_eq!(data.as_ref().unwrap().len(), 3);
        assert!(stream.poll_send(&mut cx, &mut data).is_pending());
        assert!(rx.is_empty());
        credit.bytes.fetch_sub(SEND_CAPACITY, Ordering::AcqRel);
        assert!(matches!(
            stream.poll_send(&mut cx, &mut data),
            Poll::Ready(Ok(()))
        ));
        assert!(data.is_none());
        let Some(Command::Send(last)) = rx.pop() else {
            panic!()
        };
        assert_eq!(last, original.slice(SEND_CAPACITY..));
    }

    #[test]
    fn repeated_writes_cannot_drain_unread_data_or_skip_terminal_message() {
        let (mut stream, _rx, tx, _credit) = fixture();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for b in [b"first".as_slice(), b"second".as_slice()] {
            assert!(tx.push(Inbound::Data(Bytes::copy_from_slice(b))).is_ok());
        }
        assert!(tx.push(Inbound::Reset).is_ok());
        drop(tx);
        for _ in 0..100 {
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b""),
                Poll::Ready(Ok(0))
            ));
        }
        assert_eq!(stream.read_queue.len(), 1);
        assert_eq!(stream.inbound_rx.len(), 2);
        assert_eq!(stream.state, StreamState::Open);
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            match stream.poll_recv(&mut cx) {
                Poll::Ready(Ok(Some(bytes))) => assert_eq!(&bytes[..], expected),
                _ => panic!("data must precede reset"),
            }
        }
        assert!(
            matches!(stream.poll_recv(&mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn reset_unblocks_writer_even_with_unread_data() {
        let (mut stream, _rx, tx, credit) = fixture();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            tx.push(Inbound::Data(Bytes::from_static(b"unread")))
                .is_ok()
        );
        stream.drain_inbound();
        credit.failed.store(true, Ordering::Release);
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"x"),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
        let mut data = Some(Bytes::from_static(b"x"));
        assert!(matches!(stream.poll_send(&mut cx, &mut data),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
        assert_eq!(stream.read_queue.front().unwrap(), b"unread".as_slice());
    }

    #[test]
    fn partial_read_keeps_only_one_staged_chunk() {
        let (mut stream, _rx, tx, _) = fixture();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(tx.push(Inbound::Data(Bytes::from_static(b"abcd"))).is_ok());
        assert!(tx.push(Inbound::Data(Bytes::from_static(b"ef"))).is_ok());
        let mut storage = [0; 2];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"ab");
        stream.drain_inbound();
        assert_eq!(stream.read_queue.front().unwrap(), b"cd".as_slice());
        assert_eq!(stream.inbound_rx.len(), 1);
    }
}

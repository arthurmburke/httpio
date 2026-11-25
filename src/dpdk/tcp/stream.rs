//! `TcpStream`: tokio `AsyncRead`/`AsyncWrite` over a connection managed
//! by the TCP engine on the worker lcore. All I/O crosses the core
//! boundary through this connection's SPSC ring pair (see
//! `crate::tcp::worker`): writes push `Command`s, reads pop `Inbound`
//! messages. There is no lock and no shared engine access on this side.
//!
//! [`AsyncRead`] copies directly from the receive mbuf into the caller's
//! buffer. [`recv_chunk`](TcpStream::recv_chunk) hands out a view of the mbuf
//! itself ([`MbufSlice`]), so the caller can read, split and keep the data
//! without copying or allocating; [`recv`](TcpStream::recv) does the same as
//! [`Bytes`], at the cost of one allocation per mbuf.
//! [`send`](TcpStream::send) moves owned bytes across the ring, while
//! [`AsyncWrite`] copies borrowed writes into storage the worker can keep.
//!
//! Waiting: when a read has no data yet (or a write can't enqueue because
//! the command ring or send credit is exhausted), the stream stores its
//! waker, checks once more, and returns `Pending`. The worker reports which
//! connections changed and one driver task per worker wakes exactly those
//! (see `crate::dpdk::tcp::app_wake`). The driver busy-polls -- no thread
//! sleeps and no system call is made while a stream is waiting -- but
//! streams with no news are not polled. Outside a tokio runtime a stream
//! falls back to waking itself. Run the client on a `current_thread` tokio
//! runtime built without the I/O driver (`enable_time` only): tokio's I/O
//! driver makes an `epoll_wait` call on its own schedule.

use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::core::spinlock::SpinLock;
use crate::dpdk::tcp::app_wake::{AppWake, Parker};
use crate::dpdk::tcp::worker::{
    CmdTx, Command, Inbound, InboundRx, OpenError, SendCredit, WorkerHandle,
};
use crate::dpdk::{DmaWriter, MbufSlice};

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
    /// connection closes, which flushes implicitly). The flush uncorks the
    /// connection for good: nothing written after it is held either. The
    /// cork is applied once the TCP/TLS handshakes are over, so they are
    /// unaffected. Since a
    /// manually-held tail is incompatible with a shared multiplexed
    /// connection, corked `https` requests go over HTTP/1.1, each with a
    /// connection to itself for as long as it lasts; the connection is
    /// then kept for the next HTTP/1.1 request to the origin, which may
    /// cork it again. Takes precedence over `nodelay`.
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
/// Once the request's connection exists, [`flush`](Self::flush) tells the
/// TCP worker directly: it sets a flag the worker shares with the
/// connection and puts the connection on the worker's notification queue.
/// The worker releases the tail on its next turn, after whatever the
/// stream had already written. Nothing on the application side has to run
/// for that -- not the request's task, not the runtime -- so the reaction
/// time is the worker's alone, whatever the calling thread does next.
///
/// A flush is final, and it cannot come too early. It uncorks the
/// connection rather than releasing one tail: whatever the request still
/// has to write goes out as it is written. And the handle remembers that
/// it was flushed, so a flush made before the request has been staged --
/// before the connection exists, during its handshakes, between the
/// request's writes -- means the request is simply never held. (A
/// one-shot release would be lost in every one of those cases, leaving
/// the request waiting for a flush that had already happened.)
///
/// The same handle can instead call the request off:
/// [`terminate`](Self::terminate) ends its connection at once, with
/// nothing more sent on it -- the held tail is discarded, not released --
/// and the request fails. It reaches the worker the way a flush does, and
/// like a flush it is final and cannot come too early.
///
/// A handle belongs to one request and reaches that request's connection
/// only: once the connection goes on to carry another request, neither
/// call on the old handle touches it. A request that ends up on a shared
/// HTTP/2 connection is not within its handle's reach at all.
///
/// The handle stays `Send + Sync` (required to live in
/// `http::Extensions`) and may be used from any thread.
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
    state: Arc<FlushState>,
}

/// Shared by a [`FlushHandle`] and the stream it releases.
pub(crate) struct FlushState {
    /// [`FlushHandle::flush`] has been called. Never cleared: a stream
    /// that sees it does not cork, whenever it looks.
    flushed: AtomicBool,
    /// [`FlushHandle::terminate`] has been called. Never cleared: a
    /// stream paired with the handle fails everything from then on.
    aborted: AtomicBool,
    /// A flush the stream has to pass on itself, as a command, because no
    /// worker could be told directly (the connection did not exist yet).
    requested: AtomicBool,
    /// The paired stream's waker slot, once it has connected, so a flush
    /// request reaches a stream that is waiting for the worker.
    stream: SpinLock<Option<Arc<AppWake>>>,
    /// The paired stream's line to its worker, once it has connected.
    worker: SpinLock<Option<Arc<SendCredit>>>,
}

impl Default for FlushState {
    fn default() -> Self {
        Self {
            flushed: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            requested: AtomicBool::new(false),
            stream: SpinLock::new(None),
            worker: SpinLock::new(None),
        }
    }
}

impl FlushHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Releases the request: the held tail goes out, and nothing more is
    /// held on its connection. Fire and forget: with the connection up,
    /// the worker is told at once and sends the tail on its next turn
    /// (after any writes the stream has already handed it). Calling it
    /// before the request has been staged, at any point, is fine -- the
    /// request then goes out as it is written, unheld. Calling it again
    /// does nothing.
    pub fn flush(&self) {
        // First, and for good: from here on the stream will not cork,
        // however far it has got (see `TcpStream::request_cork`).
        self.state.flushed.store(true, Ordering::SeqCst);
        // Called under the lock rather than on a clone taken out of it: a
        // clone would write the reference count, which shares a cache line
        // with state the worker keeps writing, and so wait for that line
        // before the request could even be made.
        let told = self
            .state
            .worker
            .with(|worker| worker.as_ref().is_some_and(|worker| worker.request_flush()));
        if told {
            return;
        }
        self.state.requested.store(true, Ordering::Release);
        // The request is set before the wake, and the stream checks it
        // again after storing its waker, so it cannot be missed.
        let stream = self.state.stream.with(|stream| stream.clone());
        if let Some(stream) = stream {
            stream.wake_now();
        }
    }

    /// Calls the request off: its connection is ended now and nothing
    /// more is sent on it. A corked request's held tail is discarded, so a
    /// request that was wholly held never reaches the server; the peer is
    /// sent a reset. The request itself fails (its connection reports
    /// `ConnectionAborted`), and the connection is not kept for reuse.
    ///
    /// Fire and forget, like [`flush`](Self::flush): with the connection
    /// up the worker is told at once and acts on its next turn, without
    /// the request's task or the runtime having to run. If both a flush
    /// and a termination are waiting when the worker looks, the
    /// termination wins. Called before the request has a connection, the
    /// request fails without getting one. Called after the request is
    /// over, when its connection has gone on to another, it does nothing.
    /// It cannot take back what has already been sent.
    pub fn abort(&self) {
        // First, and for good: a stream paired with this handle, now or
        // later, fails whatever it is asked to do.
        self.state.aborted.store(true, Ordering::SeqCst);
        self.state.worker.with(|worker| {
            if let Some(worker) = worker {
                worker.request_abort();
            }
        });
        // The request may be waiting on the stream: it has an answer now.
        let stream = self.state.stream.with(|stream| stream.clone());
        if let Some(stream) = stream {
            stream.wake_now();
        }
    }

    /// Whether [`abort`](Self::abort) has been called.
    pub fn is_aborted(&self) -> bool {
        self.state.aborted.load(Ordering::SeqCst)
    }

    pub(crate) fn attach(
        &self,
        stream: &Arc<AppWake>,
        worker: &Arc<SendCredit>,
    ) -> Arc<FlushState> {
        self.state.stream.with(|slot| *slot = Some(stream.clone()));
        self.state.worker.with(|slot| *slot = Some(worker.clone()));
        // Aborted before it had a connection to end: end this one.
        // (`abort` sets its mark before it looks for the connection,
        // and this looks for the mark after providing one, so between
        // them the worker is always told.)
        if self.is_aborted() {
            worker.request_abort();
        }
        self.state.clone()
    }
}

impl FlushState {
    /// Cuts the handle off from its connection, which is going on to
    /// another request: a late `flush` on the old handle must not release
    /// that one.
    fn detach(&self) {
        self.worker.with(|slot| *slot = None);
        self.stream.with(|slot| *slot = None);
    }
}

/// What a stream reports once its [`FlushHandle`] has aborted it.
fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection aborted through its flush handle",
    )
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
/// side. Bytes already in `read_chunk` are still delivered first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// The handshake is in flight.
    Connecting,
    /// The handshake completed and the peer may still send.
    Open,
    /// The peer finished sending (or the worker went away) after the
    /// handshake: reads end cleanly once `read_chunk` drains.
    Eof,
    /// The connection was reset, or the handshake failed: reads error once
    /// `read_chunk` drains and writes error at once.
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

/// A body the owner of the stream lent it before handing the stream to a
/// writer that only has `AsyncWrite` (hyper), so that writes of that
/// body's bytes go out as slices of it instead of copies.
///
/// Sound because the stream holds its own clone: the memory stays alive
/// and, `Bytes` being immutable while shared, any borrowed slice whose
/// address range lies inside it reads exactly the bytes the slice of the
/// clone does. Only addresses are compared; contents never are.
enum LentBody {
    /// Nothing lent, or the lent body has been sent in full.
    Empty,
    /// `body` is lent; `unsent` of its bytes have not yet gone out as
    /// slices of it. Some may have been copied instead (a writer that
    /// flattened them), in which case it stays lent until the next
    /// [`TcpStream::lend_body`] or the stream's end.
    Lent { body: Bytes, unsent: usize },
}

impl LentBody {
    /// What [`TcpStream::lend_body`] keeps of `body`. With a DMA writer
    /// only a body that `is_dma` (checked once, here, not per write) is
    /// worth lending; see there. `is_dma` is not called without a writer,
    /// which is also when EAL may not be up to answer it.
    fn new(body: &Bytes, has_writer: bool, is_dma: impl FnOnce() -> bool) -> Self {
        if body.is_empty() || (has_writer && !is_dma()) {
            return LentBody::Empty;
        }
        LentBody::Lent {
            body: body.clone(),
            unsent: body.len(),
        }
    }

    /// The part of the lent body that `data` borrows from, if all of
    /// `data` lies inside it.
    fn slice_of(&self, data: &[u8]) -> Option<Bytes> {
        let LentBody::Lent { body, .. } = self else {
            return None;
        };
        if data.is_empty() {
            return None;
        }
        let start = (data.as_ptr() as usize).checked_sub(body.as_ptr() as usize)?;
        let end = start.checked_add(data.len())?;
        (end <= body.len()).then(|| body.slice(start..end))
    }

    /// Records that `n` bytes went out as slices of the body, letting go
    /// of it once all of it has.
    fn sent(&mut self, n: usize) {
        if let LentBody::Lent { unsent, .. } = self {
            *unsent = unsent.saturating_sub(n);
            if *unsent == 0 {
                *self = LentBody::Empty;
            }
        }
    }
}

/// Where a vectored write has got to in its slices: `offset` bytes into
/// `bufs[index]`.
#[derive(Clone, Copy)]
struct Position {
    index: usize,
    offset: usize,
}

impl Position {
    /// The unwritten part of the current slice, skipping empty ones;
    /// `None` once every slice is written.
    fn current<'a>(&mut self, bufs: &'a [IoSlice<'_>]) -> Option<&'a [u8]> {
        while let Some(buf) = bufs.get(self.index) {
            let rest = &buf[self.offset..];
            if !rest.is_empty() {
                return Some(rest);
            }
            self.index += 1;
            self.offset = 0;
        }
        None
    }

    fn advance(&mut self, bufs: &[IoSlice<'_>], mut n: usize) {
        while n > 0 {
            let rest = bufs[self.index].len() - self.offset;
            if n < rest {
                self.offset += n;
                return;
            }
            n -= rest;
            self.index += 1;
            self.offset = 0;
        }
    }
}

pub struct TcpStream {
    cmd_tx: CmdTx,
    inbound_rx: InboundRx,
    /// Shared with a user `FlushHandle`; observed on each poll to enqueue
    /// an ordered `Command::Flush`.
    flush: Option<Arc<FlushState>>,
    /// Where the waker goes while the stream waits for the worker. `None`
    /// only in tests that build a stream without a worker.
    wake: Option<Parker>,
    state: StreamState,
    /// The next in-order chunk, including any unread suffix of a partial read.
    read_chunk: Option<MbufSlice>,
    /// Where `poll_write` copies borrowed data on a port with TSO, so the
    /// engine attaches it to packets without a second copy; `None`
    /// otherwise, and the data goes to the ordinary heap.
    writer: Option<DmaWriter>,
    /// See [`lend_body`](Self::lend_body).
    lent: LentBody,
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
        // Called off before it began: no connection is opened for it.
        if flush.is_some_and(FlushHandle::is_aborted) {
            return Err(aborted());
        }
        let endpoints = worker
            .open(remote_ip, remote_port, local_port, options.nodelay)
            .map_err(|error| match error {
                OpenError::Busy => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "TCP worker control ring is full (worker overloaded or stalled)",
                ),
                OpenError::PortNotSteered => io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "local port is outside the range the NIC steers to a worker \
                     (use 49152..=65535 with more than one worker)",
                ),
            })?;

        let flush = flush.map(|flush| flush.attach(&endpoints.wake, endpoints.cmd_tx.credit()));
        let mut stream = Self {
            cmd_tx: endpoints.cmd_tx,
            inbound_rx: endpoints.inbound_rx,
            flush,
            wake: Some(Parker(endpoints.wake)),
            state: StreamState::Connecting,
            read_chunk: None,
            writer: endpoints.dma_writes.then(DmaWriter::new),
            lent: LentBody::Empty,
        };
        poll_fn(|cx| stream.poll_established(cx)).await?;
        Ok(stream)
    }

    /// Enables TCP_CORK on this connection. Must be called *after* the TLS
    /// handshake (if any) and before writing the request body: corking
    /// earlier would hold the sub-MSS handshake records. The command is
    /// ordered ahead of subsequent writes on the same ring.
    ///
    /// Does nothing if the connection's [`FlushHandle`] has already been
    /// flushed: the request was released before it was staged, so it is
    /// not to be held at all.
    pub fn request_cork(&self) {
        let flushed = || {
            self.flush
                .as_ref()
                .is_some_and(|flush| flush.flushed.load(Ordering::SeqCst))
        };
        if flushed() {
            return;
        }
        // Best-effort: the command ring is empty right after connect, so a
        // single push cannot fail here in practice.
        let _ = self.cmd_tx.push(Command::SetCork(true));
        // A flush that came between the look and the push may already have
        // been taken by the worker, ahead of the cork: undo it. (One that
        // comes after this look finds the cork on the ring, which the
        // worker applies before it.)
        if flushed() {
            let _ = self.cmd_tx.push(Command::SetCork(false));
        }
    }

    /// Pairs the connection with the flush handle of the next request it
    /// carries, in place of the last one's (which can no longer reach it),
    /// or with none. For a connection reused between requests; follow it
    /// with [`request_cork`](Self::request_cork) to hold that request.
    pub fn set_flush_handle(&mut self, flush: Option<&FlushHandle>) {
        if let Some(previous) = self.flush.take() {
            previous.detach();
        }
        self.flush = flush.map(|flush| match &self.wake {
            Some(Parker(wake)) => flush.attach(wake, self.cmd_tx.credit()),
            None => flush.state.clone(),
        });
    }

    /// The error every operation gives once the connection has been ended
    /// through its [`FlushHandle`]. The handle's word, not the worker's:
    /// the stream fails from the moment `abort` is called, without
    /// waiting to be told the connection is gone.
    fn aborted(&self) -> Option<io::Error> {
        self.flush
            .as_ref()
            .is_some_and(|flush| flush.aborted.load(Ordering::SeqCst))
            .then(aborted)
    }

    /// Whether the connection, idle between two requests, can carry
    /// another: it is open, the peer has sent nothing unread, and no tail
    /// of the last request is still held (a request given a
    /// [`FlushHandle`] counts as held until that handle is flushed).
    /// Registers no waker.
    pub fn reusable(&mut self) -> bool {
        if self
            .flush
            .as_ref()
            .is_some_and(|flush| !flush.flushed.load(Ordering::SeqCst))
        {
            return false;
        }
        if self.aborted().is_some() {
            return false;
        }
        self.drain_flush();
        self.drain_inbound();
        self.state == StreamState::Open
            && self.read_chunk.is_none()
            && !self.cmd_tx.failed()
            && !self.cmd_tx.is_closed()
    }

    /// Forgets the waker of the last poll, for a caller that polled only to
    /// look and is not waiting.
    pub fn unpark(&self) {
        if let Some(Parker(wake)) = &self.wake {
            wake.unpark();
        }
    }

    /// Lends the stream a body that is about to be written through
    /// [`AsyncWrite`] by code that only sees borrowed slices (hyper's h1
    /// connection, which queues the body `Bytes` and writes it vectored).
    /// Any write whose slice lies entirely inside `body` then goes out as
    /// a slice of it, with no copy; anything else is copied as usual. The
    /// stream keeps a clone until all of `body` has gone out this way, the
    /// next call replaces it, or the stream is dropped.
    ///
    /// Only for writes that reach the stream unchanged: behind TLS the
    /// stream sees ciphertext, which never matches.
    ///
    /// On a port that attaches external buffers (the stream has a
    /// `DmaWriter`) the body is kept only if it is already EAL memory. A
    /// heap body is left unlent: sliced, it would reach the worker as heap
    /// memory and be copied into mbufs there, on the shared worker lcore,
    /// whereas copied here it lands in the writer's DMA block once, on the
    /// app thread, and the worker attaches it. Without a writer the worker
    /// copies every payload anyway, so slicing is never worse than copying
    /// and the body is always lent.
    pub fn lend_body(&mut self, body: &Bytes) {
        self.lent = LentBody::new(body, self.writer.is_some(), || {
            // Classifies by the first byte's memory segment: EAL memory or
            // not. A body longer than one segment (or than `dma_prefix`'s
            // u16 cap) still counts; the engine attaches what it can and
            // copies the rest, chunk by chunk.
            crate::dpdk::mbuf::Mbuf::dma_prefix(body).is_some()
        });
    }

    /// Whether this connection's port attaches DMA-capable `Bytes` to
    /// packets without copying them (see [`DmaWriter`]). A layer that
    /// produces its own output, such as TLS encryption, writes it into DMA
    /// memory exactly when this holds, else onto the ordinary heap.
    pub fn dma_writes(&self) -> bool {
        self.writer.is_some()
    }

    /// Zero-copy write: hands owned `data` straight to the worker as a
    /// `Command::Send`, avoiding the copy the [`AsyncWrite`] path is forced to
    /// make from its borrowed `&[u8]`. Waits while the command ring or the
    /// send credit is exhausted; errors if the connection was reset.
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
        if let Poll::Ready(done) = self.try_send(data) {
            return Poll::Ready(done);
        }
        if !self.wait(cx) {
            return Poll::Pending;
        }
        self.try_send(data)
    }

    /// Stores the task's waker for the worker's next report on this
    /// connection. On `true` the caller must run its check once more
    /// before returning `Pending`: the worker may have acted between the
    /// first check and the waker being stored. On `false` nobody can wake
    /// the stream (no worker, or no tokio runtime for the driver), so the
    /// task has been woken to poll again.
    fn wait(&mut self, cx: &mut Context<'_>) -> bool {
        if let Some(Parker(wake)) = &self.wake
            && wake.park(cx.waker())
        {
            return true;
        }
        cx.waker().wake_by_ref();
        false
    }

    /// One attempt at [`poll_send`](Self::poll_send): pushes as much of
    /// `data` as ring space and send credit allow.
    fn try_send(&mut self, data: &mut Option<Bytes>) -> Poll<io::Result<()>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        self.drain_inbound();
        if self.state == StreamState::Reset || self.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        self.drain_flush();
        if self.cmd_tx.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        loop {
            let bytes = data.as_mut().expect("poll_send polled without a payload");
            if bytes.is_empty() {
                data.take();
                return Poll::Ready(Ok(()));
            }
            let n = bytes.len().min(self.cmd_tx.available_bytes());
            if n == 0 || self.cmd_tx.len() == self.cmd_tx.capacity() {
                return Poll::Pending;
            }
            // Retain the unsent suffix in the caller's Option across polls.
            if self.cmd_tx.push(Command::Send(bytes.slice(..n))).is_err() {
                return Poll::Pending;
            }
            bytes.advance(n);
            if bytes.is_empty() {
                data.take();
                self.drain_flush();
                return Poll::Ready(Ok(()));
            }
        }
    }

    /// Zero-copy read as owned [`Bytes`]: [`recv_chunk`](Self::recv_chunk),
    /// converted. `Ok(None)` is a clean EOF; waits until a chunk, EOF, or
    /// reset is available.
    ///
    /// Turning a packet buffer into `Bytes` heap-allocates its shared owner
    /// (`Bytes` has no allocation-free way to wrap foreign memory), once
    /// per chunk. Only for callers that must have `Bytes`.
    pub async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Poll form of [`recv`](Self::recv). Buffered data is delivered before a
    /// reset is surfaced, matching [`AsyncRead`].
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        self.poll_recv_chunk(cx)
            .map_ok(|chunk| chunk.map(MbufSlice::into_bytes))
    }

    /// Zero-copy read: pops the next received chunk, a view of the packet
    /// buffer it arrived in, with no copy and no heap allocation. The
    /// [`MbufSlice`] can be split, sliced and cloned, still without allocating;
    /// the buffer returns to its pool when the last part is dropped.
    /// `Ok(None)` is a clean EOF; waits until a chunk, EOF, or reset is
    /// available.
    pub async fn recv_chunk(&mut self) -> io::Result<Option<MbufSlice>> {
        poll_fn(|cx| self.poll_recv_chunk(cx)).await
    }

    /// Poll form of [`recv_chunk`](Self::recv_chunk). Buffered data is
    /// delivered before a reset is surfaced, matching [`AsyncRead`].
    pub fn poll_recv_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<MbufSlice>>> {
        if let Poll::Ready(done) = self.try_recv() {
            return Poll::Ready(done);
        }
        if !self.wait(cx) {
            return Poll::Pending;
        }
        self.try_recv()
    }

    fn try_recv(&mut self) -> Poll<io::Result<Option<MbufSlice>>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        self.drain_flush();
        self.drain_inbound();
        if let Some(chunk) = self.read_chunk.take() {
            return Poll::Ready(Ok(Some(chunk)));
        }
        match self.state {
            StreamState::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            StreamState::Connecting | StreamState::Open => Poll::Pending,
            // Clean EOF.
            StreamState::Eof | StreamState::AddrInUse | StreamState::Aborted => {
                Poll::Ready(Ok(None))
            }
        }
    }

    fn poll_established(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(done) = self.try_established() {
            return Poll::Ready(done);
        }
        if !self.wait(cx) {
            return Poll::Pending;
        }
        self.try_established()
    }

    fn try_established(&mut self) -> Poll<io::Result<()>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        self.drain_inbound();
        match self.state {
            StreamState::Connecting => Poll::Pending,
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
        while self.read_chunk.is_none() {
            match self.inbound_rx.pop() {
                None => break,
                Some(Inbound::Data(chunk)) => {
                    if !chunk.is_empty() {
                        self.read_chunk = Some(chunk);
                    }
                }
                Some(control) => self.on_control(control),
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

    /// If a flush was requested that no worker could be told of directly,
    /// pass it on now: uncork (ordered after any writes already pushed).
    /// Re-arms on a full command ring so it isn't lost.
    fn drain_flush(&self) {
        if let Some(flush) = &self.flush
            && flush.requested.swap(false, Ordering::AcqRel)
            && self.cmd_tx.push(Command::SetCork(false)).is_err()
        {
            flush.requested.store(true, Ordering::Release);
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
        if let Poll::Ready(done) = this.try_read(buf) {
            return Poll::Ready(done);
        }
        if !this.wait(cx) {
            return Poll::Pending;
        }
        this.try_read(buf)
    }
}

impl TcpStream {
    /// One attempt at `poll_read`. Nothing is written to `buf` when it
    /// returns `Pending`.
    fn try_read(&mut self, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        let this = self;
        this.drain_flush();
        this.drain_inbound();

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Copy as much queued data as fits, staging further chunks as each
        // one is consumed: a chunk is one received segment, and a caller
        // with a large buffer should not need a poll per segment.
        let mut wrote = false;
        while buf.remaining() > 0 {
            if this.read_chunk.is_none() && wrote {
                this.drain_inbound();
            }
            let Some(front) = this.read_chunk.as_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front.as_slice()[..n]);
            front.advance(n);
            wrote = true;
            if front.is_empty() {
                this.read_chunk = None;
            }
        }

        if wrote {
            return Poll::Ready(Ok(()));
        }
        // `read_chunk` is empty here: surface how the inbound side ended.
        match this.state {
            StreamState::Reset => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            StreamState::Connecting | StreamState::Open => Poll::Pending,
            // Clean EOF: signalled by a zero-length read.
            StreamState::Eof | StreamState::AddrInUse | StreamState::Aborted => Poll::Ready(Ok(())),
        }
    }
}

impl TcpStream {
    /// One attempt at `poll_write_vectored` (and `poll_write`, as one
    /// slice). Accepts as much of `bufs`, in order, as byte credit and
    /// ring space allow, in as few `Command::Send`s as it can: slices of
    /// a lent body go out as slices of it, and each run of other slices
    /// is copied into one contiguous chunk -- DMA memory on a port with
    /// TSO, so a header and the start of a body share a block and can
    /// share a packet, else the heap. Returns the bytes accepted, which
    /// may end mid-slice. Nothing is enqueued when it returns `Pending`.
    fn try_write(&mut self, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        self.drain_inbound();
        if self.state == StreamState::Reset || self.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }

        self.drain_flush();
        if self.cmd_tx.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let mut position = Position {
            index: 0,
            offset: 0,
        };
        if position.current(bufs).is_none() {
            return Poll::Ready(Ok(0));
        }
        let mut accepted = 0;
        // Check both limits before allocating or copying each chunk.
        while let Some(first) = position.current(bufs) {
            if self.cmd_tx.len() == self.cmd_tx.capacity() {
                break;
            }
            let credit = self.cmd_tx.available_bytes();
            if credit == 0 {
                break;
            }
            let Some(n) = self.push_chunk(bufs, position, first, credit) else {
                break;
            };
            position.advance(bufs, n);
            accepted += n;
        }
        if accepted == 0 {
            return Poll::Pending;
        }
        self.drain_flush();
        Poll::Ready(Ok(accepted))
    }

    /// Enqueues one `Command::Send` starting at `position` (whose unwritten
    /// part of the current slice is `first`), of at most `credit` bytes.
    /// Returns its length, or `None` if the ring refused it, in which case
    /// nothing was enqueued and any DMA space taken has been given back.
    fn push_chunk(
        &mut self,
        bufs: &[IoSlice<'_>],
        position: Position,
        first: &[u8],
        credit: usize,
    ) -> Option<usize> {
        if let Some(chunk) = self.lent.slice_of(&first[..first.len().min(credit)]) {
            let n = chunk.len();
            self.cmd_tx.push(Command::Send(chunk)).ok()?;
            self.lent.sent(n);
            return Some(n);
        }
        // The run of slices to copy: this one and those after it, up to
        // (not including) the next one that is part of the lent body.
        let lent = &self.lent;
        let run = || {
            std::iter::once(first).chain(
                bufs[position.index + 1..]
                    .iter()
                    .map(|buf| &**buf)
                    .take_while(|buf| buf.is_empty() || lent.slice_of(buf).is_none()),
            )
        };
        let len = run().map(<[u8]>::len).sum::<usize>().min(credit);
        // Copy only the prefix covered by byte credit: into DMA memory
        // (possibly a shorter prefix, up to the end of the writer's
        // current block), else to the heap.
        let staged = self
            .writer
            .as_mut()
            .and_then(|writer| writer.copy_parts(run(), len));
        let chunk = match &staged {
            Some(chunk) => chunk.clone(),
            None => {
                let mut heap = Vec::with_capacity(len);
                for part in run() {
                    let take = part.len().min(len - heap.len());
                    heap.extend_from_slice(&part[..take]);
                }
                // Shared from the start: the worker clones every segment
                // into its retransmit queue, and the first clone of a
                // Vec-backed `Bytes` allocates its refcount -- a malloc on
                // the lcore. `from_owner` pays for it here, on the app
                // thread, and its clones never allocate.
                Bytes::from_owner(heap)
            }
        };
        let n = chunk.len();
        if self.cmd_tx.push(Command::Send(chunk)).is_err() {
            // Not sent after all: give the space back to the writer.
            if let (Some(writer), Some(chunk)) = (self.writer.as_mut(), staged) {
                writer.undo(chunk);
            }
            return None;
        }
        Some(n)
    }

    /// One attempt at `poll_shutdown`.
    fn try_shutdown(&mut self) -> Poll<io::Result<()>> {
        if let Some(error) = self.aborted() {
            return Poll::Ready(Err(error));
        }
        if self.cmd_tx.is_closed() || self.cmd_tx.failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // Half-close: enqueue a FIN. Reading may continue afterward.
        match self.cmd_tx.push(Command::Close) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_full) => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(data)])
    }

    /// hyper's h1 connection checks [`is_write_vectored`] once: when true
    /// it queues body `Bytes` behind the head instead of copying them into
    /// its own buffer first, and h2/rustls hand over several frames or
    /// records per call. All of them are gathered here into as few ring
    /// commands as the limits allow.
    ///
    /// [`is_write_vectored`]: AsyncWrite::is_write_vectored
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Poll::Ready(done) = this.try_write(bufs) {
            return Poll::Ready(done);
        }
        if !this.wait(cx) {
            return Poll::Pending;
        }
        this.try_write(bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
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
        if let Poll::Ready(done) = this.try_shutdown() {
            return Poll::Ready(done);
        }
        if !this.wait(cx) {
            return Poll::Pending;
        }
        this.try_shutdown()
    }
}

impl TcpStream {
    /// The stream's DMA writer, when the port attaches DMA memory to
    /// packets without copying (the same condition `poll_write` uses);
    /// `None` otherwise, and owned data sent with
    /// [`poll_send`](Self::poll_send) should come from the ordinary heap.
    /// For callers that generate their bytes (e.g. masking) and want to
    /// write them once, straight into memory the engine can transmit.
    pub fn dma_writer(&mut self) -> Option<&mut DmaWriter> {
        self.writer.as_mut()
    }

    /// An open stream with no worker behind it, plus the worker's ends of
    /// its rings, for tests elsewhere in the crate. Writes have no DMA
    /// writer (no EAL in unit tests).
    #[cfg(test)]
    pub(crate) fn test_stream() -> (
        TcpStream,
        crate::dpdk::tcp::worker::CmdRx,
        crate::dpdk::tcp::worker::InboundTx,
        Arc<crate::dpdk::tcp::worker::SendCredit>,
    ) {
        let (cmd_tx, cmd_rx, credit) = crate::dpdk::tcp::worker::command_channel();
        let (inbound_tx, inbound_rx) = crate::dpdk::tcp::worker::inbound_channel();
        let stream = TcpStream {
            cmd_tx,
            inbound_rx,
            flush: None,
            wake: None,
            state: StreamState::Open,
            read_chunk: None,
            writer: None,
            lent: LentBody::Empty,
        };
        (stream, cmd_rx, inbound_tx, credit)
    }
}

// Dropping the stream drops its command sender; the worker observes the
// closed ring and closes the engine-side connection (sending a FIN), so
// no explicit teardown message is needed here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpdk::tcp::worker::{CmdRx, InboundTx, SEND_CAPACITY};
    use crate::dpdk::testing::slice;

    /// The worker clones each sent chunk into its retransmit queue (and
    /// slices it into segments). That must never allocate on the lcore, so
    /// every chunk arrives already shared -- including the heap copy a write
    /// without DMA memory makes, and a caller's Vec-backed `Bytes`.
    #[test]
    fn sent_chunks_clone_on_the_worker_without_allocating() {
        use crate::allocations::count_allocations;
        let (mut stream, rx, _tx, _credit) = TcpStream::test_stream();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let check = |what: &str| {
            let Some(Command::Send(sent)) = rx.pop() else {
                panic!("{what}: nothing sent")
            };
            let (_, allocations) = count_allocations(|| {
                let retransmit = std::hint::black_box(sent.clone());
                let segment = std::hint::black_box(sent.slice(..sent.len() / 2));
                drop((retransmit, segment));
            });
            assert_eq!(allocations, 0, "{what}: the worker's clone allocated");
        };

        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &[1; 1024]),
            Poll::Ready(Ok(1024))
        ));
        check("poll_write heap copy");

        let mut owned = Some(Bytes::from(vec![2; 1024]));
        assert!(matches!(
            stream.poll_send(&mut cx, &mut owned),
            Poll::Ready(Ok(()))
        ));
        check("poll_send of a Vec-backed Bytes");
    }

    #[test]
    fn writes_stop_at_byte_limit_even_after_worker_drains_ring() {
        let (mut stream, rx, _tx, credit) = TcpStream::test_stream();
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
        let (mut stream, rx, _tx, credit) = TcpStream::test_stream();
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
        let (mut stream, _rx, tx, _credit) = TcpStream::test_stream();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for b in [b"first".as_slice(), b"second".as_slice()] {
            assert!(tx.push(Inbound::Data(slice(b))).is_ok());
        }
        assert!(tx.push(Inbound::Reset).is_ok());
        drop(tx);
        for _ in 0..100 {
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b""),
                Poll::Ready(Ok(0))
            ));
        }
        assert!(stream.read_chunk.is_some());
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
        let (mut stream, _rx, tx, credit) = TcpStream::test_stream();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(tx.push(Inbound::Data(slice(b"unread"))).is_ok());
        stream.drain_inbound();
        credit.failed.store(true, Ordering::Release);
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"x"),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
        let mut data = Some(Bytes::from_static(b"x"));
        assert!(matches!(stream.poll_send(&mut cx, &mut data),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
        assert_eq!(
            stream.read_chunk.as_ref().unwrap().as_slice(),
            b"unread".as_slice()
        );
    }

    #[test]
    fn partial_read_keeps_only_one_staged_chunk() {
        let (mut stream, _rx, tx, _) = TcpStream::test_stream();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(tx.push(Inbound::Data(slice(b"abcd"))).is_ok());
        assert!(tx.push(Inbound::Data(slice(b"ef"))).is_ok());
        let mut storage = [0; 2];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"ab");
        stream.drain_inbound();
        assert_eq!(
            stream.read_chunk.as_ref().unwrap().as_slice(),
            b"cd".as_slice()
        );
        assert_eq!(stream.inbound_rx.len(), 1);
    }

    /// A stream wired to a ready list, with the worker's ends of its rings.
    fn parked_fixture() -> (
        TcpStream,
        CmdRx,
        InboundTx,
        crate::dpdk::tcp::app_wake::AppNotifier,
        Arc<AppWake>,
    ) {
        let (mut stream, cmd_rx, inbound_tx, _credit) = TcpStream::test_stream();
        let (notifier, ready) = crate::dpdk::tcp::app_wake::channel();
        let wake = ready.wake_handle();
        stream.wake = Some(Parker(wake.clone()));
        (stream, cmd_rx, inbound_tx, notifier, wake)
    }

    #[test]
    fn a_waiting_reader_never_misses_data_pushed_from_another_thread() {
        const CHUNKS: u32 = 300_000;
        let (mut stream, cmd_rx, inbound_tx, mut notifier, wake) = parked_fixture();

        // The worker's side: push, then notify, exactly as the lcore does.
        let worker = std::thread::spawn(move || {
            let _cmd_rx = cmd_rx;
            let mut next = 0u32;
            while next < CHUNKS {
                notifier.retry();
                let chunk = slice(&next.to_be_bytes());
                if inbound_tx.push(Inbound::Data(chunk)).is_ok() {
                    notifier.notify(&wake);
                    next += 1;
                    // Pause now and then so the reader really does wait.
                    if next % 61 == 0 {
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async {
                for expected in 0..CHUNKS {
                    let chunk = stream.recv_chunk().await.unwrap().unwrap();
                    assert_eq!(&chunk[..], &expected.to_be_bytes());
                }
            });
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the reader stalled: a wake-up was lost");
        worker.join().unwrap();
    }

    #[test]
    fn a_flush_request_reaches_a_stream_that_is_waiting() {
        let (mut stream, cmd_rx, _inbound_tx, _notifier, wake) = parked_fixture();
        let flush = FlushHandle::new();
        // No worker behind this stream: the request goes through the
        // stream, which has to be woken for it.
        stream.flush = Some(flush.attach(&wake, stream.cmd_tx.credit()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let reader = tokio::spawn(async move { stream.recv().await });
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(cmd_rx.pop().is_none());
            flush.flush();
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(false))));
            reader.abort();
        });
    }

    /// A connection that goes on to another request is corked again for
    /// it, under that request's handle, and the last request's handle no
    /// longer reaches it.
    #[test]
    fn a_reused_connection_is_corked_again_under_the_next_handle() {
        let (mut stream, cmd_rx, _inbound_tx, _notifier, _wake) = parked_fixture();
        let drain = || std::iter::from_fn(|| cmd_rx.pop()).collect::<Vec<_>>();

        let first = FlushHandle::new();
        stream.set_flush_handle(Some(&first));
        stream.request_cork();
        // Held, so not to be handed to another request yet.
        assert!(!stream.reusable());
        first.flush();
        assert!(stream.reusable());
        let commands = drain();
        assert!(matches!(commands.first(), Some(Command::SetCork(true))));
        assert!(matches!(commands.last(), Some(Command::SetCork(false))));

        // The next request: corked afresh, and held until its own flush.
        let second = FlushHandle::new();
        stream.set_flush_handle(Some(&second));
        stream.request_cork();
        assert!(matches!(drain()[..], [Command::SetCork(true)]));
        assert!(!stream.reusable());

        // A late flush on the first handle releases nothing.
        first.flush();
        stream.drain_flush();
        assert!(
            drain().is_empty(),
            "the old handle released the new request"
        );
        assert!(!stream.reusable());

        second.flush();
        stream.drain_flush();
        assert!(matches!(drain()[..], [Command::SetCork(false)]));
        assert!(stream.reusable());

        // A request with no handle leaves the connection free at once.
        stream.set_flush_handle(None);
        assert!(stream.reusable());
    }

    /// A connection the peer closed, or wrote on unasked, is not reused.
    #[test]
    fn a_closed_connection_is_not_reusable() {
        let (mut stream, _cmd_rx, inbound_tx, _credit) = TcpStream::test_stream();
        assert!(stream.reusable());
        drop(inbound_tx);
        assert!(!stream.reusable());

        let (mut stream, cmd_rx, _inbound_tx, _credit) = TcpStream::test_stream();
        drop(cmd_rx);
        assert!(!stream.reusable());
    }

    /// Terminated through its handle, a stream fails everything at once,
    /// by the handle's word alone, and is not kept for another request.
    #[test]
    fn a_terminated_stream_fails_everything() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, cmd_rx, _inbound_tx, _notifier, wake) = parked_fixture();
        let handle = FlushHandle::new();
        stream.flush = Some(handle.attach(&wake, stream.cmd_tx.credit()));
        stream.request_cork();
        assert!(!handle.is_aborted());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            // A request waiting on the stream is woken with the answer.
            let waiting = handle.clone();
            let reader = tokio::spawn(async move {
                let result = stream.recv().await;
                (stream, result)
            });
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(!reader.is_finished());
            waiting.abort();
            let (mut stream, result) = reader.await.unwrap();
            let aborted = |error: io::Error| error.kind() == io::ErrorKind::ConnectionAborted;
            assert!(aborted(result.unwrap_err()));
            assert!(aborted(
                stream.send(Bytes::from_static(b"x")).await.unwrap_err()
            ));
            assert!(aborted(stream.recv_chunk().await.unwrap_err()));
            assert!(aborted(stream.write_all(b"x").await.unwrap_err()));
            assert!(aborted(stream.read_u8().await.unwrap_err()));
            assert!(aborted(stream.shutdown().await.unwrap_err()));
            assert!(!stream.reusable());
            // Nothing was queued for the worker after the cork.
            assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(true))));
            assert!(cmd_rx.pop().is_none());
        });

        // A handle whose request is over reaches nothing: the connection
        // has gone on to another request, under another handle.
        let (mut stream, _cmd_rx, _inbound_tx, _notifier, _wake) = parked_fixture();
        let first = FlushHandle::new();
        stream.set_flush_handle(Some(&first));
        first.flush();
        let second = FlushHandle::new();
        stream.set_flush_handle(Some(&second));
        first.abort();
        assert!(stream.aborted().is_none());
        second.flush();
        assert!(stream.reusable());
        // And one terminated before it is paired ends what it is given.
        let late = FlushHandle::new();
        late.abort();
        stream.set_flush_handle(Some(&late));
        assert!(stream.aborted().is_some());
        assert!(!stream.reusable());
    }

    /// A flush is final and cannot come too early: whenever it happens,
    /// the request ends up not held.
    #[test]
    fn a_flush_before_the_cork_means_the_request_is_never_held() {
        // Flushed before the connection is even attached: no cork at all.
        let (mut stream, cmd_rx, _inbound_tx, _notifier, wake) = parked_fixture();
        let flush = FlushHandle::new();
        flush.flush();
        stream.flush = Some(flush.attach(&wake, stream.cmd_tx.credit()));
        stream.request_cork();
        let mut commands = Vec::new();
        while let Some(command) = cmd_rx.pop() {
            commands.push(command);
        }
        assert!(
            !commands
                .iter()
                .any(|command| matches!(command, Command::SetCork(true))),
            "a released request was corked"
        );

        // Flushed after attaching but before the cork (during the
        // handshakes): the same.
        let (mut stream, cmd_rx, _inbound_tx, _notifier, wake) = parked_fixture();
        let flush = FlushHandle::new();
        stream.flush = Some(flush.attach(&wake, stream.cmd_tx.credit()));
        flush.flush();
        stream.request_cork();
        let mut corked = false;
        while let Some(command) = cmd_rx.pop() {
            if let Command::SetCork(cork) = command {
                corked = cork;
            }
        }
        assert!(!corked);

        // Corked first, flushed later: the uncork follows the cork, and a
        // second flush adds nothing.
        let (mut stream, cmd_rx, _inbound_tx, _notifier, wake) = parked_fixture();
        let flush = FlushHandle::new();
        stream.flush = Some(flush.attach(&wake, stream.cmd_tx.credit()));
        stream.request_cork();
        assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(true))));
        flush.flush();
        stream.drain_flush();
        assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(false))));
        flush.flush();
        stream.drain_flush();
        assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(false)) | None));
        // And corking again after the flush does nothing.
        stream.request_cork();
        assert!(cmd_rx.pop().is_none());

        // Without a handle the stream corks as asked.
        let (stream, cmd_rx, _inbound_tx, _notifier, _wake) = parked_fixture();
        stream.request_cork();
        assert!(matches!(cmd_rx.pop(), Some(Command::SetCork(true))));
        assert!(cmd_rx.pop().is_none());
    }

    #[test]
    fn without_a_runtime_a_waiting_stream_keeps_itself_awake() {
        let (mut stream, _cmd_rx, _inbound_tx, _notifier, _wake) = parked_fixture();
        struct Count(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(Count(std::sync::atomic::AtomicUsize::new(0)));
        let waker = std::task::Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(stream.poll_recv(&mut cx).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
    }

    fn write_vectored(stream: &mut TcpStream, bufs: &[&[u8]]) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let slices: Vec<IoSlice<'_>> = bufs.iter().map(|buf| IoSlice::new(buf)).collect();
        Pin::new(stream).poll_write_vectored(&mut cx, &slices)
    }

    fn pop_send(rx: &CmdRx) -> Bytes {
        match rx.pop() {
            Some(Command::Send(bytes)) => bytes,
            Some(_) => panic!("expected a Send, got another command"),
            None => panic!("expected a Send, ring is empty"),
        }
    }

    #[test]
    fn a_vectored_write_gathers_its_slices_into_one_send() {
        let (mut stream, rx, _tx, _credit) = TcpStream::test_stream();
        assert!(stream.is_write_vectored());
        assert!(matches!(
            write_vectored(&mut stream, &[b"head", b"", b"body", b"tail"]),
            Poll::Ready(Ok(12))
        ));
        assert_eq!(pop_send(&rx), b"headbodytail".as_slice());
        assert!(rx.is_empty());
        // All slices empty: nothing to do, and nothing enqueued.
        assert!(matches!(
            write_vectored(&mut stream, &[b"", b""]),
            Poll::Ready(Ok(0))
        ));
        assert!(rx.is_empty());
    }

    #[test]
    fn a_vectored_write_stops_mid_slice_at_the_byte_limit_and_resumes_in_order() {
        let (mut stream, rx, _tx, credit) = TcpStream::test_stream();
        credit.bytes.fetch_add(SEND_CAPACITY - 6, Ordering::AcqRel);
        assert!(matches!(
            write_vectored(&mut stream, &[b"abcd", b"efgh", b"ij"]),
            Poll::Ready(Ok(6))
        ));
        assert_eq!(pop_send(&rx), b"abcdef".as_slice());
        // Out of credit: Pending, with nothing staged.
        assert!(write_vectored(&mut stream, &[b"gh", b"ij"]).is_pending());
        assert!(rx.is_empty());
        credit.bytes.fetch_sub(SEND_CAPACITY, Ordering::AcqRel);
        assert!(matches!(
            write_vectored(&mut stream, &[b"gh", b"ij"]),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(pop_send(&rx), b"ghij".as_slice());
    }

    #[test]
    fn a_vectored_write_stops_when_the_ring_fills_and_stages_nothing_on_pending() {
        let (mut stream, rx, _tx, _credit) = TcpStream::test_stream();
        let body = Bytes::from(vec![9; 100]);
        stream.lend_body(&body);
        // Leave room for exactly one command.
        while stream.cmd_tx.len() < stream.cmd_tx.capacity() - 1 {
            assert!(stream.cmd_tx.push(Command::Flush).is_ok());
        }
        // The head takes the last slot; the body has to wait.
        assert!(matches!(
            write_vectored(&mut stream, &[b"head", &body]),
            Poll::Ready(Ok(4))
        ));
        assert!(write_vectored(&mut stream, &[&body]).is_pending());
        let lent_untouched = matches!(stream.lent, LentBody::Lent { unsent: 100, .. });
        assert!(lent_untouched);
        while let Some(command) = rx.pop() {
            if let Command::Send(head) = command {
                assert_eq!(head, b"head".as_slice());
            }
        }
        assert!(matches!(
            write_vectored(&mut stream, &[&body]),
            Poll::Ready(Ok(100))
        ));
        assert_eq!(pop_send(&rx).as_ptr(), body.as_ptr());
    }

    #[test]
    fn lent_body_slices_go_out_uncopied_across_credit_stalls() {
        let (mut stream, rx, _tx, credit) = TcpStream::test_stream();
        let body = Bytes::from(vec![5; SEND_CAPACITY + 100]);
        stream.lend_body(&body);
        let head = b"POST / HTTP/1.1\r\n\r\n";
        let Poll::Ready(Ok(n)) = write_vectored(&mut stream, &[head, &body]) else {
            panic!("the first write must be accepted");
        };
        assert_eq!(n, SEND_CAPACITY);
        let sent_head = pop_send(&rx);
        assert_eq!(sent_head, head.as_slice());
        assert_ne!(sent_head.as_ptr(), head.as_ptr());
        let first = pop_send(&rx);
        assert_eq!(first.as_ptr(), body.as_ptr());
        assert_eq!(first.len(), SEND_CAPACITY - head.len());
        assert!(rx.is_empty());

        // The caller retries with the rest, a sub-slice of the body.
        let rest = &body[first.len()..];
        assert!(write_vectored(&mut stream, &[rest]).is_pending());
        credit.bytes.fetch_sub(SEND_CAPACITY, Ordering::AcqRel);
        assert!(matches!(
            write_vectored(&mut stream, &[rest]),
            Poll::Ready(Ok(n)) if n == rest.len()
        ));
        let second = pop_send(&rx);
        assert_eq!(second.as_ptr(), rest.as_ptr());
        assert_eq!(second.len(), rest.len());
        // All of it went out as slices: the stream lets go of the body.
        assert!(matches!(stream.lent, LentBody::Empty));
    }

    /// The lending decision, with the EAL memory check stubbed: telling
    /// heap from EAL memory needs EAL, which unit tests don't start.
    #[test]
    fn a_writer_lends_only_dma_bodies_and_asks_only_once() {
        let body = Bytes::from(vec![3; 32]);
        let lent = |state: &LentBody| matches!(state, LentBody::Lent { unsent: 32, .. });
        // No writer: always lent, and EAL is never consulted.
        assert!(lent(&LentBody::new(&body, false, || panic!(
            "no EAL check without a writer"
        ))));
        // A writer and a heap body: left to be copied into the writer.
        let mut asked = 0;
        let heap = LentBody::new(&body, true, || {
            asked += 1;
            false
        });
        assert!(matches!(heap, LentBody::Empty));
        // A writer and a DMA body: lent.
        let dma = LentBody::new(&body, true, || {
            asked += 1;
            true
        });
        assert!(lent(&dma));
        assert_eq!(asked, 2);
        // Empty bodies are never lent, and need no check.
        assert!(matches!(
            LentBody::new(&Bytes::new(), true, || panic!("no check for an empty body")),
            LentBody::Empty
        ));
    }

    #[test]
    fn slices_outside_the_lent_body_are_copied() {
        let (mut stream, rx, _tx, _credit) = TcpStream::test_stream();
        let body = Bytes::from(vec![1; 64]);
        stream.lend_body(&body);
        // Same contents, different memory.
        let lookalike = vec![1; 64];
        // Straddles the end of the body.
        let wider = body.slice(32..);
        let mut outside = wider.to_vec();
        outside.extend_from_slice(&[2; 8]);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(
                &mut Context::from_waker(std::task::Waker::noop()),
                &lookalike
            ),
            Poll::Ready(Ok(64))
        ));
        let copied = pop_send(&rx);
        assert_ne!(copied.as_ptr(), lookalike.as_ptr());
        assert_ne!(copied.as_ptr(), body.as_ptr());
        assert!(matches!(
            write_vectored(&mut stream, &[&outside]),
            Poll::Ready(Ok(40))
        ));
        assert_ne!(pop_send(&rx).as_ptr(), body.as_ptr());
        // Through poll_write too, a slice inside the body is not copied.
        assert!(matches!(
            Pin::new(&mut stream).poll_write(
                &mut Context::from_waker(std::task::Waker::noop()),
                &body[10..20]
            ),
            Poll::Ready(Ok(10))
        ));
        assert_eq!(pop_send(&rx).as_ptr(), body[10..].as_ptr());
    }

    /// hyper's h1 connection sees `is_write_vectored` and queues the body
    /// `Bytes` instead of flattening it into its head buffer, so a lent
    /// body reaches the ring as its own `Send`, pointing into the original.
    #[test]
    fn hyper_h1_writes_a_lent_body_without_copying_it() {
        use http_body_util::Full;
        use hyper_util::rt::TokioIo;

        let (mut stream, rx, _tx, _credit) = TcpStream::test_stream();
        let body = Bytes::from(vec![b'x'; 100 * 1024]);
        stream.lend_body(&body);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut send_request, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
            let conn = tokio::spawn(conn);
            let request = http::Request::post("/upload")
                .header(http::header::HOST, "example.com")
                .body(Full::new(body.clone()))
                .unwrap();
            let response = tokio::spawn(async move { send_request.send_request(request).await });
            let mut sends = Vec::new();
            let mut total = 0;
            for _ in 0..1000 {
                tokio::task::yield_now().await;
                while let Some(command) = rx.pop() {
                    if let Command::Send(bytes) = command {
                        total += bytes.len();
                        sends.push(bytes);
                    }
                }
                if total > body.len() {
                    break;
                }
            }
            assert_eq!(sends.len(), 2, "head and body, each in one Send");
            assert!(sends[0].starts_with(b"POST /upload HTTP/1.1\r\n"));
            assert!(sends[0].ends_with(b"\r\n\r\n"));
            assert_eq!(sends[1].as_ptr(), body.as_ptr());
            assert_eq!(sends[1].len(), body.len());
            response.abort();
            conn.abort();
        });
    }
}

#[cfg(test)]
mod read_benchmark;

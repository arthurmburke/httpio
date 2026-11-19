//! A hand-rolled HTTP/2 client codec, the multiplexed counterpart of the
//! HTTP/1.1 codec in [`h1`](super::h1), used for `https://` requests whose
//! ALPN negotiation chose `h2` in place of hyper.
//!
//! Like `h1` it runs over any [`Transport`] and moves owned buffers both
//! ways, never borrowed slices through `AsyncRead`/`AsyncWrite`:
//!
//! - **Requests**: the HEADERS frame is encoded once into a buffer the
//!   connection keeps, with the DATA frame header and a small body right
//!   behind it, so a request is one buffer handed to the transport (one
//!   TLS record, one segment). The connection preface and SETTINGS ride in
//!   front of the first request the same way. Larger bodies go out as
//!   slices of the caller's `Bytes`, untouched, between nine-byte frame
//!   headers. Header compression uses only HPACK's static table (see
//!   [`hpack`]), so encoding a head has no per-connection state.
//! - **Responses**: frames are parsed in place in the chunks the transport
//!   delivers. A DATA payload is handed out as slices of those chunks
//!   (views of packet buffers over plain TCP, plaintext `Bytes` over TLS)
//!   as they arrive, whether or not the frame is complete; only a frame
//!   header or a control frame that straddles chunks is gathered, and then
//!   only its own bytes.
//!
//! # Who drives the connection
//!
//! There is no task that owns the transport and no channel to it. The
//! connection's state sits behind one lock, and whichever request task is
//! being polled does the I/O itself: it encodes its request straight into
//! the write buffer, sends it, reads from the transport and dispatches
//! whatever frames arrive -- its own, and those of other streams, whose
//! tasks it wakes. A lone request therefore costs no task switch at all:
//! the task that asked is the one the transport wakes, and it parses its
//! own response.
//!
//! The [`Connection`] future returned by [`handshake`] is the fallback
//! driver: it holds the connection's place with the transport whenever no
//! request task does (between requests, or when the task that was reading
//! got its answer and left), answering PINGs and SETTINGS and noticing
//! GOAWAY and the end of the connection. It must be spawned, as hyper's
//! connection future must be.
//!
//! A response body that is being read keeps its task in charge of the
//! transport between chunks only while it is the connection's only stream;
//! with other streams open, a task that returns data always hands the
//! transport back first, so a body nobody reads stalls only itself.
//!
//! # Flow control
//!
//! The receive windows are hyper's defaults ([`STREAM_WINDOW`],
//! [`CONNECTION_WINDOW`]) and are replenished as the application takes
//! body data, half a window at a time. Sending obeys the peer's windows
//! and frame size limit; a body larger than its window is sent on as
//! WINDOW_UPDATEs arrive, by the task reading the response.
//!
//! # Scope
//!
//! A client, speaking to servers: no server push (refused in SETTINGS; a
//! PUSH_PROMISE is a connection error), no priorities (ignored), no
//! extended CONNECT. Trailers are read and discarded, as in `h1`. The
//! response side parses untrusted input: frame sizes, header block size
//! ([`MAX_HEADER_LIST_SIZE`], [`MAX_HEADERS`]), interim responses and
//! queued control replies are all bounded, flow-control arithmetic is
//! checked, and malformed input is an error, never a panic.

mod frame;
mod hpack;
mod huffman;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{Stream as FuturesStream, StreamExt};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode, Version, request, response};
use serde::de::DeserializeOwned;

use crate::core::hashmap::HashMap;
use crate::dpdk::http::RecvBuf;
use crate::dpdk::http::h1;
use crate::http::codec::{self, EncodedBody};
use crate::http::errors::HttpError;

use frame::{FRAME_HEADER_LEN, FrameHead, MAX_WINDOW, be32, flag, kind, setting};

pub use super::h1::Transport;
pub use frame::Reason;

/// The receive window offered for each stream (`SETTINGS_INITIAL_WINDOW_SIZE`).
pub const STREAM_WINDOW: u32 = 2 * 1024 * 1024;
/// The receive window offered for the connection as a whole.
pub const CONNECTION_WINDOW: u32 = 5 * 1024 * 1024;
/// Largest frame payload accepted: the protocol default, which this client
/// does not raise.
pub const MAX_FRAME_SIZE: usize = 16 * 1024;
/// Largest decoded response head accepted (names, values and 32 bytes per
/// field), advertised as `SETTINGS_MAX_HEADER_LIST_SIZE`.
pub const MAX_HEADER_LIST_SIZE: usize = h1::MAX_HEAD_SIZE;
/// Most header fields accepted in one response head.
pub const MAX_HEADERS: usize = h1::MAX_HEADERS;
/// Most interim (1xx) responses skipped before the final response.
pub const MAX_INTERIM_RESPONSES: usize = h1::MAX_INTERIM_RESPONSES;

/// Largest compressed header block accepted across HEADERS and
/// CONTINUATION frames.
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// The window every stream and the connection start with (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: u32 = 65_535;
/// Largest DATA frame sent, however large a frame the peer allows: a frame
/// cannot be interleaved with other streams' frames.
const MAX_SEND_FRAME: usize = 256 * 1024;
/// A request body shorter than this is copied behind its frame header so
/// that head and body leave as one buffer; a longer one is sent as a slice
/// of the caller's `Bytes`.
const COPY_BODY_BELOW: usize = 1024;
/// Bound on replies (SETTINGS and PING acknowledgements) queued while the
/// transport is not accepting writes; a peer that makes us queue more is
/// flooding.
const MAX_PENDING_CONTROL: usize = 64 * 1024;
/// Chunks processed per turn when reading on behalf of other streams,
/// before yielding to the executor.
const READ_BUDGET: usize = 32;
/// Stream identifiers are 31 bits; a client's are odd.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
/// `current` when no stream's own task is polling.
const NO_STREAM: usize = usize::MAX;
/// Most bytes [`Body::collect`] reserves up front from a `Content-Length`.
const MAX_COLLECT_RESERVE: u64 = 16 * 1024 * 1024;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Why a request or response failed. Kept apart from [`HttpError`] (which
/// reports all of these as [`HttpError::Protocol`]) so the cause stays
/// visible to tests and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2Error {
    /// The transport failed.
    Io(io::ErrorKind),
    /// The connection ended (or its [`Connection`] was dropped) before the
    /// response was complete.
    Closed,
    /// The peer broke the protocol; the connection was closed with this
    /// error code.
    Protocol(Reason),
    /// The peer closed the connection with this error code (GOAWAY).
    GoAway(Reason),
    /// The peer did not process the request (`REFUSED_STREAM`, or a GOAWAY
    /// that excludes it): it is safe to send again on a new connection.
    Refused,
    /// The peer reset the stream with this error code.
    Reset(Reason),
    /// The response was malformed (RFC 9113 §8.1.1): bad or missing
    /// `:status`, a pseudo-header field out of place, DATA before the
    /// head, an invalid `content-length`.
    MalformedResponse,
    /// More than [`MAX_INTERIM_RESPONSES`] interim responses.
    TooManyInterimResponses,
    /// The body's length disagreed with the response's `content-length`.
    LengthMismatch,
    /// The request body's producer failed, or broke the length it
    /// announced.
    RequestBody,
}

impl From<H2Error> for HttpError {
    fn from(_: H2Error) -> Self {
        HttpError::Protocol
    }
}

// ---------------------------------------------------------------------------
// Waking
// ---------------------------------------------------------------------------

/// The one waker the transport ever sees. It forwards to the request task
/// currently in charge of the transport, if there is one, and otherwise to
/// the [`Connection`] driver.
struct ConnWake {
    slots: Mutex<WakeSlots>,
    /// Set before each transport poll and cleared when the transport wakes
    /// us or the poll completes: while it is set, the transport holds this
    /// waker. May read `false` while the waker is still held (never the
    /// reverse), which costs a redundant poll, not a missed wake-up.
    armed: AtomicBool,
    /// More than one stream is open: the driver is woken along with the
    /// task, to take over if the task does not come back.
    multi: AtomicBool,
}

#[derive(Default)]
struct WakeSlots {
    task: Option<Waker>,
    driver: Option<Waker>,
}

impl ConnWake {
    fn slots(&self) -> MutexGuard<'_, WakeSlots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_task(&self, waker: &Waker) {
        let mut slots = self.slots();
        match &slots.task {
            Some(task) if task.will_wake(waker) => {}
            _ => slots.task = Some(waker.clone()),
        }
    }

    fn clear_task(&self) {
        let task = self.slots().task.take();
        drop(task);
    }

    fn set_driver(&self, waker: &Waker) {
        let mut slots = self.slots();
        match &slots.driver {
            Some(driver) if driver.will_wake(waker) => {}
            _ => slots.driver = Some(waker.clone()),
        }
    }

    fn has_task(&self) -> bool {
        self.slots().task.is_some()
    }

    fn has_driver(&self) -> bool {
        self.slots().driver.is_some()
    }

    fn wake_driver(&self) {
        if let Some(driver) = &self.slots().driver {
            driver.wake_by_ref();
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }
}

impl Wake for ConnWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.disarm();
        let slots = self.slots();
        match &slots.task {
            Some(task) => {
                task.wake_by_ref();
                if self.multi.load(Ordering::SeqCst)
                    && let Some(driver) = &slots.driver
                {
                    driver.wake_by_ref();
                }
            }
            None => {
                if let Some(driver) = &slots.driver {
                    driver.wake_by_ref();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Frames on their way out, in order: `queue`, then `buf`.
struct Writer {
    /// Frames being assembled. Everything but large DATA payloads is
    /// written here, so consecutive frames leave as one buffer.
    buf: BytesMut,
    /// Finished buffers: runs of `buf` and the body slices between them.
    /// The transport takes them from the front, and leaves what it has
    /// not yet taken.
    queue: VecDeque<Bytes>,
    /// The transport did not take everything it was last offered.
    blocked: bool,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(16 * 1024),
            queue: VecDeque::new(),
            blocked: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.buf.is_empty()
    }

    fn clear(&mut self) {
        self.blocked = false;
        self.queue.clear();
        self.buf.clear();
    }

    /// Moves the frames assembled so far behind the queued buffers.
    fn seal(&mut self) {
        if !self.buf.is_empty() {
            let frames = self.buf.split().freeze();
            self.queue.push_back(frames);
        }
    }

    fn head(&mut self, len: usize, kind: u8, flags: u8, stream: u32) {
        let head = FrameHead {
            len: len as u32,
            kind,
            flags,
            stream,
        };
        self.buf.put_slice(&head.encode());
    }

    /// A DATA frame. `payload` is at most the peer's frame size limit.
    fn data(&mut self, stream: u32, payload: Bytes, end_stream: bool) {
        let flags = if end_stream { flag::END_STREAM } else { 0 };
        self.head(payload.len(), kind::DATA, flags, stream);
        if payload.len() < COPY_BODY_BELOW {
            self.buf.put_slice(&payload);
        } else {
            self.seal();
            self.queue.push_back(payload);
        }
    }

    fn window_update(&mut self, stream: u32, increment: u32) {
        self.head(4, kind::WINDOW_UPDATE, 0, stream);
        self.buf.put_u32(increment);
    }

    fn rst_stream(&mut self, stream: u32, reason: Reason) {
        self.head(4, kind::RST_STREAM, 0, stream);
        self.buf.put_u32(reason.0);
    }

    fn goaway(&mut self, reason: Reason) {
        self.head(8, kind::GOAWAY, 0, 0);
        // No server-initiated stream was ever processed.
        self.buf.put_u32(0);
        self.buf.put_u32(reason.0);
    }

    fn settings_ack(&mut self) {
        self.head(0, kind::SETTINGS, flag::ACK, 0);
    }

    fn ping_ack(&mut self, payload: &[u8]) {
        self.head(payload.len(), kind::PING, flag::ACK, 0);
        self.buf.put_slice(payload);
    }

    /// The client connection preface: the magic, our SETTINGS, and the
    /// WINDOW_UPDATE that raises the connection window from its default.
    fn preface(&mut self) {
        self.buf.put_slice(PREFACE);
        self.head(18, kind::SETTINGS, 0, 0);
        for (id, value) in [
            (setting::ENABLE_PUSH, 0),
            (setting::INITIAL_WINDOW_SIZE, STREAM_WINDOW),
            (setting::MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST_SIZE as u32),
        ] {
            self.buf.put_u16(id);
            self.buf.put_u32(value);
        }
        self.window_update(0, CONNECTION_WINDOW - DEFAULT_WINDOW);
    }
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

/// A streamed request body, as its producer hands it over.
type BodyStream = Pin<Box<dyn FuturesStream<Item = Result<Bytes, HttpError>> + Send>>;

/// What is left of a request body to send.
enum Upload {
    /// Nothing: there was no body, it has all been framed, or the stream
    /// ended first.
    Done,
    /// The rest of a buffered body.
    Full(Bytes),
    Stream(StreamUpload),
}

struct StreamUpload {
    stream: BodyStream,
    /// The part of the current chunk not yet framed.
    chunk: Bytes,
    /// The caller's `content-length`, which the body must add up to.
    declared: Option<u64>,
    /// Bytes taken from `stream` so far.
    produced: u64,
}

/// Where the response stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recv {
    /// Waiting for the final response head.
    Head,
    /// The head arrived; DATA (or trailers) may follow.
    Body,
    /// The response ended cleanly.
    End,
    /// The stream failed.
    Failed(H2Error),
}

/// How much body the response may still carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyLength {
    /// No `content-length`: whatever arrives before END_STREAM.
    Unknown,
    /// Exactly this many more bytes (zero from the start for responses
    /// that cannot have a body).
    Exact(u64),
}

/// Received payload waiting for the application: one slot inline, since a
/// small response is a single slice, then a queue.
struct DataQueue<B> {
    front: Option<B>,
    more: VecDeque<B>,
}

impl<B> DataQueue<B> {
    fn new() -> Self {
        Self {
            front: None,
            more: VecDeque::new(),
        }
    }

    fn push(&mut self, slice: B) {
        if self.front.is_none() && self.more.is_empty() {
            self.front = Some(slice);
        } else {
            self.more.push_back(slice);
        }
    }

    fn pop(&mut self) -> Option<B> {
        self.front.take().or_else(|| self.more.pop_front())
    }

    fn is_empty(&self) -> bool {
        self.front.is_none() && self.more.is_empty()
    }

    fn clear(&mut self) {
        self.front = None;
        self.more.clear();
    }
}

/// One request/response exchange. Lives in the connection's slab from
/// [`SendRequest::send`] until its [`ResponseFuture`] or [`Body`] is done
/// with it, which may be after the stream itself has closed.
struct Stream<B> {
    /// The stream identifier; 0 until the request is sent.
    id: u32,
    /// Counted against the peer's concurrency limit and reachable by
    /// identifier: from the request being sent until the response ends or
    /// the stream is reset.
    open: bool,
    recv: Recv,
    /// The final response head, until the response future takes it.
    head: Option<response::Parts>,
    data: DataQueue<B>,
    /// Bytes in `data`.
    buffered: usize,
    length: BodyLength,
    /// The `content-length` of a response that may have a body.
    length_hint: Option<u64>,
    /// A HEAD request: the response has no body whatever it announces.
    head_request: bool,
    interim: usize,
    /// How much more the peer may send on this stream.
    recv_window: i64,
    /// Bytes the application took that the peer has not been credited.
    unreleased: u32,
    /// How much more we may send on this stream.
    send_window: i64,
    upload: Upload,
    /// Waiting for connection-level send window (listed in `conn_blocked`).
    conn_blocked: bool,
    /// Waiting for the write queue to drain (listed in `write_waiters`).
    write_blocked: bool,
    /// The request itself failed (its body's producer did); reported in
    /// place of the stream error.
    request_error: Option<HttpError>,
    /// The request, while the peer's concurrency limit keeps it from
    /// being sent.
    pending: Option<Box<(request::Parts, EncodedBody)>>,
    /// The owning task, stored when it last returned `Pending`.
    waker: Option<Waker>,
}

impl<B> Stream<B> {
    fn new(head_request: bool) -> Self {
        Self {
            id: 0,
            open: false,
            recv: Recv::Head,
            head: None,
            data: DataQueue::new(),
            buffered: 0,
            length: BodyLength::Unknown,
            length_hint: None,
            head_request,
            interim: 0,
            recv_window: i64::from(STREAM_WINDOW),
            unreleased: 0,
            send_window: 0,
            upload: Upload::Done,
            conn_blocked: false,
            write_blocked: false,
            request_error: None,
            pending: None,
            waker: None,
        }
    }

    /// Whether the owning task has something to act on.
    fn has_event(&self) -> bool {
        self.head.is_some()
            || !self.data.is_empty()
            || matches!(self.recv, Recv::End | Recv::Failed(_))
    }
}

struct Slab<S> {
    entries: Vec<Option<S>>,
    free: Vec<usize>,
    len: usize,
}

impl<S> Slab<S> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    fn insert(&mut self, value: S) -> usize {
        self.len += 1;
        match self.free.pop() {
            Some(index) => {
                self.entries[index] = Some(value);
                index
            }
            None => {
                self.entries.push(Some(value));
                self.entries.len() - 1
            }
        }
    }

    fn remove(&mut self, index: usize) -> Option<S> {
        let value = self.entries.get_mut(index)?.take()?;
        self.free.push(index);
        self.len -= 1;
        Some(value)
    }

    fn get(&self, index: usize) -> Option<&S> {
        self.entries.get(index)?.as_ref()
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut S> {
        self.entries.get_mut(index)?.as_mut()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Where the frame parser is in the byte stream.
#[derive(Clone, Copy)]
enum Parse {
    /// Between frames, or inside a frame header (see `head_have`).
    Head,
    /// Inside a DATA frame.
    Data(DataFrame),
    /// Gathering the payload of another frame, which straddles chunks.
    Gather(FrameHead),
    /// Skipping this many bytes of padding.
    Skip(u32),
}

#[derive(Clone, Copy)]
struct DataFrame {
    id: u32,
    /// The slab index of the stream this frame was for when it started.
    /// Checked against `id` on each use: the slot may have been given to
    /// another stream between chunks.
    index: Option<usize>,
    /// Payload bytes still to come, padding excluded once it is known.
    remaining: u32,
    padding: u32,
    /// The pad length byte has not arrived yet.
    pad_pending: bool,
    end_stream: bool,
}

/// A header block continued in CONTINUATION frames.
#[derive(Clone, Copy)]
struct Continuation {
    id: u32,
    end_stream: bool,
}

/// Collects the fields of a response head as they are decoded.
struct HeadBuilder {
    /// `false` for a block nobody will read (trailers, a closed stream):
    /// it is decoded for the table's sake only.
    collect: bool,
    status: Option<StatusCode>,
    headers: HeaderMap,
    regular_seen: bool,
    malformed: bool,
}

impl HeadBuilder {
    fn new(collect: bool) -> Self {
        Self {
            collect,
            status: None,
            headers: if collect {
                HeaderMap::with_capacity(8)
            } else {
                HeaderMap::new()
            },
            regular_seen: false,
            malformed: false,
        }
    }

    fn field(&mut self, name: hpack::Name, value: HeaderValue) {
        match name {
            hpack::Name::Status => {
                // Pseudo-header fields come first and only once.
                if self.regular_seen || self.status.is_some() {
                    self.malformed = true;
                }
                match StatusCode::from_bytes(value.as_bytes()) {
                    Ok(status) => self.status = Some(status),
                    Err(_) => self.malformed = true,
                }
            }
            hpack::Name::Pseudo(_) => self.malformed = true,
            hpack::Name::Field(name) => {
                self.regular_seen = true;
                if self.collect {
                    self.headers.append(name, value);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------

struct Shared<T: Transport> {
    inner: Mutex<Inner<T>>,
    wake: Arc<ConnWake>,
    /// [`ConnWake`] as a `Waker`: what every transport poll is given.
    io_waker: Waker,
}

impl<T: Transport> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What reading from the transport came to.
#[derive(PartialEq, Eq)]
enum Read {
    /// A chunk was processed.
    Progress,
    /// Nothing to read yet; the transport holds the connection's waker.
    Pending,
    /// The connection is over.
    Closed,
}

struct Inner<T: Transport> {
    /// `None` once the connection is over.
    io: Option<T>,
    out: Writer,

    parse: Parse,
    /// The bytes of a frame header that straddles chunks.
    head_buf: [u8; FRAME_HEADER_LEN],
    head_have: usize,
    /// The payload of a control frame that straddles chunks.
    gather: BytesMut,
    continuation: Option<Continuation>,
    /// The header block being continued.
    block: BytesMut,
    hpack: hpack::Decoder,
    /// The server's preface (its first SETTINGS frame) has arrived.
    got_settings: bool,

    streams: Slab<Stream<T::Recv>>,
    /// Open streams by identifier.
    ids: HashMap<u32, usize>,
    next_id: u32,
    /// Open streams, against the peer's limit.
    active: usize,
    /// Streams waiting for the peer's concurrency limit, oldest first.
    pending_open: VecDeque<usize>,
    /// Streams waiting for connection-level send window.
    conn_blocked: Vec<usize>,
    /// Streams waiting for the write queue to drain.
    write_waiters: Vec<usize>,
    /// The stream whose own task is polling, which needs no wake-up.
    current: usize,

    peer_max_frame: usize,
    peer_initial_window: i64,
    peer_max_streams: usize,
    /// How much more we may send on the connection.
    send_window: i64,
    /// How much more the peer may send on the connection.
    recv_window: i64,
    /// Bytes consumed that the peer has not been credited.
    unreleased: u32,

    /// Why the connection can carry no more requests, once it cannot.
    error: Option<H2Error>,
    /// The peer sent GOAWAY: open streams may finish, no new ones start.
    goaway: bool,
    /// Our GOAWAY has been queued.
    goaway_sent: bool,
    /// [`SendRequest`] handles alive.
    handles: usize,
}

impl<T: Transport> Inner<T> {
    fn new(io: T) -> Self {
        let mut out = Writer::new();
        out.preface();
        Self {
            io: Some(io),
            out,
            parse: Parse::Head,
            head_buf: [0; FRAME_HEADER_LEN],
            head_have: 0,
            gather: BytesMut::new(),
            continuation: None,
            block: BytesMut::new(),
            hpack: hpack::Decoder::new(),
            got_settings: false,
            streams: Slab::new(),
            ids: HashMap::default(),
            next_id: 1,
            active: 0,
            pending_open: VecDeque::new(),
            conn_blocked: Vec::new(),
            write_waiters: Vec::new(),
            current: NO_STREAM,
            peer_max_frame: MAX_FRAME_SIZE,
            peer_initial_window: i64::from(DEFAULT_WINDOW),
            peer_max_streams: usize::MAX,
            send_window: i64::from(DEFAULT_WINDOW),
            recv_window: i64::from(CONNECTION_WINDOW),
            unreleased: 0,
            error: None,
            goaway: false,
            goaway_sent: false,
            handles: 1,
        }
    }

    // ---- lifecycle -------------------------------------------------------

    /// Whether a new request can be sent right away.
    fn can_open(&self) -> bool {
        self.accepting() && self.active < self.peer_max_streams
    }

    /// Whether the connection takes new requests at all.
    fn accepting(&self) -> bool {
        self.error.is_none() && !self.goaway && self.next_id <= MAX_STREAM_ID
    }

    /// Ends the connection: every unfinished stream fails with `error`,
    /// and `reason`, if given, is sent to the peer in a GOAWAY. The
    /// transport is dropped by [`settle`](Self::settle) once that has had
    /// its chance to go out.
    fn fail(&mut self, error: H2Error, reason: Option<Reason>) {
        if self.error.is_some() {
            return;
        }
        if let Some(reason) = reason
            && !self.goaway_sent
        {
            self.goaway_sent = true;
            self.out.goaway(reason);
        }
        self.error = Some(error);
        for index in 0..self.streams.entries.len() {
            if let Some(stream) = self.streams.get(index)
                && !matches!(stream.recv, Recv::End | Recv::Failed(_))
            {
                self.fail_stream(index, error);
            }
        }
    }

    /// After an error: gives queued output (a GOAWAY) one chance to leave,
    /// then drops the transport.
    fn settle(&mut self, io_cx: &mut Context<'_>, wake: &ConnWake) {
        if self.error.is_none() || self.io.is_none() {
            return;
        }
        if let Some(io) = self.io.as_mut() {
            self.out.seal();
            let _ = io.poll_send_queue(io_cx, &mut self.out.queue);
        }
        self.io = None;
        self.out.clear();
        wake.disarm();
        wake.wake_driver();
    }

    // ---- writing ---------------------------------------------------------

    /// Hands queued output to the transport until it is all out or the
    /// transport stops taking it.
    fn flush(&mut self, io_cx: &mut Context<'_>, wake: &ConnWake) {
        if self.out.is_empty() {
            return;
        }
        let Some(io) = self.io.as_mut() else {
            self.out.clear();
            return;
        };
        self.out.seal();
        wake.arm();
        match io.poll_send_queue(io_cx, &mut self.out.queue) {
            Poll::Ready(Ok(())) => {
                wake.disarm();
                self.out.blocked = false;
            }
            Poll::Ready(Err(error)) => {
                self.fail(H2Error::Io(error.kind()), None);
                self.settle(io_cx, wake);
                return;
            }
            Poll::Pending => {
                self.out.blocked = true;
                return;
            }
        }
        // Drained: streamed uploads held back by the queue may go on.
        if self.write_waiters.is_empty() {
            return;
        }
        for index in std::mem::take(&mut self.write_waiters) {
            if let Some(stream) = self.streams.get_mut(index) {
                stream.write_blocked = false;
                self.wake_stream(index);
            }
        }
    }

    /// Sends the request for the stream at `index`: assigns its identifier
    /// and encodes HEADERS, then as much of a buffered body as the windows
    /// allow.
    fn open_stream(&mut self, index: usize, parts: &request::Parts, body: EncodedBody) {
        let id = self.next_id;
        self.next_id += 2;
        self.active += 1;
        self.ids.insert(id, index);

        let (end_stream, content_length) = match &body {
            EncodedBody::Full(bytes) => {
                let announce = !parts.headers.contains_key(header::CONTENT_LENGTH)
                    && (!bytes.is_empty() || h1::anticipates_body(&parts.method));
                (bytes.is_empty(), announce.then_some(bytes.len() as u64))
            }
            EncodedBody::Stream(_) => (false, None),
        };
        // `send` checked that there is one.
        let authority = hpack::authority(&parts.uri, &parts.headers).unwrap_or(b"");

        let start = self.out.buf.len();
        self.out.buf.put_slice(&[0; FRAME_HEADER_LEN]);
        hpack::encode_request(
            &mut self.out.buf,
            &parts.method,
            &parts.uri,
            authority,
            &parts.headers,
            content_length,
        );
        let len = self.out.buf.len() - start - FRAME_HEADER_LEN;
        let end_flag = if end_stream { flag::END_STREAM } else { 0 };
        if len <= self.peer_max_frame {
            let head = FrameHead {
                len: len as u32,
                kind: kind::HEADERS,
                flags: flag::END_HEADERS | end_flag,
                stream: id,
            };
            self.out.buf[start..start + FRAME_HEADER_LEN].copy_from_slice(&head.encode());
        } else {
            // A block too large for one frame: HEADERS, then CONTINUATIONs.
            let block = self.out.buf.split_off(start + FRAME_HEADER_LEN);
            self.out.buf.truncate(start);
            let mut pieces = block.chunks(self.peer_max_frame).peekable();
            let mut first = true;
            while let Some(piece) = pieces.next() {
                let last = pieces.peek().is_none();
                let end_headers = if last { flag::END_HEADERS } else { 0 };
                if first {
                    self.out
                        .head(piece.len(), kind::HEADERS, end_headers | end_flag, id);
                } else {
                    self.out
                        .head(piece.len(), kind::CONTINUATION, end_headers, id);
                }
                self.out.buf.put_slice(piece);
                first = false;
            }
        }

        let declared = h1::content_length(&parts.headers).ok().flatten();
        let peer_initial_window = self.peer_initial_window;
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        stream.id = id;
        stream.open = true;
        stream.send_window = peer_initial_window;
        stream.upload = match body {
            EncodedBody::Full(bytes) if bytes.is_empty() => Upload::Done,
            EncodedBody::Full(bytes) => Upload::Full(bytes),
            EncodedBody::Stream(stream) => Upload::Stream(StreamUpload {
                stream: stream.into_inner(),
                chunk: Bytes::new(),
                declared,
                produced: 0,
            }),
        };
        if matches!(stream.upload, Upload::Full(_)) {
            self.send_data(index, None);
        }
    }

    /// Frames as much of the stream's request body as the flow-control
    /// windows allow. A streamed body is polled only with `task`, the
    /// context of the task that owns the stream (its producer must wake
    /// that task and no other).
    fn send_data(&mut self, index: usize, mut task: Option<&mut Context<'_>>) {
        loop {
            let Some(stream) = self.streams.get_mut(index) else {
                return;
            };
            let window = self.send_window.min(stream.send_window);
            let id = stream.id;
            match &mut stream.upload {
                Upload::Done => return,
                Upload::Full(body) => {
                    if window <= 0 {
                        if self.send_window <= 0 && !stream.conn_blocked {
                            stream.conn_blocked = true;
                            self.conn_blocked.push(index);
                        }
                        return;
                    }
                    let n = body
                        .len()
                        .min(window as usize)
                        .min(self.peer_max_frame)
                        .min(MAX_SEND_FRAME);
                    let payload = body.split_to(n);
                    let last = body.is_empty();
                    self.send_window -= n as i64;
                    stream.send_window -= n as i64;
                    if last {
                        stream.upload = Upload::Done;
                    }
                    self.out.data(id, payload, last);
                }
                Upload::Stream(upload) => {
                    if upload.chunk.is_empty() {
                        let Some(cx) = task.as_deref_mut() else {
                            return;
                        };
                        match upload.stream.poll_next_unpin(cx) {
                            Poll::Pending => return,
                            Poll::Ready(Some(Ok(chunk))) => {
                                upload.produced += chunk.len() as u64;
                                // Never put more on the wire than announced.
                                if upload.declared.is_some_and(|n| upload.produced > n) {
                                    stream.request_error = Some(HttpError::MalformedRequest);
                                    self.reset_stream(index, Reason::CANCEL, H2Error::RequestBody);
                                    return;
                                }
                                upload.chunk = chunk;
                                continue;
                            }
                            Poll::Ready(Some(Err(error))) => {
                                stream.request_error = Some(error);
                                self.reset_stream(index, Reason::CANCEL, H2Error::RequestBody);
                                return;
                            }
                            Poll::Ready(None) => {
                                if upload.declared.is_some_and(|n| upload.produced != n) {
                                    stream.request_error = Some(HttpError::MalformedRequest);
                                    self.reset_stream(index, Reason::CANCEL, H2Error::RequestBody);
                                    return;
                                }
                                stream.upload = Upload::Done;
                                self.out.data(id, Bytes::new(), true);
                                return;
                            }
                        }
                    }
                    // The transport is not keeping up: produce no more
                    // until what is queued has gone.
                    if self.out.blocked {
                        if !stream.write_blocked {
                            stream.write_blocked = true;
                            self.write_waiters.push(index);
                        }
                        return;
                    }
                    if window <= 0 {
                        if self.send_window <= 0 && !stream.conn_blocked {
                            stream.conn_blocked = true;
                            self.conn_blocked.push(index);
                        }
                        return;
                    }
                    let n = upload
                        .chunk
                        .len()
                        .min(window as usize)
                        .min(self.peer_max_frame)
                        .min(MAX_SEND_FRAME);
                    let payload = upload.chunk.split_to(n);
                    self.send_window -= n as i64;
                    stream.send_window -= n as i64;
                    self.out.data(id, payload, false);
                }
            }
        }
    }

    // ---- stream bookkeeping ----------------------------------------------

    fn lookup(&self, id: u32) -> Option<usize> {
        self.ids.get(&id).copied()
    }

    /// Wakes the task that owns the stream at `index`, unless that is the
    /// task running now.
    fn wake_stream(&self, index: usize) {
        if index != self.current
            && let Some(stream) = self.streams.get(index)
            && let Some(waker) = &stream.waker
        {
            waker.wake_by_ref();
        }
    }

    /// The stream is over as far as the protocol goes: frees its place
    /// under the peer's concurrency limit.
    fn close_stream(&mut self, index: usize) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        if !stream.open {
            return;
        }
        stream.open = false;
        self.ids.remove(&stream.id);
        self.active -= 1;
        self.open_pending();
    }

    /// Sends requests that were waiting for the concurrency limit.
    fn open_pending(&mut self) {
        while self.can_open() {
            let Some(index) = self.pending_open.pop_front() else {
                break;
            };
            let Some(pending) = self
                .streams
                .get_mut(index)
                .and_then(|stream| stream.pending.take())
            else {
                continue;
            };
            let (parts, body) = *pending;
            self.open_stream(index, &parts, body);
            self.wake_stream(index);
        }
    }

    /// Fails the stream at `index` and tells the peer why.
    fn reset_stream(&mut self, index: usize, reason: Reason, error: H2Error) {
        if let Some(stream) = self.streams.get(index)
            && stream.open
        {
            self.out.rst_stream(stream.id, reason);
        }
        self.fail_stream(index, error);
    }

    /// Fails the stream at `index`: its owner sees `error`, and whatever
    /// it had buffered is dropped.
    fn fail_stream(&mut self, index: usize, error: H2Error) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        stream.recv = Recv::Failed(error);
        stream.head = None;
        stream.data.clear();
        stream.upload = Upload::Done;
        stream.pending = None;
        let buffered = std::mem::take(&mut stream.buffered);
        self.release_connection(buffered);
        self.close_stream(index);
        self.wake_stream(index);
    }

    /// The response ended (END_STREAM).
    fn on_end_stream(&mut self, index: usize) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        if let BodyLength::Exact(remaining) = stream.length
            && remaining != 0
        {
            self.reset_stream(index, Reason::PROTOCOL_ERROR, H2Error::LengthMismatch);
            return;
        }
        stream.recv = Recv::End;
        // A complete response to a request still being sent: there is no
        // point in sending the rest (RFC 9113 §8.1).
        if !matches!(stream.upload, Upload::Done) {
            stream.upload = Upload::Done;
            self.out.rst_stream(stream.id, Reason::NO_ERROR);
        }
        self.close_stream(index);
        self.wake_stream(index);
    }

    /// Credits the peer's connection window for `n` bytes that are done
    /// with (consumed or discarded), in half-window steps.
    fn release_connection(&mut self, n: usize) {
        self.unreleased += n as u32;
        if self.unreleased >= CONNECTION_WINDOW / 2 && self.error.is_none() {
            self.out.window_update(0, self.unreleased);
            self.recv_window += i64::from(self.unreleased);
            self.unreleased = 0;
        }
    }

    /// Credits the stream's window likewise, while more data can come.
    fn release_stream(&mut self, index: usize, n: usize) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        if stream.recv != Recv::Body {
            return;
        }
        stream.unreleased += n as u32;
        if stream.unreleased >= STREAM_WINDOW / 2 {
            self.out.window_update(stream.id, stream.unreleased);
            stream.recv_window += i64::from(stream.unreleased);
            stream.unreleased = 0;
        }
    }

    /// The handle for the stream at `index` is gone: cancels the stream if
    /// it is still running and frees its slot.
    fn release(&mut self, index: usize, wake: &ConnWake) {
        let Some(stream) = self.streams.remove(index) else {
            return;
        };
        if stream.open {
            self.out.rst_stream(stream.id, Reason::CANCEL);
            self.ids.remove(&stream.id);
            self.active -= 1;
        }
        if stream.pending.is_some() {
            self.pending_open.retain(|&pending| pending != index);
        }
        self.release_connection(stream.buffered);
        if stream.open {
            self.open_pending();
        }
        wake.multi.store(self.streams.len > 1, Ordering::SeqCst);
        if self.streams.len == 0 && (self.handles == 0 || !self.accepting()) {
            // Nothing left to do on this connection: the driver closes it.
            wake.wake_driver();
        }
    }

    // ---- reading ---------------------------------------------------------

    /// Takes one chunk from the transport, if there is one, and processes
    /// every frame in it.
    fn read(&mut self, io_cx: &mut Context<'_>, wake: &ConnWake) -> Read {
        let Some(io) = self.io.as_mut() else {
            return Read::Closed;
        };
        wake.arm();
        match io.poll_recv(io_cx) {
            Poll::Pending => Read::Pending,
            Poll::Ready(Ok(Some(mut chunk))) => {
                wake.disarm();
                if let Err(reason) = self.parse_chunk(&mut chunk) {
                    self.fail(H2Error::Protocol(reason), Some(reason));
                }
                if self.error.is_some() {
                    self.settle(io_cx, wake);
                    return Read::Closed;
                }
                Read::Progress
            }
            Poll::Ready(Ok(None)) => {
                self.fail(H2Error::Closed, None);
                self.settle(io_cx, wake);
                Read::Closed
            }
            Poll::Ready(Err(error)) => {
                self.fail(H2Error::Io(error.kind()), None);
                self.settle(io_cx, wake);
                Read::Closed
            }
        }
    }

    /// Reads on behalf of whoever is waiting, until the transport has
    /// nothing more (and holds our waker) or the budget runs out. Returns
    /// `false` in the latter case: the caller must arrange another turn.
    fn read_until_pending(&mut self, io_cx: &mut Context<'_>, wake: &ConnWake) -> bool {
        for _ in 0..READ_BUDGET {
            match self.read(io_cx, wake) {
                Read::Progress => self.flush(io_cx, wake),
                Read::Pending | Read::Closed => return true,
            }
        }
        false
    }

    /// Processes every frame, or part of one, in `chunk`.
    fn parse_chunk(&mut self, chunk: &mut T::Recv) -> Result<(), Reason> {
        while !chunk.is_empty() {
            match self.parse {
                Parse::Head => {
                    let head = if self.head_have == 0 && chunk.len() >= FRAME_HEADER_LEN {
                        let bytes: &[u8; FRAME_HEADER_LEN] = chunk[..FRAME_HEADER_LEN]
                            .try_into()
                            .expect("slice of the header's length");
                        let head = FrameHead::parse(bytes);
                        chunk.advance(FRAME_HEADER_LEN);
                        head
                    } else {
                        let n = (FRAME_HEADER_LEN - self.head_have).min(chunk.len());
                        self.head_buf[self.head_have..self.head_have + n]
                            .copy_from_slice(&chunk[..n]);
                        chunk.advance(n);
                        self.head_have += n;
                        if self.head_have < FRAME_HEADER_LEN {
                            return Ok(());
                        }
                        self.head_have = 0;
                        FrameHead::parse(&self.head_buf)
                    };
                    self.on_frame_head(head, chunk)?;
                }
                Parse::Data(mut data) => {
                    if data.pad_pending {
                        let padding = u32::from(chunk[0]);
                        chunk.advance(1);
                        data.pad_pending = false;
                        data.remaining -= 1;
                        if padding > data.remaining {
                            return Err(Reason::PROTOCOL_ERROR);
                        }
                        data.remaining -= padding;
                        data.padding = padding;
                        // Padding counts against the windows but is never
                        // consumed by anyone: credit it back now.
                        let overhead = padding as usize + 1;
                        self.release_connection(overhead);
                        if let Some(index) = self.data_target(&data) {
                            self.release_stream(index, overhead);
                        }
                    }
                    let n = (data.remaining as usize).min(chunk.len());
                    if n > 0 {
                        let slice = chunk.split_to(n);
                        data.remaining -= n as u32;
                        self.deliver(&data, slice);
                    }
                    if data.remaining == 0 {
                        if data.end_stream
                            && let Some(index) = self.data_target(&data)
                        {
                            self.on_end_stream(index);
                        }
                        self.parse = if data.padding > 0 {
                            Parse::Skip(data.padding)
                        } else {
                            Parse::Head
                        };
                    } else {
                        self.parse = Parse::Data(data);
                    }
                }
                Parse::Gather(head) => {
                    let need = head.len as usize - self.gather.len();
                    let n = need.min(chunk.len());
                    self.gather.extend_from_slice(&chunk[..n]);
                    chunk.advance(n);
                    if n == need {
                        self.parse = Parse::Head;
                        let payload = std::mem::take(&mut self.gather);
                        let result = self.on_frame(head, &payload);
                        self.gather = payload;
                        self.gather.clear();
                        result?;
                    }
                }
                Parse::Skip(remaining) => {
                    let n = (remaining as usize).min(chunk.len());
                    chunk.advance(n);
                    self.parse = if n as u32 == remaining {
                        Parse::Head
                    } else {
                        Parse::Skip(remaining - n as u32)
                    };
                }
            }
        }
        Ok(())
    }

    /// A frame header has been read; `chunk` starts at its payload.
    fn on_frame_head(&mut self, head: FrameHead, chunk: &mut T::Recv) -> Result<(), Reason> {
        if head.len as usize > MAX_FRAME_SIZE {
            return Err(Reason::FRAME_SIZE_ERROR);
        }
        // The server's preface is a SETTINGS frame (RFC 9113 §3.4).
        if !self.got_settings && (head.kind != kind::SETTINGS || head.has(flag::ACK)) {
            return Err(Reason::PROTOCOL_ERROR);
        }
        // Nothing may interrupt a header block (RFC 9113 §6.10).
        match (&self.continuation, head.kind) {
            (Some(continuation), kind::CONTINUATION) if continuation.id == head.stream => {}
            (Some(_), _) | (None, kind::CONTINUATION) => return Err(Reason::PROTOCOL_ERROR),
            (None, _) => {}
        }
        if head.kind == kind::DATA {
            return self.on_data_head(head);
        }
        let len = head.len as usize;
        if chunk.len() >= len {
            // The whole payload is here: process it where it lies.
            let result = self.on_frame(head, &chunk[..len]);
            chunk.advance(len);
            result
        } else {
            self.gather.clear();
            self.parse = Parse::Gather(head);
            Ok(())
        }
    }

    /// The stream a DATA frame's payload goes to, if it is still there and
    /// still reading a body.
    fn data_target(&self, data: &DataFrame) -> Option<usize> {
        let index = data.index?;
        let stream = self.streams.get(index)?;
        (stream.id == data.id && stream.recv == Recv::Body).then_some(index)
    }

    fn on_data_head(&mut self, head: FrameHead) -> Result<(), Reason> {
        if head.stream == 0 {
            return Err(Reason::PROTOCOL_ERROR);
        }
        let len = i64::from(head.len);
        // The whole frame counts against the windows, padding included.
        if len > self.recv_window {
            return Err(Reason::FLOW_CONTROL_ERROR);
        }
        self.recv_window -= len;
        let padded = head.has(flag::PADDED);
        if padded && head.len == 0 {
            return Err(Reason::FRAME_SIZE_ERROR);
        }
        let mut index = self.lookup(head.stream);
        match index {
            None => {
                // A stream we never opened, as opposed to one that closed
                // with frames still in flight.
                if head.stream.is_multiple_of(2) || head.stream >= self.next_id {
                    return Err(Reason::PROTOCOL_ERROR);
                }
            }
            Some(at) => {
                let stream = self.streams.get_mut(at).expect("listed streams exist");
                match stream.recv {
                    Recv::Body if len <= stream.recv_window => stream.recv_window -= len,
                    Recv::Body => {
                        self.reset_stream(
                            at,
                            Reason::FLOW_CONTROL_ERROR,
                            H2Error::Protocol(Reason::FLOW_CONTROL_ERROR),
                        );
                        index = None;
                    }
                    // DATA before the response head.
                    Recv::Head => {
                        self.reset_stream(at, Reason::PROTOCOL_ERROR, H2Error::MalformedResponse);
                        index = None;
                    }
                    Recv::End | Recv::Failed(_) => index = None,
                }
            }
        }
        let end_stream = head.has(flag::END_STREAM);
        if head.len == 0 {
            if end_stream && let Some(index) = index {
                self.on_end_stream(index);
            }
            return Ok(());
        }
        self.parse = Parse::Data(DataFrame {
            id: head.stream,
            index,
            remaining: head.len,
            padding: 0,
            pad_pending: padded,
            end_stream,
        });
        Ok(())
    }

    /// Gives a slice of DATA payload to its stream, or discards it.
    fn deliver(&mut self, data: &DataFrame, slice: T::Recv) {
        let n = slice.len();
        let Some(index) = self.data_target(data) else {
            self.release_connection(n);
            return;
        };
        let stream = self.streams.get_mut(index).expect("target exists");
        if let BodyLength::Exact(remaining) = stream.length {
            if n as u64 > remaining {
                self.release_connection(n);
                self.reset_stream(index, Reason::PROTOCOL_ERROR, H2Error::LengthMismatch);
                return;
            }
            stream.length = BodyLength::Exact(remaining - n as u64);
        }
        stream.data.push(slice);
        stream.buffered += n;
        self.wake_stream(index);
    }

    /// A complete frame other than DATA.
    fn on_frame(&mut self, head: FrameHead, payload: &[u8]) -> Result<(), Reason> {
        match head.kind {
            kind::HEADERS => {
                if head.stream == 0 {
                    return Err(Reason::PROTOCOL_ERROR);
                }
                let mut fragment = payload;
                if head.has(flag::PADDED) {
                    let (&padding, rest) =
                        fragment.split_first().ok_or(Reason::FRAME_SIZE_ERROR)?;
                    let len = rest
                        .len()
                        .checked_sub(usize::from(padding))
                        .ok_or(Reason::PROTOCOL_ERROR)?;
                    fragment = &rest[..len];
                }
                if head.has(flag::PRIORITY) {
                    fragment = fragment.get(5..).ok_or(Reason::FRAME_SIZE_ERROR)?;
                }
                let end_stream = head.has(flag::END_STREAM);
                if head.has(flag::END_HEADERS) {
                    self.on_header_block(head.stream, end_stream, fragment)
                } else {
                    self.block.clear();
                    self.block.extend_from_slice(fragment);
                    self.continuation = Some(Continuation {
                        id: head.stream,
                        end_stream,
                    });
                    Ok(())
                }
            }
            kind::CONTINUATION => {
                // `on_frame_head` checked that a block is being continued.
                let Some(continuation) = self.continuation else {
                    return Err(Reason::PROTOCOL_ERROR);
                };
                if self.block.len() + payload.len() > MAX_HEADER_BLOCK {
                    return Err(Reason::ENHANCE_YOUR_CALM);
                }
                self.block.extend_from_slice(payload);
                if !head.has(flag::END_HEADERS) {
                    return Ok(());
                }
                self.continuation = None;
                let block = std::mem::take(&mut self.block);
                let result = self.on_header_block(continuation.id, continuation.end_stream, &block);
                self.block = block;
                result
            }
            kind::SETTINGS => self.on_settings(head, payload),
            kind::PING => {
                if head.stream != 0 {
                    return Err(Reason::PROTOCOL_ERROR);
                }
                if payload.len() != 8 {
                    return Err(Reason::FRAME_SIZE_ERROR);
                }
                if !head.has(flag::ACK) {
                    self.control_budget()?;
                    self.out.ping_ack(payload);
                }
                Ok(())
            }
            kind::GOAWAY => {
                if head.stream != 0 {
                    return Err(Reason::PROTOCOL_ERROR);
                }
                if payload.len() < 8 {
                    return Err(Reason::FRAME_SIZE_ERROR);
                }
                let last = be32(payload) & MAX_STREAM_ID;
                let code = Reason(be32(&payload[4..]));
                self.on_goaway(last, code);
                Ok(())
            }
            kind::WINDOW_UPDATE => {
                if payload.len() != 4 {
                    return Err(Reason::FRAME_SIZE_ERROR);
                }
                let increment = i64::from(be32(payload) & MAX_STREAM_ID);
                self.on_window_update(head.stream, increment)
            }
            kind::RST_STREAM => {
                if head.stream == 0 {
                    return Err(Reason::PROTOCOL_ERROR);
                }
                if payload.len() != 4 {
                    return Err(Reason::FRAME_SIZE_ERROR);
                }
                let code = Reason(be32(payload));
                match self.lookup(head.stream) {
                    Some(index) => {
                        let error = if code == Reason::REFUSED_STREAM {
                            H2Error::Refused
                        } else {
                            H2Error::Reset(code)
                        };
                        self.fail_stream(index, error);
                    }
                    None if head.stream.is_multiple_of(2) || head.stream >= self.next_id => {
                        return Err(Reason::PROTOCOL_ERROR);
                    }
                    // Closed already; a complete response stays valid.
                    None => {}
                }
                Ok(())
            }
            kind::PRIORITY => {
                if head.stream == 0 {
                    return Err(Reason::PROTOCOL_ERROR);
                }
                if payload.len() != 5 {
                    return Err(Reason::FRAME_SIZE_ERROR);
                }
                Ok(())
            }
            // Push is disabled in our SETTINGS.
            kind::PUSH_PROMISE => Err(Reason::PROTOCOL_ERROR),
            // Unknown frame types are ignored (RFC 9113 §4.1).
            _ => Ok(()),
        }
    }

    /// Refuses to queue yet another reply while the transport is not
    /// taking the ones already queued.
    fn control_budget(&self) -> Result<(), Reason> {
        if self.out.blocked && self.out.buf.len() > MAX_PENDING_CONTROL {
            return Err(Reason::ENHANCE_YOUR_CALM);
        }
        Ok(())
    }

    fn on_settings(&mut self, head: FrameHead, payload: &[u8]) -> Result<(), Reason> {
        if head.stream != 0 {
            return Err(Reason::PROTOCOL_ERROR);
        }
        if head.has(flag::ACK) {
            return if payload.is_empty() {
                Ok(())
            } else {
                Err(Reason::FRAME_SIZE_ERROR)
            };
        }
        if !payload.len().is_multiple_of(6) {
            return Err(Reason::FRAME_SIZE_ERROR);
        }
        self.got_settings = true;
        for entry in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let value = be32(&entry[2..]);
            match id {
                setting::ENABLE_PUSH => {
                    // A server has nothing to enable here.
                    if value != 0 {
                        return Err(Reason::PROTOCOL_ERROR);
                    }
                }
                setting::MAX_CONCURRENT_STREAMS => {
                    self.peer_max_streams = value as usize;
                }
                setting::INITIAL_WINDOW_SIZE => {
                    let window = i64::from(value);
                    if window > MAX_WINDOW {
                        return Err(Reason::FLOW_CONTROL_ERROR);
                    }
                    let delta = window - self.peer_initial_window;
                    self.peer_initial_window = window;
                    // Applies to every open stream (RFC 9113 §6.9.2).
                    for index in 0..self.streams.entries.len() {
                        let Some(stream) = self.streams.get_mut(index) else {
                            continue;
                        };
                        if !stream.open {
                            continue;
                        }
                        stream.send_window += delta;
                        if stream.send_window > MAX_WINDOW {
                            return Err(Reason::FLOW_CONTROL_ERROR);
                        }
                        if delta > 0 && !matches!(stream.upload, Upload::Done) {
                            self.wake_stream(index);
                        }
                    }
                }
                setting::MAX_FRAME_SIZE => {
                    if !(MAX_FRAME_SIZE as u32..=0x00ff_ffff).contains(&value) {
                        return Err(Reason::PROTOCOL_ERROR);
                    }
                    self.peer_max_frame = value as usize;
                }
                // The header table size binds an encoder that uses the
                // dynamic table, which ours does not; the header list
                // size is advisory; anything else is unknown.
                _ => {}
            }
        }
        self.control_budget()?;
        self.out.settings_ack();
        // A raised concurrency limit lets waiting requests go.
        self.open_pending();
        Ok(())
    }

    fn on_window_update(&mut self, id: u32, increment: i64) -> Result<(), Reason> {
        if id == 0 {
            if increment == 0 {
                return Err(Reason::PROTOCOL_ERROR);
            }
            self.send_window += increment;
            if self.send_window > MAX_WINDOW {
                return Err(Reason::FLOW_CONTROL_ERROR);
            }
            for index in std::mem::take(&mut self.conn_blocked) {
                if let Some(stream) = self.streams.get_mut(index) {
                    stream.conn_blocked = false;
                    self.wake_stream(index);
                }
            }
            return Ok(());
        }
        let Some(index) = self.lookup(id) else {
            return if id.is_multiple_of(2) || id >= self.next_id {
                Err(Reason::PROTOCOL_ERROR)
            } else {
                // A closed stream's window no longer matters.
                Ok(())
            };
        };
        let stream = self.streams.get_mut(index).expect("listed streams exist");
        stream.send_window += increment;
        if increment == 0 || stream.send_window > MAX_WINDOW {
            let reason = if increment == 0 {
                Reason::PROTOCOL_ERROR
            } else {
                Reason::FLOW_CONTROL_ERROR
            };
            self.reset_stream(index, reason, H2Error::Protocol(reason));
            return Ok(());
        }
        self.wake_stream(index);
        Ok(())
    }

    fn on_goaway(&mut self, last: u32, code: Reason) {
        self.goaway = true;
        let error = if code == Reason::NO_ERROR {
            H2Error::Refused
        } else {
            H2Error::GoAway(code)
        };
        for index in 0..self.streams.entries.len() {
            let Some(stream) = self.streams.get(index) else {
                continue;
            };
            // Requests the peer will not process: those past `last`, and
            // those not even sent.
            let unprocessed = (stream.open && stream.id > last) || stream.pending.is_some();
            if unprocessed && !matches!(stream.recv, Recv::End | Recv::Failed(_)) {
                self.fail_stream(index, error);
            }
        }
        self.pending_open.clear();
    }

    /// A complete header block for stream `id`.
    fn on_header_block(&mut self, id: u32, end_stream: bool, block: &[u8]) -> Result<(), Reason> {
        let target = self.lookup(id);
        let recv = target
            .and_then(|index| self.streams.get(index))
            .map(|stream| stream.recv);
        // Decoded whoever it is for: the table must see every block.
        let mut head = HeadBuilder::new(recv == Some(Recv::Head));
        let limits = hpack::Limits {
            fields: MAX_HEADERS,
            size: MAX_HEADER_LIST_SIZE,
        };
        self.hpack
            .decode(block, limits, |name, value| head.field(name, value))
            .map_err(|error| match error {
                hpack::HpackError::TooLarge => Reason::ENHANCE_YOUR_CALM,
                _ => Reason::COMPRESSION_ERROR,
            })?;
        let Some(index) = target else {
            return if id.is_multiple_of(2) || id >= self.next_id {
                Err(Reason::PROTOCOL_ERROR)
            } else {
                Ok(())
            };
        };
        match recv {
            Some(Recv::Head) => self.on_response_head(index, head, end_stream),
            // Trailers: read for the table, then dropped. They end the
            // stream (RFC 9113 §8.1).
            Some(Recv::Body) if end_stream && !head.malformed => self.on_end_stream(index),
            Some(Recv::Body) => {
                self.reset_stream(index, Reason::PROTOCOL_ERROR, H2Error::MalformedResponse);
            }
            _ => {}
        }
        Ok(())
    }

    fn on_response_head(&mut self, index: usize, head: HeadBuilder, end_stream: bool) {
        let malformed = |this: &mut Self| {
            this.reset_stream(index, Reason::PROTOCOL_ERROR, H2Error::MalformedResponse);
        };
        let Some(status) = head.status.filter(|_| !head.malformed) else {
            return malformed(self);
        };
        let stream = self.streams.get_mut(index).expect("target exists");
        if status.is_informational() {
            // An interim response cannot end the stream, and HTTP/2 has
            // no 101 (RFC 9113 §8.6).
            if end_stream || status == StatusCode::SWITCHING_PROTOCOLS {
                return malformed(self);
            }
            stream.interim += 1;
            if stream.interim > MAX_INTERIM_RESPONSES {
                self.reset_stream(index, Reason::CANCEL, H2Error::TooManyInterimResponses);
            }
            return;
        }
        let bodiless = stream.head_request
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED;
        if bodiless {
            stream.length = BodyLength::Exact(0);
        } else {
            match h1::content_length(&head.headers) {
                Ok(Some(n)) => {
                    stream.length = BodyLength::Exact(n);
                    stream.length_hint = Some(n);
                }
                Ok(None) => stream.length = BodyLength::Unknown,
                Err(()) => return malformed(self),
            }
        }
        let mut parts = Response::new(()).into_parts().0;
        parts.status = status;
        parts.version = Version::HTTP_2;
        parts.headers = head.headers;
        stream.head = Some(parts);
        stream.recv = Recv::Body;
        if end_stream {
            self.on_end_stream(index);
        } else {
            self.wake_stream(index);
        }
    }

    // ---- polling ---------------------------------------------------------

    /// Drives the connection from the task that owns the stream at
    /// `index` until that stream has something for it: sends what the
    /// stream has to send, then reads and dispatches frames.
    fn poll_stream(
        &mut self,
        task: &mut Context<'_>,
        io_cx: &mut Context<'_>,
        wake: &ConnWake,
        index: usize,
    ) -> Poll<()> {
        self.current = index;
        // The transport's waker must lead to this task before any poll of
        // the transport can fire it.
        let mut in_charge = false;
        let mut reads = 0;
        let outcome = loop {
            let Some(stream) = self.streams.get(index) else {
                break Poll::Ready(());
            };
            if !matches!(stream.upload, Upload::Done) {
                self.send_data(index, Some(task));
            }
            let stream = self.streams.get(index).expect("checked above");
            if stream.has_event() {
                break Poll::Ready(());
            }
            if !in_charge {
                wake.set_task(task.waker());
                in_charge = true;
            }
            self.flush(io_cx, wake);
            match self.read(io_cx, wake) {
                Read::Closed => {}
                Read::Progress => {
                    // All for other streams so far: let their tasks run
                    // before reading on.
                    reads += 1;
                    if reads == READ_BUDGET {
                        task.waker().wake_by_ref();
                        break Poll::Pending;
                    }
                }
                Read::Pending => break Poll::Pending,
            }
        };
        self.current = NO_STREAM;
        if outcome.is_pending()
            && let Some(stream) = self.streams.get_mut(index)
        {
            match &stream.waker {
                Some(waker) if waker.will_wake(task.waker()) => {}
                _ => stream.waker = Some(task.waker().clone()),
            }
        }
        outcome
    }

    /// The task that was polling is leaving with a result and may not
    /// poll again: hands the transport to the driver, so that frames for
    /// other streams (and the peer's PINGs) are not left unread.
    fn hand_off(&mut self, io_cx: &mut Context<'_>, wake: &ConnWake) {
        if !wake.has_driver() {
            // Nobody to hand to (a connection whose driver is not
            // running): leave things as they are.
            self.flush(io_cx, wake);
            return;
        }
        wake.clear_task();
        self.flush(io_cx, wake);
        if !wake.is_armed() && !self.read_until_pending(io_cx, wake) {
            wake.wake_driver();
        }
    }
}

/// Starts an HTTP/2 connection over `io`, which must be freshly connected
/// (for `https`, with ALPN having chosen `h2`).
///
/// Nothing is sent yet: the connection preface and SETTINGS leave with the
/// first request, in the same buffer. The returned [`Connection`] must be
/// spawned; see the [module documentation](self).
pub fn handshake<T: Transport>(io: T) -> (SendRequest<T>, Connection<T>) {
    let wake = Arc::new(ConnWake {
        slots: Mutex::new(WakeSlots::default()),
        armed: AtomicBool::new(false),
        multi: AtomicBool::new(false),
    });
    let shared = Arc::new(Shared {
        inner: Mutex::new(Inner::new(io)),
        io_waker: Waker::from(wake.clone()),
        wake,
    });
    (
        SendRequest {
            shared: shared.clone(),
        },
        Connection { shared },
    )
}

/// The handle requests are sent through. Cloning it gives another handle
/// to the same connection; requests sent through any of them are
/// multiplexed.
pub struct SendRequest<T: Transport> {
    shared: Arc<Shared<T>>,
}

impl<T: Transport> Clone for SendRequest<T> {
    fn clone(&self) -> Self {
        self.shared.lock().handles += 1;
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: Transport> Drop for SendRequest<T> {
    fn drop(&mut self) {
        let mut inner = self.shared.lock();
        inner.handles -= 1;
        if inner.handles == 0 && inner.streams.len == 0 {
            self.shared.wake.wake_driver();
        }
    }
}

impl<T: Transport> SendRequest<T> {
    /// Whether the connection can no longer take new requests: it failed,
    /// ended, the server announced it is going away, or its stream
    /// identifiers ran out.
    pub fn is_closed(&self) -> bool {
        !self.shared.lock().accepting()
    }

    /// Starts a request. `parts.uri` supplies `:scheme`, `:authority` and
    /// `:path` (an absolute URI, as the caller gave it; without an
    /// authority the `Host` header is used); connection-specific headers
    /// are left out, and `content-length` is added for a buffered body
    /// when the caller set none.
    ///
    /// The request is encoded here and sent when the returned future is
    /// first polled. If the server's concurrency limit is reached it is
    /// held back until a stream ends.
    pub fn send(
        &self,
        parts: request::Parts,
        body: EncodedBody,
    ) -> Result<ResponseFuture<T>, HttpError> {
        if hpack::authority(&parts.uri, &parts.headers).is_none() {
            return Err(HttpError::MissingHost);
        }
        // A caller's content-length must be well formed and match a body
        // whose size is known, as in `h1`.
        let declared =
            h1::content_length(&parts.headers).map_err(|()| HttpError::MalformedRequest)?;
        if let (Some(declared), EncodedBody::Full(bytes)) = (declared, &body)
            && bytes.len() as u64 != declared
        {
            return Err(HttpError::MalformedRequest);
        }
        let mut inner = self.shared.lock();
        if !inner.accepting() {
            return Err(HttpError::Protocol);
        }
        let index = inner
            .streams
            .insert(Stream::new(parts.method == Method::HEAD));
        self.shared
            .wake
            .multi
            .store(inner.streams.len > 1, Ordering::SeqCst);
        if inner.can_open() {
            inner.open_stream(index, &parts, body);
        } else {
            inner.streams.get_mut(index).expect("just inserted").pending =
                Some(Box::new((parts, body)));
            inner.pending_open.push_back(index);
        }
        Ok(ResponseFuture {
            shared: Some(self.shared.clone()),
            index,
        })
    }
}

/// The connection's fallback driver; see the [module documentation](self).
/// Resolves when the connection is over: cleanly once every
/// [`SendRequest`] and response is gone or the server went away, or with
/// the error that ended it. Dropping it closes the connection.
pub struct Connection<T: Transport> {
    shared: Arc<Shared<T>>,
}

impl<T: Transport> Future for Connection<T> {
    type Output = Result<(), H2Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let shared = &*self.shared;
        let wake = &*shared.wake;
        wake.set_driver(cx.waker());
        let mut io_cx = Context::from_waker(&shared.io_waker);
        let mut inner = shared.lock();
        let inner = &mut *inner;
        // A request task that the transport is set to wake is in charge;
        // otherwise (nobody is, or the one that was has been woken and
        // has not come back) the driver reads.
        if inner.io.is_some() && !(wake.has_task() && wake.is_armed()) {
            wake.clear_task();
            inner.current = NO_STREAM;
            inner.flush(&mut io_cx, wake);
            if !inner.read_until_pending(&mut io_cx, wake) {
                cx.waker().wake_by_ref();
            }
        }
        // Nothing left to do, and nobody who could ask for more.
        if inner.io.is_some()
            && inner.streams.len == 0
            && (inner.handles == 0 || !inner.accepting())
        {
            if !inner.goaway_sent {
                inner.goaway_sent = true;
                inner.out.goaway(Reason::NO_ERROR);
            }
            inner.error.get_or_insert(H2Error::Closed);
            inner.settle(&mut io_cx, wake);
            return Poll::Ready(Ok(()));
        }
        if inner.io.is_none() {
            return Poll::Ready(match inner.error {
                None | Some(H2Error::Closed) => Ok(()),
                Some(error) => Err(error),
            });
        }
        Poll::Pending
    }
}

impl<T: Transport> Drop for Connection<T> {
    fn drop(&mut self) {
        let shared = &*self.shared;
        let mut io_cx = Context::from_waker(&shared.io_waker);
        let mut inner = shared.lock();
        // The driver is gone for good.
        shared.wake.slots().driver = None;
        if inner.io.is_some() {
            inner.fail(H2Error::Closed, None);
            inner.settle(&mut io_cx, &shared.wake);
        }
    }
}

/// Why [`ResponseFuture`] failed: the request's own fault, reported as
/// what it is, or the exchange's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The request body's producer failed, or broke the length the
    /// request announced.
    Request(HttpError),
    H2(H2Error),
}

impl From<SendError> for HttpError {
    fn from(error: SendError) -> Self {
        match error {
            SendError::Request(error) => error,
            SendError::H2(error) => error.into(),
        }
    }
}

/// Resolves to the response head, with the body still to be read. Dropping
/// it cancels the request.
pub struct ResponseFuture<T: Transport> {
    /// `None` once the future has resolved.
    shared: Option<Arc<Shared<T>>>,
    index: usize,
}

impl<T: Transport> Future for ResponseFuture<T> {
    type Output = Result<Response<Body<T>>, SendError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let shared = this
            .shared
            .as_deref()
            .expect("ResponseFuture polled after completion");
        let wake = &*shared.wake;
        let mut io_cx = Context::from_waker(&shared.io_waker);
        let mut guard = shared.lock();
        let inner = &mut *guard;
        if inner
            .poll_stream(cx, &mut io_cx, wake, this.index)
            .is_pending()
        {
            return Poll::Pending;
        }
        let stream = inner
            .streams
            .get_mut(this.index)
            .expect("a stream outlives its handle");
        let result = match stream.head.take() {
            Some(parts) => Ok((parts, stream.length_hint)),
            None => Err(match (stream.request_error.take(), stream.recv) {
                (Some(error), _) => SendError::Request(error),
                (None, Recv::Failed(error)) => SendError::H2(error),
                (None, _) => SendError::H2(H2Error::Closed),
            }),
        };
        if result.is_err() {
            inner.release(this.index, wake);
        }
        inner.hand_off(&mut io_cx, wake);
        drop(guard);
        let shared = this.shared.take();
        Poll::Ready(result.map(|(parts, length_hint)| {
            let body = Body {
                shared,
                index: this.index,
                length_hint,
            };
            Response::from_parts(parts, body)
        }))
    }
}

impl<T: Transport> Drop for ResponseFuture<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            abandon(&shared, self.index);
        }
    }
}

/// A handle is dropped with its stream unfinished: cancels the stream and
/// makes sure the cancellation and whatever else is queued gets sent.
fn abandon<T: Transport>(shared: &Shared<T>, index: usize) {
    let mut io_cx = Context::from_waker(&shared.io_waker);
    let mut inner = shared.lock();
    inner.release(index, &shared.wake);
    inner.hand_off(&mut io_cx, &shared.wake);
}

/// A response body. Yields payload as slices of the chunks the transport
/// delivered (no copy), via [`Stream`](FuturesStream) or
/// [`poll_chunk`](Self::poll_chunk), or all at once via
/// [`collect`](Self::collect). Dropping it before the end cancels the
/// stream (RST_STREAM); the connection carries on. After an error the body
/// yields nothing more.
pub struct Body<T: Transport> {
    /// `None` once the body has finished.
    shared: Option<Arc<Shared<T>>>,
    index: usize,
    /// The `content-length`, when there is one, to size `collect`.
    length_hint: Option<u64>,
}

impl<T: Transport> Body<T> {
    /// The next payload slice, still a view of the buffer it was received
    /// in: no copy, and no allocation for a packet buffer. `None` at the
    /// clean end of the body.
    pub fn poll_slice(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<T::Recv, H2Error>>> {
        let Some(shared) = self.shared.as_deref() else {
            return Poll::Ready(None);
        };
        let wake = &*shared.wake;
        let mut io_cx = Context::from_waker(&shared.io_waker);
        let mut guard = shared.lock();
        let inner = &mut *guard;
        if inner
            .poll_stream(cx, &mut io_cx, wake, self.index)
            .is_pending()
        {
            return Poll::Pending;
        }
        let stream = inner
            .streams
            .get_mut(self.index)
            .expect("a stream outlives its handle");
        let item = match stream.data.pop() {
            Some(slice) => {
                let n = slice.len();
                stream.buffered -= n;
                inner.release_connection(n);
                inner.release_stream(self.index, n);
                Some(Ok(slice))
            }
            None => match stream.recv {
                Recv::Failed(error) => Some(Err(error)),
                _ => None,
            },
        };
        let stream = inner.streams.get(self.index).expect("still there");
        let finished =
            !matches!(item, Some(Ok(_))) || (stream.data.is_empty() && stream.recv == Recv::End);
        if finished {
            inner.release(self.index, wake);
            inner.hand_off(&mut io_cx, wake);
        } else if inner.streams.len > 1 {
            // Others share the connection: do not keep it to ourselves
            // between reads.
            inner.hand_off(&mut io_cx, wake);
        } else if !inner.out.is_empty() {
            inner.flush(&mut io_cx, wake);
        }
        drop(guard);
        if finished {
            self.shared = None;
        }
        Poll::Ready(item)
    }

    /// The next payload slice as [`Bytes`]; see
    /// [`poll_slice`](Self::poll_slice). A slice of a packet buffer gets
    /// its heap-allocated `Bytes` owner here.
    pub fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, H2Error>>> {
        self.poll_slice(cx)
            .map(|item| item.map(|slice| slice.map(RecvBuf::into_bytes)))
    }

    /// The next payload slice as [`Bytes`]; `None` at the clean end.
    pub async fn chunk(&mut self) -> Option<Result<Bytes, H2Error>> {
        poll_fn(|cx| self.poll_chunk(cx)).await
    }

    /// The next payload slice; `None` at the clean end.
    pub async fn slice(&mut self) -> Option<Result<T::Recv, H2Error>> {
        poll_fn(|cx| self.poll_slice(cx)).await
    }

    /// Reads the whole body. One that arrived as a single slice is
    /// returned as is; otherwise the slices are concatenated, each byte
    /// copied once, as they arrive (so received buffers are released right
    /// away rather than pinned until the end).
    pub async fn collect(mut self) -> Result<Bytes, H2Error> {
        let Some(first) = self.slice().await.transpose()? else {
            return Ok(Bytes::new());
        };
        let Some(second) = self.slice().await.transpose()? else {
            return Ok(first.into_bytes());
        };
        let reserve = self
            .length_hint
            .unwrap_or(0)
            .min(MAX_COLLECT_RESERVE)
            .max((first.len() + second.len()) as u64) as usize;
        let mut out = BytesMut::with_capacity(reserve);
        out.extend_from_slice(&first);
        out.extend_from_slice(&second);
        drop((first, second));
        while let Some(slice) = self.slice().await.transpose()? {
            out.extend_from_slice(&slice);
        }
        Ok(out.freeze())
    }
}

impl<T: Transport> Drop for Body<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            abandon(&shared, self.index);
        }
    }
}

impl<T: Transport> FuturesStream for Body<T> {
    type Item = Result<Bytes, HttpError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .poll_chunk(cx)
            .map(|item| item.map(|result| result.map_err(HttpError::from)))
    }
}

/// Turns a codec response into the typed response `Client::request`
/// returns, exactly as [`h1::into_typed_response`] does: a
/// [`ByteStream`](codec::ByteStream) target gets the body unbuffered;
/// anything else is collected and decoded for its `Content-Type`.
pub async fn into_typed_response<R, T>(
    response: Response<Body<T>>,
) -> Result<Response<R>, HttpError>
where
    R: DeserializeOwned + 'static,
    T: Transport + Send + 'static,
{
    let (parts, body) = response.into_parts();
    if codec::is_stream::<R>() {
        let body = codec::stream_response::<R, _>(body).expect("is_stream::<R>() checked above");
        return Ok(Response::from_parts(parts, body));
    }
    let bytes = body.collect().await?;
    let body = codec::decode(parts.headers.get(header::CONTENT_TYPE), bytes)?;
    Ok(Response::from_parts(parts, body))
}

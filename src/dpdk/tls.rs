//! TLS over [`TcpStream`] on rustls's unbuffered API, with the caller (this
//! module) owning every buffer.
//!
//! `tokio-rustls` drives rustls's buffered `ClientConnection` through the
//! stream's copying `AsyncRead`/`AsyncWrite` faces. Here the ciphertext is
//! produced straight into memory the NIC transmits from and handed to
//! [`TcpStream::poll_send`] as owned [`Bytes`], and received segments are
//! taken from [`TcpStream::poll_recv`] as owned [`Bytes`]. [`TlsStream`]
//! offers both faces itself: owned-`Bytes` [`poll_send`](TlsStream::poll_send)
//! / [`poll_recv`](TlsStream::poll_recv) with exactly `TcpStream`'s signatures
//! (so a codec written against those runs over TLS unchanged), and tokio
//! `AsyncRead`/`AsyncWrite` for hyper.
//!
//! # Copies, per direction (rustls 0.23.41)
//!
//! The unbuffered API does not yet decrypt or encrypt fully in the caller's
//! buffers, so rustls still makes one internal copy each way. What remains:
//!
//! Receive, per byte of a record:
//! 1. segment -> `incoming` (here). Segments are immutable, refcounted views
//!    of NIC buffers and records straddle segments, while rustls decrypts in
//!    place in one contiguous `&mut [u8]`, so this copy is required.
//!    Occasionally the trailing partial record is also moved to the front of
//!    `incoming` when its tail runs out (see [`Incoming::append`]).
//! 2. decrypt in place in `incoming` (the cipher pass, not a copy), then
//!    *inside rustls*: plaintext -> a fresh `Vec` per record
//!    (`CommonState::take_received_plaintext` does `payload.into_vec()`).
//!    `ReadTraffic::next_record` only lends that `Vec` (`AppDataRecord`
//!    borrows it and the `Vec` is private to `ReadTraffic`), so plaintext
//!    cannot leave as a view of `incoming` -- a `BytesMut::split_to` /
//!    `freeze` scheme has nothing to split.
//! 3. that `Vec` -> the reader: straight into the caller's `ReadBuf` on the
//!    `AsyncRead` face (overflow into `decrypted`, then to the `ReadBuf` on a
//!    later read), or into `decrypted` and out as owned `Bytes` on the
//!    [`poll_recv`](TlsStream::poll_recv) face.
//!
//! Send, per byte of plaintext:
//! 1. *inside rustls*: plaintext -> a fresh per-record `Vec` (the record
//!    layer's `encrypt` builds an owned `PrefixedPayload`), sealed in place
//!    there (the cipher pass).
//! 2. *inside rustls*: that `Vec` -> the caller's output slice
//!    (`write_fragments` does `copy_from_slice`). The output slice here is
//!    DMA memory ([`DmaWriter::fill_prefix`]) on ports that attach `Bytes`
//!    without copying, so the TCP worker adds no copy; on other ports it is
//!    a reused heap buffer and the worker copies it into mbufs as for any
//!    heap `Bytes`.
//!
//! On the `AsyncWrite` face hyper's borrowed slices are encrypted directly
//! (copy 1 is rustls's); only runs of small slices (below
//! [`COALESCE_BELOW`]) are first gathered into one plaintext buffer, so a
//! vectored write of h2 frame headers does not become one 30-byte record per
//! 9-byte header.
//!
//! Compared with `tokio-rustls` this saves no copy on either side: the
//! buffered rustls path makes the same internal copies, and its
//! `poll_read`/`poll_write` adapter copies match copies 1/3 above. What it
//! does change: ciphertext goes to DMA memory directly, several records
//! share one buffer, the incoming buffer is reused, and there is an
//! owned-`Bytes` face. Getting to one pass per direction needs either a
//! rustls release whose unbuffered API decrypts/encrypts in the caller's
//! buffer (the source marks `next_record` "requires in-place decryption"
//! as a TODO), or running the record layer ourselves on secrets extracted
//! with `dangerous_into_kernel_connection`, which would put key material in
//! this crate; neither is done here.
//!
//! # Errors
//!
//! Every rustls error is fatal: whatever alert rustls queued is sent
//! (best effort), and every later call returns the same error
//! (`InvalidData`, as `tokio-rustls` maps it). Plaintext already decrypted
//! from authenticated records before the error is still delivered first,
//! the way [`TcpStream`] delivers buffered data before a reset. A TCP end
//! of stream without the peer's `close_notify` is `UnexpectedEof`, as with
//! rustls's buffered reader.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};

use bytes::{Buf, Bytes, BytesMut};
use rustls::ClientConfig;
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::pki_types::ServerName;
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncodeTlsData, EncryptError, InsufficientSizeError,
    UnbufferedStatus, WriteTraffic,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::dpdk::DmaWriter;
use crate::dpdk::tcp::stream::TcpStream;

/// Largest plaintext a TLS record carries (RFC 8446 5.1, RFC 5246 6.2.1).
const MAX_RECORD_PLAINTEXT: usize = 16 * 1024;

/// Upper bound on what a record adds to its plaintext for the AEAD suites
/// rustls implements: 5-byte header plus, worst case, TLS 1.2 GCM's 8-byte
/// explicit nonce and 16-byte tag (TLS 1.3: inner content type + tag, 17).
/// Only sizes buffers; a provider with a larger overhead is still correct
/// because rustls reports the exact size it needs (see `encrypt_into`).
const RECORD_OVERHEAD: usize = 32;

/// Largest output buffer one encryption fills: a whole DMA block, so
/// several records share one buffer (and one `Command::Send`).
const MAX_OUT: usize = 64 * 1024;

/// Room kept free for records rustls itself queued ahead of the
/// application data (a TLS 1.3 `KeyUpdate`, written before it by
/// `WriteTraffic::encrypt`).
const QUEUED_SLACK: usize = 64;

/// First guess at the size of a handshake record or alert to encode; rustls
/// says how much it needs when this is too small.
const ENCODE_GUESS: usize = 2 * 1024;

/// Slices of a vectored write shorter than this are gathered (copied) into
/// one plaintext buffer and encrypted as one record, rather than each
/// becoming a record of its own with ~22-29 bytes of overhead and one AEAD
/// invocation. Longer slices are encrypted from where they are.
pub const COALESCE_BELOW: usize = 1024;

/// Size of the reusable ciphertext buffer: room for several maximum-size
/// records, so moving a trailing partial record to the front (when the
/// tail runs out) happens rarely.
const INCOMING_CAPACITY: usize = 128 * 1024;

/// Bound on undecrypted ciphertext held at once. Data is processed after
/// every appended segment, so this only holds a partial record plus a
/// segment, or a handshake message spanning records (rustls limits those
/// to 64 KiB); exceeding it means something is badly wrong.
const INCOMING_LIMIT: usize = 512 * 1024;

/// Dials TLS clients with one configuration (ALPN offer, roots, ...). The
/// drop-in for `tokio_rustls::TlsConnector` on the DPDK stack.
#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl TlsConnector {
    /// Runs the TLS handshake over `tcp`; see [`connect`].
    pub async fn connect(
        &self,
        server_name: ServerName<'static>,
        tcp: TcpStream,
    ) -> io::Result<TlsStream> {
        connect(self.config.clone(), server_name, tcp).await
    }
}

/// Runs a TLS client handshake over `tcp` and resolves once application
/// data may flow in both directions (the client's final flight has been
/// handed to the TCP worker). Certificate verification is whatever
/// `config` specifies. Errors: rustls failures as `InvalidData`, the peer
/// closing mid-handshake as `UnexpectedEof`, TCP errors as they come.
pub async fn connect(
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    tcp: TcpStream,
) -> io::Result<TlsStream> {
    let conn = UnbufferedClientConnection::new(config, server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut tls = TlsStream::new(tcp, conn);
    poll_fn(|cx| tls.poll_handshake(cx)).await?;
    Ok(tls)
}

/// Whether the connection can still be used at all.
enum Session {
    Live,
    /// rustls reported this error; every later call returns it. Its alert,
    /// if any, has been queued.
    Failed(rustls::Error),
}

/// The receive direction, as far as the application is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// The peer may still send.
    Open,
    /// The peer's `close_notify` was processed: everything it sent has been
    /// received, and reads end cleanly once `plaintext` drains.
    CloseNotify,
    /// TCP ended without a `close_notify`, so the data may have been cut
    /// short by an attacker: reads fail with `UnexpectedEof`.
    Truncated,
}

/// The send direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    Open,
    /// Our `close_notify` is encrypted and queued in `tx`; once it is with
    /// the TCP worker, TCP is half-closed.
    CloseNotifyQueued,
    /// `close_notify` sent and TCP half-closed.
    Shutdown,
}

/// What [`TlsStream::process`] stopped at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The handshake needs more data from the peer.
    Blocked,
    /// Every complete record in `incoming` is processed; application data
    /// may be written.
    Open,
    /// Both sides have sent `close_notify`.
    Closed,
}

/// Work for [`TlsStream::process`] to do once it reaches a state that
/// allows writing.
enum Job<'a> {
    None,
    /// Encrypt (a prefix of) these slices, in order.
    Encrypt(&'a [IoSlice<'a>]),
    CloseNotify,
}

/// What became of the [`Job`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// `process` stopped somewhere that does not allow writing.
    NotRun,
    /// This many plaintext bytes were encrypted into `tx`.
    Encrypted(usize),
    CloseNotifyQueued,
}

/// Whether [`Incoming`] holds bytes rustls has not looked at yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputState {
    /// Bytes were appended since `process` last ran out of complete records.
    Fresh,
    /// Whatever is held is an incomplete record (or nothing).
    Exhausted,
}

/// The ciphertext buffer rustls decrypts in place. `buf[start..end]` is
/// what the peer sent that rustls has not yet told us to discard; rustls's
/// `discard` counts always remove from its front.
struct Incoming {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    state: InputState,
}

impl Incoming {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
            state: InputState::Exhausted,
        }
    }

    /// The undiscarded bytes, for `process_tls_records`.
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    fn len(&self) -> usize {
        self.end - self.start
    }

    /// Copies `segment` in behind the held bytes (copy 1 of the receive
    /// path). When the tail is too short, the held bytes -- normally less
    /// than one record, since complete records are processed and discarded
    /// as segments arrive -- move to the front first; the buffer only grows
    /// when even that is not enough.
    fn append(&mut self, segment: &[u8]) -> io::Result<()> {
        if self.len() + segment.len() > INCOMING_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too much unprocessed TLS data",
            ));
        }
        if self.buf.len() - self.end < segment.len() {
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            if self.buf.len() - self.end < segment.len() {
                let wanted = (self.end + segment.len()).max(INCOMING_CAPACITY);
                self.buf.resize(wanted, 0);
            }
        }
        self.buf[self.end..self.end + segment.len()].copy_from_slice(segment);
        self.end += segment.len();
        self.state = InputState::Fresh;
        Ok(())
    }

    /// Removes `n` bytes from the front, as rustls instructs.
    fn discard(&mut self, n: usize) -> Result<(), rustls::Error> {
        if n > self.len() {
            return Err(rustls::Error::General(
                "TLS discard beyond the received data".into(),
            ));
        }
        self.start += n;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        Ok(())
    }
}

/// Where outgoing TLS bytes are written: DMA memory the stack attaches to
/// packets as is, or the heap on ports (and in tests) without it.
enum OutAlloc {
    Dma(DmaWriter),
    /// Reused: once the `Bytes` split off it are dropped (sent and
    /// acknowledged), `reserve` reclaims the allocation.
    Heap(BytesMut),
}

impl OutAlloc {
    /// Lends `len` writable bytes to `fill`, which writes a prefix and
    /// returns its length; that prefix comes back as `Bytes`.
    fn fill(&mut self, len: usize, fill: impl FnOnce(&mut [u8]) -> usize) -> Bytes {
        let mut fill = Some(fill);
        if let OutAlloc::Dma(writer) = self
            && let Some(bytes) = writer.fill_prefix(len, |out| fill.take().map_or(0, |f| f(out)))
        {
            return bytes;
        }
        // Not DMA, or no DMA memory (or `len` beyond a DMA block): heap.
        // `fill_prefix` did not call `fill` in that case.
        let Some(fill) = fill else {
            return Bytes::new();
        };
        let mut scratch;
        let heap = match self {
            OutAlloc::Heap(heap) => heap,
            OutAlloc::Dma(_) => {
                scratch = BytesMut::new();
                &mut scratch
            }
        };
        heap.clear();
        heap.resize(len, 0);
        let n = fill(&mut heap[..]).min(len);
        heap.truncate(n);
        heap.split().freeze()
    }
}

/// A TLS client connection over [`TcpStream`]. Created by [`connect`].
pub struct TlsStream {
    tcp: TcpStream,
    conn: UnbufferedClientConnection,
    session: Session,
    read: ReadState,
    write: WriteState,
    incoming: Incoming,
    /// Decrypted plaintext not yet delivered, in order.
    plaintext: VecDeque<Bytes>,
    /// Where record payloads are copied out of rustls before they leave as
    /// `Bytes` (all records of one `process` run share one allocation).
    decrypted: BytesMut,
    /// Encrypted output not yet accepted by [`TcpStream::poll_send`], in
    /// order. Kept across polls, so backpressure never means re-encrypting.
    tx: VecDeque<Bytes>,
    out: OutAlloc,
    /// Gathers runs of small slices of a vectored write (see
    /// [`COALESCE_BELOW`]).
    gather: Vec<u8>,
}

impl TlsStream {
    fn new(tcp: TcpStream, conn: UnbufferedClientConnection) -> Self {
        let out = if tcp.dma_writes() {
            OutAlloc::Dma(DmaWriter::new())
        } else {
            OutAlloc::Heap(BytesMut::new())
        };
        Self {
            tcp,
            conn,
            session: Session::Live,
            read: ReadState::Open,
            write: WriteState::Open,
            incoming: Incoming::new(),
            plaintext: VecDeque::new(),
            decrypted: BytesMut::new(),
            tx: VecDeque::new(),
            out,
            gather: Vec::new(),
        }
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// The negotiated TLS version.
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.conn.protocol_version()
    }

    /// The underlying TCP connection, e.g. for
    /// [`request_cork`](TcpStream::request_cork) after the handshake.
    /// Reading or writing it directly would corrupt the TLS stream.
    pub fn tcp(&self) -> &TcpStream {
        &self.tcp
    }

    /// Zero-copy-shaped write of owned plaintext; see
    /// [`poll_send`](Self::poll_send).
    pub async fn send(&mut self, data: Bytes) -> io::Result<()> {
        let mut data = Some(data);
        poll_fn(|cx| self.poll_send(cx, &mut data)).await
    }

    /// Encrypts `data` and hands the records to the TCP worker; the same
    /// contract as [`TcpStream::poll_send`]. On success `data` is taken. On
    /// `Pending` it holds the suffix not yet encrypted, and what was
    /// encrypted is kept here until TCP accepts it (encrypted once, never
    /// again); cancellation may leave a prefix sent.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        loop {
            let bytes = data.as_mut().expect("poll_send polled without a payload");
            if bytes.is_empty() {
                ready!(self.poll_flush_tx(cx))?;
                data.take();
                return Poll::Ready(Ok(()));
            }
            let n = ready!(self.poll_encrypt(cx, &[IoSlice::new(bytes)]))?;
            bytes.advance(n);
        }
    }

    /// Next decrypted chunk as owned [`Bytes`]; see
    /// [`poll_recv`](Self::poll_recv).
    pub async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// The same contract as [`TcpStream::poll_recv`], for plaintext: the
    /// next decrypted chunk (one or more records), `Ok(None)` once the peer
    /// sent `close_notify`. TCP ending without it is `UnexpectedEof`.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match ready!(self.poll_plaintext(cx, None))? {
            Readable::Queued => Poll::Ready(Ok(self.plaintext.pop_front())),
            // Nothing can go to a sink that was not given.
            Readable::IntoSink => Poll::Ready(Ok(self.plaintext.pop_front())),
            Readable::Eof => Poll::Ready(Ok(None)),
        }
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let (stop, _) = self.process(None, Job::None)?;
            match stop {
                Stop::Open if !self.conn.is_handshaking() => {
                    // The client's last flight must be on its way before
                    // the caller corks the connection or starts the
                    // request.
                    ready!(self.poll_flush_tx(cx))?;
                    return Poll::Ready(Ok(()));
                }
                Stop::Closed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls handshake eof",
                    )));
                }
                Stop::Open | Stop::Blocked => {
                    // The peer answers only once our flight is out.
                    ready!(self.poll_flush_tx(cx))?;
                    match ready!(self.tcp.poll_recv(cx))? {
                        Some(segment) => self.incoming.append(&segment)?,
                        None => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tls handshake eof",
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Drives the receive side until there is plaintext (in `plaintext`, or
    /// written into `sink`), the peer has closed, or an error.
    fn poll_plaintext(
        &mut self,
        cx: &mut Context<'_>,
        mut sink: Option<&mut ReadBuf<'_>>,
    ) -> Poll<io::Result<Readable>> {
        let sunk_before = sink.as_ref().map_or(0, |buf| buf.filled().len());
        loop {
            if !self.plaintext.is_empty() {
                return Poll::Ready(Ok(Readable::Queued));
            }
            if let Session::Failed(error) = &self.session {
                return Poll::Ready(Err(tls_error(error.clone())));
            }
            match self.read {
                ReadState::Open => {}
                ReadState::CloseNotify => return Poll::Ready(Ok(Readable::Eof)),
                ReadState::Truncated => return Poll::Ready(Err(truncated())),
            }
            if self.incoming.state == InputState::Fresh {
                let result = self.process(sink.as_deref_mut(), Job::None);
                if sink.as_ref().map_or(0, |buf| buf.filled().len()) > sunk_before {
                    // Hand over what was decrypted; an error (now sticky
                    // in `session`) surfaces on the next read.
                    return Poll::Ready(Ok(Readable::IntoSink));
                }
                result?;
                continue;
            }
            // Out with anything processing produced (an alert, a key
            // update): it must not wait for our next write.
            if !self.tx.is_empty()
                && let Poll::Ready(Err(e)) = self.poll_flush_tx(cx)
            {
                return Poll::Ready(Err(e));
            }
            match ready!(self.tcp.poll_recv(cx))? {
                Some(segment) => self.incoming.append(&segment)?,
                None => {
                    self.read = ReadState::Truncated;
                    return Poll::Ready(Err(truncated()));
                }
            }
        }
    }

    /// Encrypts a prefix of `slices` once everything encrypted before is
    /// with TCP (the backpressure point), and starts sending it. Returns
    /// how much plaintext was taken.
    fn poll_encrypt(
        &mut self,
        cx: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Session::Failed(error) = &self.session {
            return Poll::Ready(Err(tls_error(error.clone())));
        }
        if self.write != WriteState::Open {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.poll_flush_tx(cx))?;
        if slices.iter().all(|slice| slice.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        let (stop, done) = self.process(None, Job::Encrypt(slices))?;
        match (stop, done) {
            (_, Done::Encrypted(n)) if n > 0 => {
                // Pending is fine: the records are queued and the next
                // write or flush waits for them.
                if let Poll::Ready(Err(e)) = self.poll_flush_tx(cx) {
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(n))
            }
            (Stop::Closed, _) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            _ => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "TLS connection cannot encrypt application data",
            ))),
        }
    }

    /// Hands every queued encrypted record to TCP, in order.
    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(chunk) = self.tx.pop_front() {
            let mut slot = Some(chunk);
            match self.tcp.poll_send(cx, &mut slot) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if let Some(rest) = slot {
                        self.tx.push_front(rest);
                    }
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Runs rustls over `incoming` until it needs more input, may write, or
    /// is closed, doing `job` if it gets to write. Decrypted records go to
    /// `sink` while nothing is queued ahead of them, the rest to
    /// `plaintext`. A rustls error fails the session (see [`Self::fail`]).
    fn process(
        &mut self,
        sink: Option<&mut ReadBuf<'_>>,
        job: Job<'_>,
    ) -> io::Result<(Stop, Done)> {
        if let Session::Failed(error) = &self.session {
            return Err(tls_error(error.clone()));
        }
        let result = self.process_records(sink, job);
        // Even on error: records decrypted before it were authenticated.
        if !self.decrypted.is_empty() {
            self.plaintext.push_back(self.decrypted.split().freeze());
        }
        match result {
            Ok(stopped) => {
                self.incoming.state = InputState::Exhausted;
                Ok(stopped)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    fn process_records(
        &mut self,
        mut sink: Option<&mut ReadBuf<'_>>,
        mut job: Job<'_>,
    ) -> Result<(Stop, Done), rustls::Error> {
        let mut done = Done::NotRun;
        loop {
            let UnbufferedStatus { discard, state } =
                self.conn.process_tls_records(self.incoming.filled_mut());
            let mut discard = discard;
            let stop = match state {
                Err(error) => {
                    self.incoming.discard(discard)?;
                    return Err(error);
                }
                Ok(ConnectionState::ReadTraffic(mut traffic)) => {
                    while let Some(record) = traffic.next_record() {
                        let record = record?;
                        discard += record.discard;
                        deliver(
                            &self.plaintext,
                            &mut self.decrypted,
                            sink.as_deref_mut(),
                            record.payload,
                        );
                    }
                    None
                }
                Ok(ConnectionState::PeerClosed) => {
                    if self.read == ReadState::Open {
                        self.read = ReadState::CloseNotify;
                    }
                    None
                }
                Ok(ConnectionState::Closed) => Some(Stop::Closed),
                Ok(ConnectionState::EncodeTlsData(encode)) => {
                    let bytes = encode_into(&mut self.out, encode)?;
                    self.tx.push_back(bytes);
                    None
                }
                Ok(ConnectionState::TransmitTlsData(transmit)) => {
                    // Everything encoded is queued in `tx`, ahead of
                    // anything encrypted later, so as far as rustls is
                    // concerned it has been transmitted.
                    transmit.done();
                    None
                }
                Ok(ConnectionState::BlockedHandshake) => Some(Stop::Blocked),
                Ok(ConnectionState::WriteTraffic(mut traffic)) => {
                    match std::mem::replace(&mut job, Job::None) {
                        Job::None => {}
                        Job::Encrypt(slices) => {
                            let n = encrypt_slices(
                                &mut traffic,
                                &mut self.out,
                                &mut self.gather,
                                &mut self.tx,
                                slices,
                            )?;
                            done = Done::Encrypted(n);
                        }
                        Job::CloseNotify => {
                            let bytes = encrypt_into(&mut self.out, QUEUED_SLACK, |out| {
                                traffic.queue_close_notify(out)
                            })?;
                            self.tx.push_back(bytes);
                            done = Done::CloseNotifyQueued;
                        }
                    }
                    Some(Stop::Open)
                }
                // Early data is server-side only; anything newer is not
                // understood, so nothing is assumed about it.
                Ok(_) => {
                    return Err(rustls::Error::General(
                        "unexpected TLS connection state".into(),
                    ));
                }
            };
            self.incoming.discard(discard)?;
            if let Some(stop) = stop {
                return Ok((stop, done));
            }
        }
    }

    /// Makes `error` the session's permanent state after queueing and
    /// pushing (best effort, without waiting) whatever alert rustls wants
    /// sent, and returns it as an `io::Error`.
    fn fail(&mut self, error: rustls::Error) -> io::Error {
        // After an error rustls yields its queued alert as `EncodeTlsData`
        // on the next call, before it looks at `incoming` again. Exactly
        // one more call: a further one would deframe the offending bytes
        // again (rustls's state is the error by then, so it never returns
        // a writable state or plaintext, but a record that fails to
        // decrypt again would have it queue a second fatal alert).
        let UnbufferedStatus { discard, state } =
            self.conn.process_tls_records(self.incoming.filled_mut());
        if let Ok(ConnectionState::EncodeTlsData(encode)) = state
            && let Ok(bytes) = encode_into(&mut self.out, encode)
        {
            self.tx.push_back(bytes);
        }
        let _ = self.incoming.discard(discard);
        self.session = Session::Failed(error.clone());
        let mut cx = Context::from_waker(Waker::noop());
        let _ = self.poll_flush_tx(&mut cx);
        tls_error(error)
    }

    fn poll_shutdown_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.write {
                WriteState::Open => {
                    if let Session::Failed(error) = &self.session {
                        return Poll::Ready(Err(tls_error(error.clone())));
                    }
                    ready!(self.poll_flush_tx(cx))?;
                    // `NotRun` only if both sides already closed, when
                    // there is nothing more to say.
                    self.process(None, Job::CloseNotify)?;
                    self.write = WriteState::CloseNotifyQueued;
                }
                WriteState::CloseNotifyQueued => {
                    ready!(self.poll_flush_tx(cx))?;
                    ready!(Pin::new(&mut self.tcp).poll_shutdown(cx))?;
                    self.write = WriteState::Shutdown;
                }
                WriteState::Shutdown => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// Where [`TlsStream::poll_plaintext`] put what it found.
enum Readable {
    /// At the front of `plaintext`.
    Queued,
    /// Into the caller's `ReadBuf` (maybe more in `plaintext`).
    IntoSink,
    /// The peer sent `close_notify` and everything before it was delivered.
    Eof,
}

/// Copies a decrypted record out of rustls (copy 3): into `sink` while
/// nothing is queued ahead of it, and what does not fit into `decrypted`.
fn deliver(
    plaintext: &VecDeque<Bytes>,
    decrypted: &mut BytesMut,
    sink: Option<&mut ReadBuf<'_>>,
    mut payload: &[u8],
) {
    if let Some(sink) = sink
        && plaintext.is_empty()
        && decrypted.is_empty()
    {
        let n = payload.len().min(sink.remaining());
        sink.put_slice(&payload[..n]);
        payload = &payload[n..];
    }
    decrypted.extend_from_slice(payload);
}

/// Encodes a handshake record or alert into a fresh output buffer.
fn encode_into(
    out: &mut OutAlloc,
    mut encode: EncodeTlsData<'_, ClientConnectionData>,
) -> Result<Bytes, rustls::Error> {
    let mut len = ENCODE_GUESS;
    // The second attempt has exactly the size rustls asked for.
    for _ in 0..2 {
        let mut outcome = Ok(());
        let bytes = out.fill(len, |buf| match encode.encode(buf) {
            Ok(n) => n,
            Err(e) => {
                outcome = Err(e);
                0
            }
        });
        match outcome {
            Ok(()) => return Ok(bytes),
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                len = required_size;
            }
            Err(e) => return Err(rustls::Error::General(e.to_string())),
        }
    }
    Err(rustls::Error::General("TLS record encoding failed".into()))
}

/// Runs one rustls write operation (`queue_close_notify`) into a fresh
/// output buffer, retrying once with the size rustls asks for.
fn encrypt_into(
    out: &mut OutAlloc,
    guess: usize,
    mut op: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> Result<Bytes, rustls::Error> {
    let mut len = guess;
    for _ in 0..2 {
        let mut outcome = Ok(());
        let bytes = out.fill(len, |buf| match op(buf) {
            Ok(n) => n,
            Err(e) => {
                outcome = Err(e);
                0
            }
        });
        match outcome {
            Ok(()) => return Ok(bytes),
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                len = required_size;
            }
            Err(e) => return Err(encrypt_error(e)),
        }
    }
    Err(rustls::Error::General("TLS encryption failed".into()))
}

/// Size of the records `plaintext` bytes become, at most.
fn sealed_len(plaintext: usize) -> usize {
    plaintext + plaintext.div_ceil(MAX_RECORD_PLAINTEXT).max(1) * RECORD_OVERHEAD
}

/// The most plaintext whose records fit in `room` bytes.
fn plaintext_fitting(room: usize) -> usize {
    let full = room / (MAX_RECORD_PLAINTEXT + RECORD_OVERHEAD);
    let rest = room % (MAX_RECORD_PLAINTEXT + RECORD_OVERHEAD);
    full * MAX_RECORD_PLAINTEXT + rest.saturating_sub(RECORD_OVERHEAD)
}

/// Encrypts a prefix of `slices` into one output buffer of at most
/// [`MAX_OUT`] bytes (several records), queues it in `tx`, and returns how
/// many plaintext bytes it covers. Each slice is encrypted from where it
/// is, except runs of slices shorter than [`COALESCE_BELOW`], which are
/// gathered first. Every plaintext byte is encrypted exactly once: a unit
/// that does not fit is left for the next call, untouched.
fn encrypt_slices(
    traffic: &mut WriteTraffic<'_, ClientConnectionData>,
    out: &mut OutAlloc,
    gather: &mut Vec<u8>,
    tx: &mut VecDeque<Bytes>,
    slices: &[IoSlice<'_>],
) -> Result<usize, rustls::Error> {
    let wanted: usize = slices.iter().map(|slice| sealed_len(slice.len())).sum();
    let mut len = (wanted + QUEUED_SLACK).min(MAX_OUT);
    for _ in 0..2 {
        let mut taken = 0;
        let mut outcome = Ok(());
        let bytes = out.fill(len, |buf| {
            let cap = buf.len();
            let mut written = 0;
            let mut seal = |unit: &[u8], written: &mut usize| -> bool {
                match traffic.encrypt(unit, &mut buf[*written..]) {
                    Ok(n) => {
                        *written += n;
                        true
                    }
                    Err(e) => {
                        outcome = Err(e);
                        false
                    }
                }
            };
            gather.clear();
            for slice in slices {
                let room = cap.saturating_sub(written + QUEUED_SLACK);
                if slice.len() < COALESCE_BELOW
                    && gather.len() + slice.len() <= MAX_RECORD_PLAINTEXT
                    && sealed_len(gather.len() + slice.len()) <= room
                {
                    gather.extend_from_slice(slice);
                    continue;
                }
                if !gather.is_empty() {
                    if !seal(gather, &mut written) {
                        return written;
                    }
                    taken += gather.len();
                    gather.clear();
                }
                let room = cap.saturating_sub(written + QUEUED_SLACK);
                let n = slice.len().min(plaintext_fitting(room));
                if n == 0 {
                    return written;
                }
                if !seal(&slice[..n], &mut written) {
                    return written;
                }
                taken += n;
                if n < slice.len() {
                    return written;
                }
            }
            if !gather.is_empty() && seal(gather, &mut written) {
                taken += gather.len();
            }
            written
        });
        gather.clear();
        match outcome {
            Ok(()) => {}
            // Something did not fit after all: what did is kept. With
            // nothing written, retry once with the size rustls asked for.
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size }))
                if taken == 0 =>
            {
                len = required_size;
                continue;
            }
            Err(EncryptError::InsufficientSize(_)) => {}
            Err(e) => return Err(encrypt_error(e)),
        }
        if !bytes.is_empty() {
            tx.push_back(bytes);
        }
        if taken > 0 {
            return Ok(taken);
        }
    }
    Err(rustls::Error::General(
        "TLS encryption made no progress".into(),
    ))
}

fn encrypt_error(e: EncryptError) -> rustls::Error {
    rustls::Error::General(e.to_string())
}

fn tls_error(error: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "peer closed connection without sending TLS close_notify",
    )
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match ready!(this.poll_plaintext(cx, Some(buf)))? {
            Readable::Eof => {}
            Readable::Queued | Readable::IntoSink => {
                // Records that overflowed earlier reads (or this one).
                while buf.remaining() > 0
                    && let Some(front) = this.plaintext.front_mut()
                {
                    let n = front.len().min(buf.remaining());
                    buf.put_slice(&front[..n]);
                    front.advance(n);
                    if front.is_empty() {
                        this.plaintext.pop_front();
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_encrypt(cx, &[IoSlice::new(buf)])
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_encrypt(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    /// Hands every encrypted record to TCP. Like [`TcpStream`]'s, not a
    /// cork-release point.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_tx(cx))?;
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    /// Sends `close_notify`, then half-closes TCP. Reading may continue.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_shutdown_tls(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::dpdk::tcp::stream::tests::fixture;
    use crate::dpdk::tcp::worker::{CmdRx, Command, Inbound, InboundTx, SendCredit};

    const CA: &[u8] = include_bytes!("tls_testdata/ca.pem");
    const CERT: &[u8] = include_bytes!("tls_testdata/server.pem");
    const KEY: &[u8] = include_bytes!("tls_testdata/server.key");

    /// The worker's side of a [`TcpStream`]'s rings, as a tokio byte
    /// stream for a server: what the client sends is read here (returning
    /// its send credit, as an ACK would); what is written here reaches the
    /// client as `Inbound::Data` segments of the sizes in `segments`
    /// (cycled), so records can be cut anywhere.
    struct Peer {
        cmd_rx: CmdRx,
        inbound_tx: InboundTx,
        credit: Arc<SendCredit>,
        unread: Bytes,
        client_closed: bool,
        segments: Vec<usize>,
        next_segment: usize,
        out: VecDeque<u8>,
        /// Queue writes until flush, so many records share one segment.
        batch: bool,
        /// Flip the last byte of the next write (a record's tag).
        tamper: bool,
        /// Sizes of the client's `Command::Send`s.
        sends: Vec<usize>,
    }

    impl Peer {
        fn push_out(&mut self) -> bool {
            while !self.out.is_empty() {
                let size = self.segments[self.next_segment % self.segments.len()];
                let n = size.min(self.out.len());
                let segment: Vec<u8> = self.out.iter().take(n).copied().collect();
                if self
                    .inbound_tx
                    .push(Inbound::Data(Bytes::from(segment)))
                    .is_err()
                {
                    return false;
                }
                self.out.drain(..n);
                self.next_segment += 1;
            }
            true
        }

        /// Ends TCP without `close_notify`.
        fn fin(&mut self) {
            assert!(self.push_out());
            assert!(self.inbound_tx.push(Inbound::Eof).is_ok());
        }
    }

    impl AsyncRead for Peer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                if !self.unread.is_empty() {
                    let n = self.unread.len().min(buf.remaining());
                    buf.put_slice(&self.unread[..n]);
                    self.unread.advance(n);
                    return Poll::Ready(Ok(()));
                }
                match self.cmd_rx.pop() {
                    Some(Command::Send(bytes)) => {
                        self.credit.bytes.fetch_sub(bytes.len(), Ordering::AcqRel);
                        self.sends.push(bytes.len());
                        self.unread = bytes;
                    }
                    Some(Command::Close) => self.client_closed = true,
                    Some(_) => {}
                    None if self.client_closed || self.cmd_rx.is_closed() => {
                        return Poll::Ready(Ok(()));
                    }
                    None => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    impl AsyncWrite for Peer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = &mut *self;
            let start = this.out.len();
            this.out.extend(buf);
            if this.tamper && !buf.is_empty() {
                this.tamper = false;
                let last = start + buf.len() - 1;
                this.out[last] ^= 0x01;
            }
            if !this.batch {
                this.push_out();
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.push_out() {
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            ready!(Pin::new(&mut *this).poll_flush(cx))?;
            let _ = this.inbound_tx.push(Inbound::Eof);
            Poll::Ready(Ok(()))
        }
    }

    fn pair(segments: &[usize]) -> (TcpStream, Peer) {
        let (tcp, cmd_rx, inbound_tx, credit) = fixture();
        let peer = Peer {
            cmd_rx,
            inbound_tx,
            credit,
            unread: Bytes::new(),
            client_closed: false,
            segments: segments.to_vec(),
            next_segment: 0,
            out: VecDeque::new(),
            batch: false,
            tamper: false,
            sends: Vec::new(),
        };
        (tcp, peer)
    }

    fn server_config(
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&[u8]],
    ) -> Arc<ServerConfig> {
        let certs = rustls_pemfile::certs(&mut &CERT[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
        let mut config = ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }

    fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &CA[..]) {
            roots.add(cert.unwrap()).unwrap();
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }

    type ServerTls = tokio_rustls::server::TlsStream<Peer>;

    fn name() -> ServerName<'static> {
        ServerName::try_from("test.local").unwrap()
    }

    /// Handshakes a client over a fresh pair against a server with
    /// `server`'s configuration.
    async fn established(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        segments: &[usize],
    ) -> (TlsStream, ServerTls) {
        let (tcp, peer) = pair(segments);
        let acceptor = tokio_rustls::TlsAcceptor::from(server);
        let (client, server) = tokio::join!(connect(client, name(), tcp), acceptor.accept(peer));
        (client.unwrap(), server.unwrap())
    }

    fn tls13() -> Arc<ServerConfig> {
        server_config(&[&rustls::version::TLS13], &[])
    }

    fn run<F: std::future::Future>(test: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(60), test)
                    .await
                    .expect("test timed out")
            })
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
            .collect()
    }

    async fn recv_all(client: &mut TlsStream, len: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < len {
            got.extend_from_slice(&client.recv().await.unwrap().expect("early EOF"));
        }
        got
    }

    #[test]
    fn tls13_handshake_negotiates_alpn_and_carries_data_both_ways() {
        run(async {
            let server = server_config(&[&rustls::version::TLS13], &[b"h2", b"http/1.1"]);
            let (mut client, mut server) =
                established(client_config(&[b"h2", b"http/1.1"]), server, &[1448]).await;
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(
                client.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );

            server.write_all(b"hello").await.unwrap();
            server.flush().await.unwrap();
            assert_eq!(&client.recv().await.unwrap().unwrap()[..], b"hello");
            client.send(Bytes::from_static(b"ping")).await.unwrap();
            let mut buf = [0; 4];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });
    }

    #[test]
    fn tls12_handshake_and_alpn_fallback_to_http1() {
        run(async {
            let server = server_config(&[&rustls::version::TLS12], &[b"http/1.1"]);
            let (mut client, mut server) =
                established(client_config(&[b"h2", b"http/1.1"]), server, &[1448]).await;
            assert_eq!(
                client.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            client.write_all(b"over tls 1.2").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = [0; 12];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"over tls 1.2");
            server.write_all(b"back").await.unwrap();
            server.flush().await.unwrap();
            let mut buf = [0; 4];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"back");
        });
    }

    #[test]
    fn records_cut_at_awkward_segment_boundaries_reassemble() {
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            run(async {
                let server = server_config(&[version], &[]);
                let (mut client, mut server) =
                    established(client_config(&[]), server, &[1, 2, 3, 5, 7, 4096, 13, 1448]).await;
                let mut expected = Vec::new();
                for (i, len) in (0..120)
                    .map(|i| (i, (i * 37) % 2000 + 1))
                    .chain([(200, 100_000)])
                {
                    let chunk = pattern(len, i as u8);
                    server.write_all(&chunk).await.unwrap();
                    expected.extend_from_slice(&chunk);
                }
                server.flush().await.unwrap();
                // Half through the owned face, half through AsyncRead with
                // an awkward buffer size.
                let half = expected.len() / 2;
                let mut got = recv_all(&mut client, half).await;
                let mut buf = vec![0; 777];
                while got.len() < expected.len() {
                    let n = client.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&buf[..n]);
                }
                assert_eq!(got, expected);
            });
        }
    }

    #[test]
    fn many_records_in_one_segment() {
        run(async {
            let (mut client, mut server) =
                established(client_config(&[]), tls13(), &[1 << 20]).await;
            server.get_mut().0.batch = true;
            let mut expected = Vec::new();
            for i in 0..200u32 {
                let chunk = i.to_be_bytes();
                server.write_all(&chunk).await.unwrap();
                expected.extend_from_slice(&chunk);
            }
            let before = server.get_ref().0.next_segment;
            server.flush().await.unwrap();
            assert_eq!(server.get_ref().0.next_segment, before + 1, "one segment");
            // All 200 records decrypt in one pass and leave as one chunk.
            let chunk = client.recv().await.unwrap().unwrap();
            assert_eq!(&chunk[..], &expected[..]);
        });
    }

    #[test]
    fn large_writes_span_records_and_share_buffers() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            let owned = pattern(1 << 20, 1);
            let borrowed = pattern(300_000, 2);
            let sent = Bytes::from(owned.clone());
            let borrowed2 = borrowed.clone();
            let writer = async move {
                client.send(sent).await.unwrap();
                client.write_all(&borrowed2).await.unwrap();
                client.flush().await.unwrap();
                client
            };
            let reader = async {
                let mut got = vec![0; owned.len() + borrowed.len()];
                server.read_exact(&mut got).await.unwrap();
                got
            };
            let (_client, got) = tokio::join!(writer, reader);
            assert_eq!(&got[..owned.len()], &owned[..]);
            assert_eq!(&got[owned.len()..], &borrowed[..]);
            let sends = &server.get_ref().0.sends;
            // Each buffer carries several 16 KiB records.
            assert!(sends.iter().any(|&n| n > 3 * MAX_RECORD_PLAINTEXT));
            // Encrypted exactly once: total ciphertext is the plaintext plus
            // at most per-record overhead (and the handshake).
            let total: usize = sends.iter().sum();
            let plain = owned.len() + borrowed.len();
            let records = plain.div_ceil(MAX_RECORD_PLAINTEXT) + sends.len();
            assert!(total >= plain);
            assert!(
                total <= plain + records * RECORD_OVERHEAD + 4096,
                "{total} for {plain}"
            );
        });
    }

    #[test]
    fn backpressure_keeps_encrypted_bytes_without_reencrypting() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            // Exceed the transport credit even when its default changes.
            let payload = pattern(2 * crate::dpdk::tcp::worker::SEND_CAPACITY, 3);
            let mut data = Some(Bytes::from(payload.clone()));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(client.poll_send(&mut cx, &mut data).is_pending());
            let left = data.as_ref().unwrap().len();
            assert!(left > 0 && left < payload.len());
            let queued: usize = client.tx.iter().map(Bytes::len).sum();
            assert!(queued > 0);
            // Still no credit: nothing is encrypted again or dropped.
            assert!(client.poll_send(&mut cx, &mut data).is_pending());
            assert_eq!(data.as_ref().unwrap().len(), left);
            assert_eq!(client.tx.iter().map(Bytes::len).sum::<usize>(), queued);

            let writer = async {
                poll_fn(|cx| client.poll_send(cx, &mut data)).await.unwrap();
                assert!(data.is_none());
            };
            let reader = async {
                let mut got = vec![0; payload.len()];
                server.read_exact(&mut got).await.unwrap();
                got
            };
            let ((), got) = tokio::join!(writer, reader);
            assert_eq!(got, payload);
        });
    }

    #[test]
    fn session_tickets_and_key_updates_mid_stream() {
        run(async {
            let client_config = client_config(&[]);
            // One server config: its session cache resumes the ticket.
            let server_config = tls13();
            let (mut client, mut server) =
                established(client_config.clone(), server_config.clone(), &[700]).await;
            assert_eq!(
                client.conn.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            server.write_all(b"one").await.unwrap();
            server.flush().await.unwrap();
            // The tickets precede "one"; they are post-handshake messages.
            assert_eq!(&recv_all(&mut client, 3).await[..], b"one");
            // A KeyUpdate asking us to update too, between data records.
            server.get_mut().1.refresh_traffic_keys().unwrap();
            server.write_all(b"two").await.unwrap();
            server.flush().await.unwrap();
            assert_eq!(&recv_all(&mut client, 3).await[..], b"two");
            // Our reply KeyUpdate goes out ahead of this data.
            client.send(Bytes::from_static(b"three")).await.unwrap();
            let mut buf = [0; 5];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"three");
            server.write_all(b"four").await.unwrap();
            server.flush().await.unwrap();
            assert_eq!(&recv_all(&mut client, 4).await[..], b"four");

            // The ticket was stored: a second connection resumes.
            let (client2, _server2) = established(client_config, server_config, &[1448]).await;
            assert_eq!(
                client2.conn.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
        });
    }

    #[test]
    fn close_notify_from_the_server_is_a_clean_eof() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            server.write_all(b"last words").await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(&recv_all(&mut client, 10).await[..], b"last words");
            assert!(client.recv().await.unwrap().is_none());
            assert!(client.recv().await.unwrap().is_none());
            let mut buf = [0; 8];
            assert_eq!(client.read(&mut buf).await.unwrap(), 0);
            // Still writable after the peer's close_notify.
            client.send(Bytes::from_static(b"bye")).await.unwrap();
            let mut buf = [0; 3];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"bye");
        });
    }

    #[test]
    fn shutdown_sends_close_notify_then_fin() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            client.write_all(b"done").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            // A clean TLS EOF on the server: close_notify was received.
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"done");
            // Then the TCP FIN, and nothing after the alert.
            let mut rest = [0; 1];
            assert_eq!(server.get_mut().0.read(&mut rest).await.unwrap(), 0);
            assert!(server.get_ref().0.client_closed);
            assert_eq!(
                client.write(b"more").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            // Reading continues after our half-close.
            server.write_all(b"reply").await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(&recv_all(&mut client, 5).await[..], b"reply");
            assert!(client.recv().await.unwrap().is_none());
        });
    }

    #[test]
    fn truncation_without_close_notify_is_an_error() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            server.write_all(b"partial").await.unwrap();
            server.flush().await.unwrap();
            server.get_mut().0.fin();
            assert_eq!(&recv_all(&mut client, 7).await[..], b"partial");
            let err = client.recv().await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            let mut buf = [0; 4];
            let err = client.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        });
    }

    #[test]
    fn truncation_mid_record_is_an_error() {
        run(async {
            let (mut client, mut server) = established(client_config(&[]), tls13(), &[1448]).await;
            server.get_mut().0.batch = true;
            server.write_all(&pattern(5000, 9)).await.unwrap();
            let peer = &mut server.get_mut().0;
            let keep = peer.out.len() - 100;
            peer.out.truncate(keep);
            peer.fin();
            let err = client.recv().await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        });
    }

    #[test]
    fn handshake_eof_is_an_error() {
        run(async {
            let (tcp, mut peer) = pair(&[1448]);
            peer.fin();
            let err = connect(client_config(&[]), name(), tcp)
                .await
                .err()
                .unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        });
    }

    #[test]
    fn untrusted_certificate_fails_the_handshake_and_alerts() {
        run(async {
            let (tcp, peer) = pair(&[1448]);
            let acceptor = tokio_rustls::TlsAcceptor::from(tls13());
            let wrong_name = ServerName::try_from("other.example").unwrap();
            let (client, server) = tokio::join!(
                connect(client_config(&[]), wrong_name, tcp),
                acceptor.accept(peer)
            );
            let err = client.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            // The server got our certificate alert.
            let err = server.err().unwrap();
            assert!(err.to_string().contains("received fatal alert"), "{err}");
        });
    }

    #[test]
    fn corrupted_record_is_rejected_and_never_delivered() {
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            run(async {
                let server = server_config(&[version], &[]);
                let (mut client, mut server) =
                    established(client_config(&[]), server, &[1448]).await;
                server.write_all(b"good").await.unwrap();
                server.flush().await.unwrap();
                assert_eq!(&recv_all(&mut client, 4).await[..], b"good");
                server.get_mut().0.tamper = true;
                server.write_all(b"evil payload").await.unwrap();
                server.flush().await.unwrap();
                let err = client.recv().await.unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert!(err.to_string().contains("decrypt"), "{err}");
                // Sticky, on every face.
                let mut buf = [0; 4];
                assert_eq!(
                    client.read(&mut buf).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(
                    client.write(b"x").await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                // The bad_record_mac alert reached the server.
                let mut rest = Vec::new();
                let err = server.read_to_end(&mut rest).await.unwrap_err();
                assert!(err.to_string().contains("BadRecordMac"), "{err}");
            });
        }
    }

    #[test]
    fn incoming_buffer_moves_partial_record_only_when_tail_runs_out() {
        let mut incoming = Incoming::new();
        incoming.append(&[1; 100]).unwrap();
        incoming.discard(60).unwrap();
        assert_eq!((incoming.start, incoming.end), (60, 100));
        incoming.append(&vec![2; INCOMING_CAPACITY - 100]).unwrap();
        assert_eq!(incoming.start, 60, "fits behind: no move");
        incoming.append(&[3; 100]).unwrap();
        assert_eq!(incoming.start, 0, "moved to the front");
        // 40 held + (CAPACITY - 100) + 100: moving freed only 60, so it grew.
        assert_eq!(incoming.len(), INCOMING_CAPACITY + 40);
        assert_eq!(incoming.buf.len(), INCOMING_CAPACITY + 40);
        assert!(incoming.discard(incoming.len() + 1).is_err());
        incoming.discard(incoming.len()).unwrap();
        assert_eq!((incoming.start, incoming.end), (0, 0));
        assert!(incoming.append(&vec![0; INCOMING_LIMIT + 1]).is_err());
    }

    #[test]
    fn record_size_bounds() {
        assert_eq!(sealed_len(1), 1 + RECORD_OVERHEAD);
        assert_eq!(
            sealed_len(MAX_RECORD_PLAINTEXT + 1),
            MAX_RECORD_PLAINTEXT + 1 + 2 * RECORD_OVERHEAD
        );
        for room in [33, 100, 16_416, 16_417, 40_000, MAX_OUT] {
            let p = plaintext_fitting(room);
            assert!(p > 0 && sealed_len(p) <= room, "{room}: {p}");
        }
    }

    /// hyper server over tokio-rustls over the peer, for end-to-end tests.
    async fn serve(server: ServerTls, h2: bool) {
        let service = hyper::service::service_fn(
            |request: hyper::Request<hyper::body::Incoming>| async move {
                let path = request.uri().path().to_owned();
                let body = request.into_body().collect().await?.to_bytes();
                Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from(
                    expected_reply(&path, body.len()),
                ))))
            },
        );
        let io = TokioIo::new(server);
        if h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
                .unwrap();
        } else {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
                .unwrap();
        }
    }

    fn expected_reply(path: &str, len: usize) -> Vec<u8> {
        let mut reply = format!("{path}:{len}:").into_bytes();
        reply.extend_from_slice(&pattern(100_000, 5));
        reply
    }

    #[test]
    fn hyper_http1_end_to_end() {
        run(async {
            let server = server_config(&[&rustls::version::TLS13], &[b"http/1.1"]);
            let (client, server) =
                established(client_config(&[b"http/1.1"]), server, &[1448, 3, 9000]).await;
            assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
            let server = tokio::spawn(serve(server, false));
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
                .await
                .unwrap();
            let conn = tokio::spawn(conn);
            for (path, len) in [("/a", 0), ("/b", 70_000), ("/c", 5)] {
                let request = hyper::Request::post(path)
                    .header("host", "test.local")
                    .body(Full::new(Bytes::from(pattern(len, 7))))
                    .unwrap();
                let response = sender.send_request(request).await.unwrap();
                assert_eq!(response.status(), 200);
                let body = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&body[..], &expected_reply(path, len)[..]);
            }
            drop(sender);
            conn.await.unwrap().unwrap();
            server.await.unwrap();
        });
    }

    /// The zero-copy HTTP/1.1 codec over this stream's owned-`Bytes` face,
    /// against a real HTTP/1.1 server: a buffered body and a streamed
    /// (chunked) one, each on its own connection, as the client sends them.
    #[test]
    fn h1_codec_end_to_end() {
        use crate::dpdk::http::h1;
        use crate::http::codec::{ByteStream, EncodedBody};

        run(async {
            for (path, len, streamed) in [
                ("/a", 0, false),
                ("/b", 70_000, false),
                ("/c", 50_000, true),
            ] {
                let server = server_config(&[&rustls::version::TLS13], &[b"http/1.1"]);
                let (client, server) =
                    established(client_config(&[b"http/1.1"]), server, &[1448, 3, 9000]).await;
                let server = tokio::spawn(serve(server, false));
                let payload = Bytes::from(pattern(len, 7));
                let body = if streamed {
                    let chunks: Vec<Bytes> =
                        payload.chunks(7_000).map(Bytes::copy_from_slice).collect();
                    EncodedBody::Stream(ByteStream::from(futures::stream::iter(chunks)))
                } else {
                    EncodedBody::Full(payload)
                };
                let parts = hyper::Request::post(path)
                    .header("host", "test.local")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0;
                let response = h1::send_over_tls(client, parts, body).await.unwrap();
                assert_eq!(response.status(), 200);
                let body = response.into_body().collect().await.unwrap();
                assert_eq!(&body[..], &expected_reply(path, len)[..]);
                // The request asked the server to close; it must finish
                // cleanly once the response is out.
                server.await.unwrap();
            }
        });
    }

    #[test]
    fn hyper_http2_end_to_end() {
        run(async {
            let server = server_config(&[&rustls::version::TLS13], &[b"h2", b"http/1.1"]);
            let (client, server) =
                established(client_config(&[b"h2", b"http/1.1"]), server, &[1448]).await;
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            let server = tokio::spawn(serve(server, true));
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let conn = tokio::spawn(conn);
            let mut requests = Vec::new();
            for (i, len) in [0usize, 40_000, 3, 200_000].into_iter().enumerate() {
                let mut sender = sender.clone();
                requests.push(tokio::spawn(async move {
                    let path = format!("/r{i}");
                    let request = hyper::Request::post(format!("https://test.local{path}"))
                        .body(Full::new(Bytes::from(pattern(len, 7))))
                        .unwrap();
                    let response = sender.send_request(request).await.unwrap();
                    assert_eq!(response.status(), 200);
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(&body[..], &expected_reply(&path, len)[..]);
                }));
            }
            for request in requests {
                request.await.unwrap();
            }
            drop(sender);
            conn.await.unwrap().unwrap();
            server.await.unwrap();
        });
    }
}

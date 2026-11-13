//! A hand-rolled, zero-copy HTTP/1.1 client codec, used for plain `http://`
//! requests in place of hyper.
//!
//! Why: hyper speaks through `AsyncRead`/`AsyncWrite`, which forces a copy
//! in each direction at the [`TcpStream`] boundary (a borrowed write slice
//! into owned memory, an owned received chunk into hyper's read buffer).
//! This codec instead moves owned [`Bytes`] both ways:
//!
//! - **Requests**: the request line and headers are serialised once, in
//!   place, into one buffer -- DMA memory when the port attaches it to
//!   packets without copying (see [`DmaWriter::fill`]), else the heap. The
//!   body `Bytes` are then sent untouched. Streamed bodies get chunked
//!   framing as small separate buffers around each untouched chunk.
//! - **Responses**: the head is parsed with `httparse` directly over the
//!   first received chunk; only a head that straddles chunks is gathered
//!   into a contiguous buffer, and then only its own bytes are copied. Body
//!   data is handed out as slices of the received chunks (refcounted views
//!   of NIC packet buffers), never copied.
//!
//! The codec runs over any [`Transport`], a two-method owned-`Bytes` I/O
//! trait, so it can run over TLS by adding one impl, and is unit tested
//! here over an in-memory transport.
//!
//! Scope: one request per connection (`Connection: close` unless the caller
//! chose otherwise); the connection is dropped when the response body ends.
//! Protocol upgrades (`101`, WebSocket) stay on hyper.
//!
//! The response side parses untrusted input: the head is bounded
//! ([`MAX_HEAD_SIZE`], [`MAX_HEADERS`], [`MAX_INTERIM_RESPONSES`]), chunk
//! framing is bounded ([`MAX_CHUNK_LINE`], [`MAX_TRAILERS_SIZE`]) and chunk
//! sizes are parsed with overflow checks. Malformed input is an error,
//! never a panic.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Response, StatusCode, Version, request, response};
use serde::de::DeserializeOwned;

use crate::dpdk::DmaWriter;
use crate::dpdk::tcp::stream::TcpStream;
use crate::http::codec::{self, EncodedBody};
use crate::http::errors::HttpError;

/// Largest response head (status line, headers, final empty line, plus any
/// blank lines before the status line) accepted, per response.
pub const MAX_HEAD_SIZE: usize = 64 * 1024;
/// Most header fields accepted in one response head.
pub const MAX_HEADERS: usize = 100;
/// Most interim (1xx) responses skipped before the final response. A server
/// could otherwise keep the client reading interim heads forever.
pub const MAX_INTERIM_RESPONSES: usize = 32;
/// Longest chunk-size line (size, extensions, CRLF) accepted.
pub const MAX_CHUNK_LINE: usize = 4096;
/// Largest trailer section accepted (it is read and discarded).
pub const MAX_TRAILERS_SIZE: usize = 64 * 1024;
/// Most bytes [`Body::collect`] reserves up front from a `Content-Length`,
/// so a lying header cannot make it allocate an absurd buffer before any
/// data has arrived. Larger bodies still collect; the buffer just grows.
const MAX_COLLECT_RESERVE: u64 = 16 * 1024 * 1024;

/// Owned-[`Bytes`] I/O the codec runs over. Mirrors [`TcpStream`]'s
/// zero-copy inherent methods, so a TLS stream offering the same two
/// methods can carry the codec too.
pub trait Transport {
    /// Sends `data`; on `Ready(Ok)` it has been taken. On `Pending` it holds
    /// the unsent suffix.
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &mut Option<Bytes>)
    -> Poll<io::Result<()>>;

    /// Receives the next chunk. `Ok(None)` is a clean end of input.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>>;
}

impl Transport for TcpStream {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        TcpStream::poll_send(self, cx, data)
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        TcpStream::poll_recv(self, cx)
    }
}

/// Why a response could not be read. Kept apart from [`HttpError`] (which
/// reports all of these as [`HttpError::Protocol`], as the hyper path does)
/// so the cause stays visible to tests and logs; in particular a truncated
/// body is distinct from a clean end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1Error {
    /// The transport failed.
    Io(io::ErrorKind),
    /// The connection ended before a complete response head arrived.
    IncompleteHead,
    /// The response head exceeded [`MAX_HEAD_SIZE`].
    HeadTooLarge,
    /// The response head had more than [`MAX_HEADERS`] fields.
    TooManyHeaders,
    /// The response head is not valid HTTP/1.x.
    MalformedHead,
    /// The server answered `101 Switching Protocols`, which this codec
    /// never asks for (upgrades go through hyper).
    UnexpectedUpgrade,
    /// More than [`MAX_INTERIM_RESPONSES`] interim responses.
    TooManyInterimResponses,
    /// `Content-Length` was invalid or its values disagreed.
    InvalidContentLength,
    /// `Transfer-Encoding` on an HTTP/1.0 response, which RFC 9112 §6.1
    /// says to treat as faulty framing.
    InvalidTransferEncoding,
    /// Chunked framing was malformed.
    MalformedChunk,
    /// A chunk size does not fit in 64 bits.
    ChunkSizeOverflow,
    /// A chunk-size line exceeded [`MAX_CHUNK_LINE`].
    ChunkLineTooLong,
    /// The trailer section exceeded [`MAX_TRAILERS_SIZE`].
    TrailersTooLarge,
    /// The connection ended before the framed end of the body.
    Truncated,
}

impl From<H1Error> for HttpError {
    fn from(_: H1Error) -> Self {
        HttpError::Protocol
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// How the request body is delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestFraming {
    /// Exactly this many body bytes, sent as is. Checked against what the
    /// body actually yields, since a mismatch would desynchronise the
    /// connection.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// The framing header the codec adds to the caller's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FramingHeader {
    /// The caller already set `Content-Length` or `Transfer-Encoding`.
    CallerSet,
    /// No body, and the method does not anticipate one: no header at all
    /// (RFC 9110 §8.6).
    Omitted,
    ContentLength(u64),
    Chunked,
}

/// Whether the codec adds `Connection: close`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionHeader {
    /// The caller set `Connection` themselves; it is left alone.
    CallerSet,
    /// One request per connection, so tell the server.
    Close,
}

/// A request whose framing has been decided and validated, ready to have
/// its head encoded and to be exchanged over a [`Transport`].
///
/// `parts` must already be in origin form with a `Host` header (the client
/// does this with `rewrite_to_origin_form`, as for hyper).
pub struct PreparedRequest {
    parts: request::Parts,
    body: EncodedBody,
    framing: RequestFraming,
    framing_header: FramingHeader,
    connection: ConnectionHeader,
}

impl PreparedRequest {
    /// Decides the body framing, respecting framing headers the caller set:
    /// a caller's `Content-Length` is kept (and must match a full body), a
    /// caller's `Transfer-Encoding` must end in `chunked` (RFC 9112 §6.1)
    /// and makes the body chunked. Otherwise a full body gets
    /// `Content-Length` and a streamed body gets chunked encoding.
    pub fn new(parts: request::Parts, body: EncodedBody) -> Result<Self, HttpError> {
        let content_length =
            content_length(&parts.headers).map_err(|_| HttpError::MalformedRequest)?;
        let (framing, framing_header) = match (transfer_coding(&parts.headers), content_length) {
            // A sender must not send both (RFC 9112 §6.2).
            (TransferCoding::Chunked | TransferCoding::Other, Some(_)) => {
                return Err(HttpError::MalformedRequest);
            }
            (TransferCoding::Chunked, None) => (RequestFraming::Chunked, FramingHeader::CallerSet),
            (TransferCoding::Other, None) => return Err(HttpError::MalformedRequest),
            (TransferCoding::Absent, Some(n)) => {
                if let EncodedBody::Full(bytes) = &body
                    && bytes.len() as u64 != n
                {
                    return Err(HttpError::MalformedRequest);
                }
                (RequestFraming::Length(n), FramingHeader::CallerSet)
            }
            (TransferCoding::Absent, None) => match &body {
                EncodedBody::Full(bytes)
                    if bytes.is_empty() && !anticipates_body(&parts.method) =>
                {
                    (RequestFraming::Length(0), FramingHeader::Omitted)
                }
                EncodedBody::Full(bytes) => {
                    let n = bytes.len() as u64;
                    (RequestFraming::Length(n), FramingHeader::ContentLength(n))
                }
                EncodedBody::Stream(_) => (RequestFraming::Chunked, FramingHeader::Chunked),
            },
        };
        let connection = if parts.headers.contains_key(header::CONNECTION) {
            ConnectionHeader::CallerSet
        } else {
            ConnectionHeader::Close
        };
        Ok(Self {
            parts,
            body,
            framing,
            framing_header,
            connection,
        })
    }

    /// Serialises the request line and headers into one buffer: in place in
    /// DMA memory when `dma` is given and has room (so the worker attaches
    /// it to the packet with no copy), else on the heap (the worker copies
    /// it into the packet, as for any heap `Bytes`).
    pub fn encode_head(&self, dma: Option<&mut DmaWriter>) -> Bytes {
        let mut measure = Measure(0);
        self.write_head(&mut measure);
        let len = measure.0;
        if let Some(head) =
            dma.and_then(|dma| dma.fill(len, |out| self.write_head(&mut Fill { out, at: 0 })))
        {
            return head;
        }
        let mut out = vec![0; len];
        self.write_head(&mut Fill {
            out: &mut out,
            at: 0,
        });
        Bytes::from(out)
    }

    /// The single serialisation routine, run once to measure and once to
    /// write, so the two can never disagree.
    fn write_head(&self, out: &mut impl Sink) {
        let target = self
            .parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str());
        out.put(self.parts.method.as_str().as_bytes());
        out.put(b" ");
        if target.is_empty() || target.starts_with('?') {
            out.put(b"/");
        }
        out.put(target.as_bytes());
        out.put(b" HTTP/1.1\r\n");
        // `http` validates names and values: neither can hold CR or LF.
        for (name, value) in &self.parts.headers {
            out.put(name.as_str().as_bytes());
            out.put(b": ");
            out.put(value.as_bytes());
            out.put(b"\r\n");
        }
        match self.framing_header {
            FramingHeader::CallerSet | FramingHeader::Omitted => {}
            FramingHeader::ContentLength(n) => {
                out.put(b"content-length: ");
                out.put(decimal(n, &mut [0; 20]));
                out.put(b"\r\n");
            }
            FramingHeader::Chunked => out.put(b"transfer-encoding: chunked\r\n"),
        }
        match self.connection {
            ConnectionHeader::CallerSet => {}
            ConnectionHeader::Close => out.put(b"connection: close\r\n"),
        }
        out.put(b"\r\n");
    }

    /// Sends `head` and the body over `io`, then reads the response head.
    /// The returned body owns `io` and drops it when the body ends.
    ///
    /// The whole request is sent before the response is read: a server that
    /// answers early and stops reading a large streamed body stalls the
    /// send (as one would expect with connection-per-request and no
    /// `Expect: 100-continue` handling).
    pub async fn exchange<T: Transport + Unpin>(
        self,
        mut io: T,
        head: Bytes,
    ) -> Result<Response<Body<T>>, HttpError> {
        let Self {
            parts,
            body,
            framing,
            ..
        } = self;
        send(&mut io, head).await?;
        send_body(&mut io, body, framing).await?;
        let (parts, body) = read_response(io, &parts.method).await?;
        Ok(Response::from_parts(parts, body))
    }
}

/// Sends one request over a fresh plain-TCP connection, with its head
/// written into DMA memory when the port supports that.
pub async fn send_over_tcp(
    mut tcp: TcpStream,
    parts: request::Parts,
    body: EncodedBody,
) -> Result<Response<Body<TcpStream>>, HttpError> {
    let request = PreparedRequest::new(parts, body)?;
    let head = request.encode_head(tcp.dma_writer());
    request.exchange(tcp, head).await
}

/// Turns a codec response into the typed response `Client::request`
/// returns: a [`ByteStream`](codec::ByteStream) target gets the body
/// unbuffered (the stream owns the connection until the body ends);
/// anything else is collected and decoded for its `Content-Type`.
pub async fn into_typed_response<R, T>(
    response: Response<Body<T>>,
) -> Result<Response<R>, HttpError>
where
    R: DeserializeOwned + 'static,
    T: Transport + Unpin + Send + 'static,
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

/// Methods whose semantics anticipate a body, so an empty one is still
/// announced with `Content-Length: 0`.
fn anticipates_body(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET
            | Method::HEAD
            | Method::DELETE
            | Method::OPTIONS
            | Method::TRACE
            | Method::CONNECT
    )
}

async fn send<T: Transport + Unpin>(io: &mut T, data: Bytes) -> Result<(), HttpError> {
    if data.is_empty() {
        return Ok(());
    }
    let mut data = Some(data);
    poll_fn(|cx| io.poll_send(cx, &mut data))
        .await
        .map_err(|_| HttpError::Protocol)
}

/// The terminating chunk when no data chunk preceded it.
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";
/// The terminating chunk, preceded by the CRLF closing the last data chunk.
const CRLF_LAST_CHUNK: &[u8] = b"\r\n0\r\n\r\n";

/// The framing before a data chunk of `len` bytes: the size line, preceded
/// by the CRLF closing the previous chunk unless this is the first. Merging
/// the two keeps it to one small buffer per chunk.
fn chunk_prefix(len: usize, first: bool) -> Bytes {
    let mut digits = [0; 16];
    let digits = hex(len as u64, &mut digits);
    let mut out = BytesMut::with_capacity(2 + digits.len() + 2);
    if !first {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(digits);
    out.extend_from_slice(b"\r\n");
    out.freeze()
}

async fn send_body<T: Transport + Unpin>(
    io: &mut T,
    body: EncodedBody,
    framing: RequestFraming,
) -> Result<(), HttpError> {
    match (body, framing) {
        (EncodedBody::Full(bytes), RequestFraming::Length(_)) => send(io, bytes).await,
        (EncodedBody::Full(bytes), RequestFraming::Chunked) => {
            if bytes.is_empty() {
                return send(io, Bytes::from_static(LAST_CHUNK)).await;
            }
            send(io, chunk_prefix(bytes.len(), true)).await?;
            send(io, bytes).await?;
            send(io, Bytes::from_static(CRLF_LAST_CHUNK)).await
        }
        (EncodedBody::Stream(stream), RequestFraming::Length(expected)) => {
            let mut stream = stream.into_inner();
            let mut sent = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                sent += chunk.len() as u64;
                // Never put more on the wire than was announced.
                if sent > expected {
                    return Err(HttpError::MalformedRequest);
                }
                send(io, chunk).await?;
            }
            if sent != expected {
                return Err(HttpError::MalformedRequest);
            }
            Ok(())
        }
        (EncodedBody::Stream(stream), RequestFraming::Chunked) => {
            let mut stream = stream.into_inner();
            let mut first = true;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                // A zero-size chunk would end the body early.
                if chunk.is_empty() {
                    continue;
                }
                send(io, chunk_prefix(chunk.len(), first)).await?;
                send(io, chunk).await?;
                first = false;
            }
            let last = if first { LAST_CHUNK } else { CRLF_LAST_CHUNK };
            send(io, Bytes::from_static(last)).await
        }
    }
}

/// Where [`PreparedRequest::write_head`] writes.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

/// Counts the bytes a head needs.
struct Measure(usize);

impl Sink for Measure {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

/// Writes a head into a buffer sized by [`Measure`].
struct Fill<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Sink for Fill<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let end = self.at + bytes.len();
        self.out[self.at..end].copy_from_slice(bytes);
        self.at = end;
    }
}

/// `n` in decimal, right-aligned in `buf`.
fn decimal(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

/// `n` in lowercase hex, right-aligned in `buf`.
fn hex(mut n: u64, buf: &mut [u8; 16]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b"0123456789abcdef"[(n & 0xf) as usize];
        n >>= 4;
        if n == 0 {
            return &buf[at..];
        }
    }
}

// ---------------------------------------------------------------------------
// Framing headers (shared by both directions)
// ---------------------------------------------------------------------------

/// What `Transfer-Encoding` says about framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferCoding {
    Absent,
    /// The final coding is `chunked`.
    Chunked,
    /// Present, but the final coding is not `chunked`.
    Other,
}

/// Reads every `Transfer-Encoding` field (comma lists and repeated fields
/// are one list, RFC 9110 §5.3) and reports whether the final coding is
/// `chunked`.
fn transfer_coding(headers: &HeaderMap) -> TransferCoding {
    let mut coding = TransferCoding::Absent;
    for value in headers.get_all(header::TRANSFER_ENCODING) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let token = token.trim_ascii();
            if token.is_empty() {
                continue;
            }
            coding = if token.eq_ignore_ascii_case(b"chunked") {
                TransferCoding::Chunked
            } else {
                TransferCoding::Other
            };
        }
        // A present but empty field still marks the message as encoded.
        if coding == TransferCoding::Absent {
            coding = TransferCoding::Other;
        }
    }
    coding
}

/// The message's `Content-Length`, if any. Repeated fields and comma lists
/// are accepted only when every value is the same valid decimal number
/// (RFC 9110 §8.6); anything else is an error rather than a guess, since a
/// wrong length desynchronises the framing.
fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut length = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let n = parse_decimal(token.trim_ascii()).ok_or(())?;
            match length {
                Some(previous) if previous != n => return Err(()),
                _ => length = Some(n),
            }
        }
    }
    Ok(length)
}

/// `1*DIGIT` as a `u64`; `None` if empty, not all digits, or too large.
fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |n, &b| {
        let digit = b.checked_sub(b'0').filter(|d| *d <= 9)?;
        n.checked_mul(10)?.checked_add(u64::from(digit))
    })
}

// ---------------------------------------------------------------------------
// Response head
// ---------------------------------------------------------------------------

async fn recv<T: Transport + Unpin>(io: &mut T) -> Result<Option<Bytes>, H1Error> {
    poll_fn(|cx| io.poll_recv(cx))
        .await
        .map_err(|e| H1Error::Io(e.kind()))
}

/// The outcome of one parse attempt.
enum Parsed {
    Complete { parts: response::Parts, len: usize },
    Partial,
}

/// Parses a response head from the start of `buf`.
///
/// Header values are copied into the `HeaderMap` rather than kept as
/// slices of the received chunk: the head is small, and a slice would pin
/// a whole NIC packet buffer for as long as the caller keeps the headers.
fn parse_head(buf: &[u8]) -> Result<Parsed, H1Error> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let len = match response.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(Parsed::Partial),
        Err(httparse::Error::TooManyHeaders) => return Err(H1Error::TooManyHeaders),
        Err(_) => return Err(H1Error::MalformedHead),
    };
    if len > MAX_HEAD_SIZE {
        return Err(H1Error::HeadTooLarge);
    }
    let mut parts = Response::new(()).into_parts().0;
    parts.version = match response.version {
        Some(0) => Version::HTTP_10,
        Some(1) => Version::HTTP_11,
        _ => return Err(H1Error::MalformedHead),
    };
    parts.status = response
        .code
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or(H1Error::MalformedHead)?;
    let mut map = HeaderMap::with_capacity(response.headers.len());
    for field in response.headers.iter() {
        let name =
            HeaderName::from_bytes(field.name.as_bytes()).map_err(|_| H1Error::MalformedHead)?;
        let value = HeaderValue::from_bytes(field.value).map_err(|_| H1Error::MalformedHead)?;
        map.append(name, value);
    }
    parts.headers = map;
    Ok(Parsed::Complete { parts, len })
}

/// Finds where a head ends (the first empty line) in bytes that arrive in
/// pieces, so that a head straddling chunks is gathered without also
/// copying the body bytes that follow it in the last chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadEnd {
    /// Inside a line.
    Text,
    /// Just after a LF.
    Lf,
    /// Just after LF CR.
    LfCr,
}

impl HeadEnd {
    /// The index of the LF that ends an empty line in `bytes`, if any.
    fn find(&mut self, bytes: &[u8]) -> Option<usize> {
        for (i, &b) in bytes.iter().enumerate() {
            *self = match (*self, b) {
                (HeadEnd::Lf | HeadEnd::LfCr, b'\n') => {
                    *self = HeadEnd::Text;
                    return Some(i);
                }
                (_, b'\n') => HeadEnd::Lf,
                (HeadEnd::Lf, b'\r') => HeadEnd::LfCr,
                _ => HeadEnd::Text,
            };
        }
        None
    }
}

/// How the head being read is held.
enum HeadBuffer {
    /// Nothing buffered: the next chunk is parsed in place.
    Direct,
    /// The head straddles chunks: its bytes so far, copied, and the
    /// end-of-head search state.
    Gathering { buf: BytesMut, end: HeadEnd },
}

/// Reads one response head (interim or final), starting with `pending`
/// (bytes already received after the previous head). Returns the head and
/// the bytes after it in the chunk that completed it.
async fn read_head<T: Transport + Unpin>(
    io: &mut T,
    mut pending: Bytes,
) -> Result<(response::Parts, Bytes), H1Error> {
    let mut state = HeadBuffer::Direct;
    loop {
        let chunk = if pending.is_empty() {
            match recv(io).await? {
                Some(chunk) => chunk,
                None => return Err(H1Error::IncompleteHead),
            }
        } else {
            std::mem::take(&mut pending)
        };
        if chunk.is_empty() {
            continue;
        }
        if let HeadBuffer::Direct = state {
            match parse_head(&chunk)? {
                Parsed::Complete { parts, len } => return Ok((parts, chunk.slice(len..))),
                Parsed::Partial if chunk.len() > MAX_HEAD_SIZE => {
                    return Err(H1Error::HeadTooLarge);
                }
                Parsed::Partial => {
                    state = HeadBuffer::Gathering {
                        buf: BytesMut::with_capacity(chunk.len() * 2),
                        end: HeadEnd::Text,
                    };
                }
            }
        }
        let HeadBuffer::Gathering { buf, end } = &mut state else {
            continue;
        };
        let mut at = 0;
        while at < chunk.len() {
            let found = end.find(&chunk[at..]);
            let take = found.map_or(chunk.len() - at, |i| i + 1);
            if buf.len() + take > MAX_HEAD_SIZE {
                return Err(H1Error::HeadTooLarge);
            }
            buf.extend_from_slice(&chunk[at..at + take]);
            at += take;
            if found.is_none() {
                break;
            }
            match parse_head(buf)? {
                Parsed::Complete { parts, len } if len == buf.len() => {
                    return Ok((parts, chunk.slice(at..)));
                }
                // httparse ends a head at its first empty line, exactly as
                // `HeadEnd` does, so this cannot happen; refuse rather
                // than lose bytes if it ever did.
                Parsed::Complete { .. } => return Err(H1Error::MalformedHead),
                // Empty lines before the status line, which httparse
                // skips: keep looking.
                Parsed::Partial => {}
            }
        }
    }
}

/// Reads the final response head (skipping interim 1xx responses) and sets
/// up the body decoder for it.
async fn read_response<T: Transport + Unpin>(
    mut io: T,
    method: &Method,
) -> Result<(response::Parts, Body<T>), H1Error> {
    let mut pending = Bytes::new();
    let mut interim = 0;
    loop {
        let (parts, rest) = read_head(&mut io, pending).await?;
        pending = rest;
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(H1Error::UnexpectedUpgrade);
        }
        if parts.status.is_informational() {
            interim += 1;
            if interim > MAX_INTERIM_RESPONSES {
                return Err(H1Error::TooManyInterimResponses);
            }
            continue;
        }
        let decoder = response_decoder(method, &parts)?;
        return Ok((parts, Body::new(io, pending, decoder)));
    }
}

/// Response body framing, RFC 9112 §6.3.
fn response_decoder(method: &Method, parts: &response::Parts) -> Result<Decoder, H1Error> {
    let status = parts.status;
    if *method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(Decoder::Done);
    }
    match transfer_coding(&parts.headers) {
        TransferCoding::Absent => {}
        _ if parts.version == Version::HTTP_10 => return Err(H1Error::InvalidTransferEncoding),
        // Transfer-Encoding overrides any Content-Length.
        TransferCoding::Chunked => {
            return Ok(Decoder::Chunked(Chunked::SizeStart { line: 0 }));
        }
        TransferCoding::Other => return Ok(Decoder::UntilEof),
    }
    match content_length(&parts.headers).map_err(|_| H1Error::InvalidContentLength)? {
        Some(0) => Ok(Decoder::Done),
        Some(n) => Ok(Decoder::Length { remaining: n }),
        None => Ok(Decoder::UntilEof),
    }
}

// ---------------------------------------------------------------------------
// Response body
// ---------------------------------------------------------------------------

/// Where the body decoder stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoder {
    /// `Content-Length`: this many bytes still to come.
    Length { remaining: u64 },
    /// `Transfer-Encoding: chunked`.
    Chunked(Chunked),
    /// No framing: the body runs until the connection closes.
    UntilEof,
    /// The body ended cleanly.
    Done,
    /// The body failed; the error was reported once.
    Failed,
}

/// The incremental chunked decoder (RFC 9112 §7.1). Every state but `Data`
/// consumes framing a byte at a time, so a size line, CRLF or trailer can
/// be split anywhere across received chunks; `Data` hands out payload as
/// slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunked {
    /// Before the first hex digit of a chunk size. `line` counts the bytes
    /// of the size line so far.
    SizeStart { line: usize },
    /// In the chunk-size digits.
    Size { size: u64, line: usize },
    /// Whitespace after the size (BWS before an extension).
    SizeWs { size: u64, line: usize },
    /// In a chunk extension, which is ignored.
    Extension { size: u64, line: usize },
    /// Saw the CR ending the size line.
    SizeLf { size: u64 },
    /// In chunk data.
    Data { remaining: u64 },
    /// Expecting the CR after chunk data.
    DataCr,
    /// Expecting the LF after chunk data.
    DataLf,
    /// At the start of a trailer line (or the final empty line). `total`
    /// counts trailer bytes so far, line endings included.
    TrailerStart { total: usize },
    /// Inside a trailer field, which is ignored.
    TrailerLine { total: usize },
    /// Saw the CR ending a trailer line.
    TrailerLf { total: usize },
    /// Saw the CR of the final empty line.
    EndLf,
    /// The final CRLF has been read.
    End,
}

fn hex_digit(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'9' => Some(u64::from(b - b'0')),
        b'a'..=b'f' => Some(u64::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(u64::from(b - b'A' + 10)),
        _ => None,
    }
}

impl Chunked {
    /// Consumes framing bytes from the front of `buf`, stopping at payload
    /// (`Data`), at the end of the body, or when `buf` runs out.
    fn consume_framing(&mut self, buf: &mut Bytes) -> Result<(), H1Error> {
        let mut used = 0;
        let mut result = Ok(());
        while !matches!(self, Chunked::Data { .. } | Chunked::End) {
            let Some(&b) = buf.get(used) else {
                break;
            };
            used += 1;
            if let Err(e) = self.on_byte(b) {
                result = Err(e);
                break;
            }
        }
        buf.advance(used);
        result
    }

    fn on_byte(&mut self, b: u8) -> Result<(), H1Error> {
        use Chunked::*;
        let line = |line: usize| {
            let line = line + 1;
            if line > MAX_CHUNK_LINE {
                Err(H1Error::ChunkLineTooLong)
            } else {
                Ok(line)
            }
        };
        let trailer = |total: usize| {
            let total = total + 1;
            if total > MAX_TRAILERS_SIZE {
                Err(H1Error::TrailersTooLarge)
            } else {
                Ok(total)
            }
        };
        let push_digit = |size: u64, digit: u64| {
            size.checked_mul(16)
                .and_then(|size| size.checked_add(digit))
                .ok_or(H1Error::ChunkSizeOverflow)
        };
        *self = match *self {
            SizeStart { line: n } => match hex_digit(b) {
                Some(digit) => Size {
                    size: digit,
                    line: line(n)?,
                },
                None => return Err(H1Error::MalformedChunk),
            },
            Size { size, line: n } => {
                let n = line(n)?;
                match (hex_digit(b), b) {
                    (Some(digit), _) => Size {
                        size: push_digit(size, digit)?,
                        line: n,
                    },
                    (None, b' ' | b'\t') => SizeWs { size, line: n },
                    (None, b';') => Extension { size, line: n },
                    (None, b'\r') => SizeLf { size },
                    (None, _) => return Err(H1Error::MalformedChunk),
                }
            }
            SizeWs { size, line: n } => {
                let n = line(n)?;
                match b {
                    b' ' | b'\t' => SizeWs { size, line: n },
                    b';' => Extension { size, line: n },
                    b'\r' => SizeLf { size },
                    _ => return Err(H1Error::MalformedChunk),
                }
            }
            Extension { size, line: n } => {
                let n = line(n)?;
                match b {
                    b'\r' => SizeLf { size },
                    b'\n' => return Err(H1Error::MalformedChunk),
                    _ => Extension { size, line: n },
                }
            }
            SizeLf { size } => match b {
                b'\n' if size == 0 => TrailerStart { total: 0 },
                b'\n' => Data { remaining: size },
                _ => return Err(H1Error::MalformedChunk),
            },
            DataCr => match b {
                b'\r' => DataLf,
                _ => return Err(H1Error::MalformedChunk),
            },
            DataLf => match b {
                b'\n' => SizeStart { line: 0 },
                _ => return Err(H1Error::MalformedChunk),
            },
            TrailerStart { total } => match b {
                b'\r' => EndLf,
                b'\n' => return Err(H1Error::MalformedChunk),
                _ => TrailerLine {
                    total: trailer(total)?,
                },
            },
            TrailerLine { total } => {
                let total = trailer(total)?;
                match b {
                    b'\r' => TrailerLf { total },
                    b'\n' => return Err(H1Error::MalformedChunk),
                    _ => TrailerLine { total },
                }
            }
            TrailerLf { total } => match b {
                b'\n' => TrailerStart {
                    total: trailer(total)?,
                },
                _ => return Err(H1Error::MalformedChunk),
            },
            EndLf => match b {
                b'\n' => End,
                _ => return Err(H1Error::MalformedChunk),
            },
            // `consume_framing` never feeds these a byte.
            state @ (Data { .. } | End) => state,
        };
        Ok(())
    }
}

impl Decoder {
    /// Decodes from the front of `buf`: returns the next payload slice, or
    /// `None` once `buf` holds no more payload (it is then empty, or the
    /// body has ended and the rest is ignored).
    fn decode(&mut self, buf: &mut Bytes) -> Result<Option<Bytes>, H1Error> {
        loop {
            match self {
                Decoder::Done | Decoder::Failed => {
                    // Anything after the framed end is not ours; the
                    // connection closes with the body.
                    buf.clear();
                    return Ok(None);
                }
                Decoder::Length { remaining } => {
                    let n = (*remaining).min(buf.len() as u64) as usize;
                    if n == 0 {
                        return Ok(None);
                    }
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        *self = Decoder::Done;
                    }
                    return Ok(Some(buf.split_to(n)));
                }
                Decoder::UntilEof => {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(std::mem::take(buf)));
                }
                Decoder::Chunked(Chunked::Data { remaining }) => {
                    let n = (*remaining).min(buf.len() as u64) as usize;
                    if n == 0 {
                        return Ok(None);
                    }
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        *self = Decoder::Chunked(Chunked::DataCr);
                    }
                    return Ok(Some(buf.split_to(n)));
                }
                Decoder::Chunked(Chunked::End) => *self = Decoder::Done,
                Decoder::Chunked(state) => {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    state.consume_framing(buf)?;
                }
            }
        }
    }

    /// The input ended cleanly: fine only where the framing says the body
    /// is complete.
    fn on_eof(&mut self) -> Result<(), H1Error> {
        match self {
            Decoder::UntilEof | Decoder::Done => {
                *self = Decoder::Done;
                Ok(())
            }
            Decoder::Chunked(Chunked::End) => {
                *self = Decoder::Done;
                Ok(())
            }
            Decoder::Length { .. } | Decoder::Chunked(_) => Err(H1Error::Truncated),
            Decoder::Failed => Ok(()),
        }
    }

    fn is_finished(&self) -> bool {
        matches!(self, Decoder::Done | Decoder::Failed)
    }
}

/// A response body read from the connection it owns. Yields payload as
/// slices of the received chunks (no copy), via [`Stream`] or
/// [`poll_chunk`](Self::poll_chunk), or all at once via
/// [`collect`](Self::collect). The connection is dropped as soon as the
/// body ends or fails, and stays open as long as the body is unfinished
/// and alive. After an error the body yields nothing more.
pub struct Body<T> {
    /// `None` once the body has finished.
    io: Option<T>,
    /// Received bytes not yet decoded.
    buffered: Bytes,
    decoder: Decoder,
    /// The `Content-Length`, when there is one, to size `collect`.
    length_hint: Option<u64>,
}

impl<T: Transport + Unpin> Body<T> {
    fn new(io: T, buffered: Bytes, decoder: Decoder) -> Self {
        let length_hint = match decoder {
            Decoder::Length { remaining } => Some(remaining),
            _ => None,
        };
        let mut body = Self {
            io: Some(io),
            buffered,
            decoder,
            length_hint,
        };
        body.release_if_finished();
        body
    }

    fn release_if_finished(&mut self) {
        if self.decoder.is_finished() {
            self.io = None;
            self.buffered = Bytes::new();
        }
    }

    fn fail(&mut self, error: H1Error) -> Poll<Option<Result<Bytes, H1Error>>> {
        self.decoder = Decoder::Failed;
        self.release_if_finished();
        Poll::Ready(Some(Err(error)))
    }

    /// The next payload slice; `None` at the clean end of the body. A
    /// connection that ends before the framed end yields
    /// [`H1Error::Truncated`].
    pub fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, H1Error>>> {
        loop {
            match self.decoder.decode(&mut self.buffered) {
                Ok(Some(data)) => {
                    self.release_if_finished();
                    return Poll::Ready(Some(Ok(data)));
                }
                Ok(None) => {}
                Err(e) => return self.fail(e),
            }
            if self.decoder.is_finished() {
                self.release_if_finished();
                return Poll::Ready(None);
            }
            let Some(io) = self.io.as_mut() else {
                return self.fail(H1Error::Truncated);
            };
            match io.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(chunk))) => self.buffered = chunk,
                Poll::Ready(Ok(None)) => {
                    if let Err(e) = self.decoder.on_eof() {
                        return self.fail(e);
                    }
                    self.release_if_finished();
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(e)) => return self.fail(H1Error::Io(e.kind())),
            }
        }
    }

    /// The next payload slice; `None` at the clean end of the body.
    pub async fn chunk(&mut self) -> Option<Result<Bytes, H1Error>> {
        poll_fn(|cx| self.poll_chunk(cx)).await
    }

    /// Reads the whole body. A body that arrived as one slice is returned
    /// as is (no copy); otherwise the slices are concatenated, each byte
    /// copied once. Slices are copied as they arrive rather than gathered
    /// first, so each received packet buffer is released right away
    /// instead of all of them being pinned until the end.
    pub async fn collect(mut self) -> Result<Bytes, H1Error> {
        let Some(first) = self.chunk().await.transpose()? else {
            return Ok(Bytes::new());
        };
        let Some(second) = self.chunk().await.transpose()? else {
            return Ok(first);
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
        while let Some(chunk) = self.chunk().await.transpose()? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }
}

impl<T: Transport + Unpin> Stream for Body<T> {
    type Item = Result<Bytes, HttpError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .poll_chunk(cx)
            .map(|item| item.map(|result| result.map_err(HttpError::from)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use crate::http::codec::ByteStream;

    /// One scripted read.
    enum Read {
        Data(Bytes),
        Error(io::ErrorKind),
    }

    /// An in-memory transport: replays scripted reads, then a clean EOF,
    /// and records what was sent. Every other poll returns `Pending` (after
    /// waking) so the codec's resumption paths are exercised too.
    struct Mock {
        reads: VecDeque<Read>,
        /// Shared, so it can be inspected after the body took the mock.
        sent: std::sync::Arc<std::sync::Mutex<Vec<Bytes>>>,
        stall: bool,
        polls: usize,
    }

    impl Mock {
        fn new(chunks: impl IntoIterator<Item = Bytes>) -> Self {
            Self {
                reads: chunks.into_iter().map(Read::Data).collect(),
                sent: Default::default(),
                stall: false,
                polls: 0,
            }
        }

        fn stalling(mut self) -> Self {
            self.stall = true;
            self
        }

        fn stall_now(&mut self, cx: &mut Context<'_>) -> bool {
            self.polls += 1;
            if self.stall && self.polls % 2 == 1 {
                cx.waker().wake_by_ref();
                return true;
            }
            false
        }
    }

    impl Transport for Mock {
        fn poll_send(
            &mut self,
            cx: &mut Context<'_>,
            data: &mut Option<Bytes>,
        ) -> Poll<io::Result<()>> {
            if self.stall_now(cx) {
                return Poll::Pending;
            }
            self.sent.lock().unwrap().push(data.take().unwrap());
            Poll::Ready(Ok(()))
        }

        fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
            if self.stall_now(cx) {
                return Poll::Pending;
            }
            match self.reads.pop_front() {
                Some(Read::Data(bytes)) => Poll::Ready(Ok(Some(bytes))),
                Some(Read::Error(kind)) => Poll::Ready(Err(kind.into())),
                None => Poll::Ready(Ok(None)),
            }
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    /// Reads a response to `method` from `chunks` and drains its body.
    fn read_all(
        chunks: Vec<Bytes>,
        method: Method,
    ) -> Result<(response::Parts, Vec<Bytes>), H1Error> {
        block_on(async {
            let (parts, mut body) = read_response(Mock::new(chunks).stalling(), &method).await?;
            let mut out = Vec::new();
            while let Some(chunk) = body.chunk().await {
                out.push(chunk?);
            }
            assert!(body.io.is_none(), "connection must be dropped at the end");
            Ok((parts, out))
        })
    }

    fn concat(chunks: &[Bytes]) -> Vec<u8> {
        chunks.iter().flat_map(|c| c.iter().copied()).collect()
    }

    /// Every body slice must point into one of the received chunks.
    fn assert_zero_copy(received: &[Bytes], body: &[Bytes]) {
        for slice in body {
            assert!(!slice.is_empty(), "empty slices are never yielded");
            let start = slice.as_ptr() as usize;
            assert!(
                received.iter().any(|chunk| {
                    let base = chunk.as_ptr() as usize;
                    start >= base && start + slice.len() <= base + chunk.len()
                }),
                "body slice was copied"
            );
        }
    }

    /// `message` split at the given offsets, each piece a separate
    /// allocation.
    fn split_at(message: &[u8], cuts: &[usize]) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut from = 0;
        for &cut in cuts.iter().chain(std::iter::once(&message.len())) {
            out.push(Bytes::copy_from_slice(&message[from..cut]));
            from = cut;
        }
        out
    }

    fn single_bytes(message: &[u8]) -> Vec<Bytes> {
        message
            .iter()
            .map(|&b| Bytes::copy_from_slice(&[b]))
            .collect()
    }

    const CL_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nX-A: 1\r\nX-A: 2\r\n\r\nhello world";

    #[test]
    fn head_in_one_chunk_body_is_a_slice_of_that_chunk() {
        let chunk = Bytes::from_static(CL_RESPONSE);
        let head_len = CL_RESPONSE.len() - 11;
        let (parts, body) = read_all(vec![chunk.clone()], Method::GET).unwrap();
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(parts.version, Version::HTTP_11);
        assert_eq!(parts.headers["content-type"], "text/plain");
        let xs: Vec<_> = parts.headers.get_all("x-a").iter().collect();
        assert_eq!(xs, ["1", "2"]);
        assert_eq!(body.len(), 1);
        assert_eq!(body[0], "hello world");
        assert_eq!(body[0].as_ptr(), chunk[head_len..].as_ptr());
    }

    #[test]
    fn head_split_at_every_byte_boundary() {
        let head_len = CL_RESPONSE.len() - 11;
        for cut in 1..CL_RESPONSE.len() {
            let chunks = split_at(CL_RESPONSE, &[cut]);
            let (parts, body) = read_all(chunks.clone(), Method::GET).unwrap();
            assert_eq!(parts.status, StatusCode::OK, "cut {cut}");
            assert_eq!(parts.headers.get_all("x-a").iter().count(), 2);
            assert_eq!(concat(&body), b"hello world", "cut {cut}");
            assert_zero_copy(&chunks, &body);
            if cut <= head_len {
                // The whole body follows the head in the second chunk.
                assert_eq!(body[0].as_ptr(), chunks[1][head_len - cut..].as_ptr());
            }
        }
        let chunks = single_bytes(CL_RESPONSE);
        let (_, body) = read_all(chunks.clone(), Method::GET).unwrap();
        assert_eq!(concat(&body), b"hello world");
        assert_zero_copy(&chunks, &body);
    }

    #[test]
    fn straddling_head_copies_only_head_bytes() {
        // The second chunk ends the head and carries the body: the body must
        // stay a slice of it.
        let chunks = split_at(CL_RESPONSE, &[10]);
        let block = block_on(read_head(&mut Mock::new([]), chunks[0].clone()));
        assert_eq!(block.err(), Some(H1Error::IncompleteHead));
        let mut mock = Mock::new([chunks[1].clone()]);
        let (_, rest) = block_on(read_head(&mut mock, chunks[0].clone())).unwrap();
        assert_eq!(rest, "hello world");
        assert_eq!(rest.as_ptr(), chunks[1][chunks[1].len() - 11..].as_ptr());
    }

    const CHUNKED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\n\
1;name=value;q=\"quoted\"\r\n \r\n\
00000A \t;ext\r\n0123456789\r\n\
0\r\nTrailer-A: x\r\nTrailer-B: y\r\n\r\n";
    const CHUNKED_BODY: &[u8] = b"hello 0123456789";

    #[test]
    fn chunked_body_split_at_every_byte_boundary() {
        let (_, body) = read_all(vec![Bytes::from_static(CHUNKED_RESPONSE)], Method::GET).unwrap();
        assert_eq!(concat(&body), CHUNKED_BODY);
        assert_eq!(body.len(), 3);
        for cut in 1..CHUNKED_RESPONSE.len() {
            let chunks = split_at(CHUNKED_RESPONSE, &[cut]);
            let (_, body) = read_all(chunks.clone(), Method::GET).unwrap();
            assert_eq!(concat(&body), CHUNKED_BODY, "cut {cut}");
            assert_zero_copy(&chunks, &body);
        }
        // Two cuts, everywhere in the body framing.
        let head_len = CHUNKED_RESPONSE
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4;
        for a in head_len..CHUNKED_RESPONSE.len() {
            for b in a + 1..CHUNKED_RESPONSE.len() {
                let chunks = split_at(CHUNKED_RESPONSE, &[a, b]);
                let (_, body) = read_all(chunks.clone(), Method::GET).unwrap();
                assert_eq!(concat(&body), CHUNKED_BODY, "cuts {a} {b}");
                assert_zero_copy(&chunks, &body);
            }
        }
        let chunks = single_bytes(CHUNKED_RESPONSE);
        let (_, body) = read_all(chunks.clone(), Method::GET).unwrap();
        assert_eq!(concat(&body), CHUNKED_BODY);
        assert_zero_copy(&chunks, &body);
    }

    #[test]
    fn content_length_body_stops_at_its_length() {
        let mut message = CL_RESPONSE.to_vec();
        message.extend_from_slice(b"garbage after the body");
        let (_, body) = read_all(vec![Bytes::from(message)], Method::GET).unwrap();
        assert_eq!(concat(&body), b"hello world");
        let (_, body) = read_all(
            vec![Bytes::from_static(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )],
            Method::GET,
        )
        .unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn body_without_framing_reads_to_eof() {
        let message = b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\nall of this until close";
        for cut in 1..message.len() {
            let chunks = split_at(message, &[cut]);
            let (parts, body) = read_all(chunks.clone(), Method::GET).unwrap();
            assert_eq!(parts.version, Version::HTTP_10);
            assert_eq!(concat(&body), b"all of this until close");
            assert_zero_copy(&chunks, &body);
        }
        // A final coding other than chunked also means read-to-close.
        let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 2\r\n\r\nabcdef";
        let (_, body) = read_all(vec![Bytes::from_static(message)], Method::GET).unwrap();
        assert_eq!(concat(&body), b"abcdef");
    }

    #[test]
    fn truncation_is_an_error_not_a_clean_end() {
        // Every proper prefix of a framed response fails.
        for message in [CL_RESPONSE, CHUNKED_RESPONSE] {
            for len in 0..message.len() {
                let result = read_all(vec![Bytes::copy_from_slice(&message[..len])], Method::GET);
                let error = result.expect_err(&format!("prefix {len} must fail"));
                assert!(
                    matches!(error, H1Error::Truncated | H1Error::IncompleteHead),
                    "prefix {len}: {error:?}"
                );
            }
        }
        // A reset is reported as such.
        let mut mock = Mock::new([Bytes::from_static(&CL_RESPONSE[..CL_RESPONSE.len() - 3])]);
        mock.reads
            .push_back(Read::Error(io::ErrorKind::ConnectionReset));
        let result = block_on(async {
            let (_, mut body) = read_response(mock, &Method::GET).await?;
            assert_eq!(body.chunk().await.unwrap().unwrap(), "hello wo");
            let error = body.chunk().await.unwrap();
            // Fused after the error, connection released.
            assert!(body.chunk().await.is_none());
            assert!(body.io.is_none());
            error
        });
        assert_eq!(result, Err(H1Error::Io(io::ErrorKind::ConnectionReset)));
    }

    #[test]
    fn head_204_and_304_have_no_body() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        // Nothing follows: reading the body must not wait for 100 bytes.
        let (_, body) = read_all(vec![Bytes::from_static(head)], Method::HEAD).unwrap();
        assert!(body.is_empty());
        for status in ["204 No Content", "304 Not Modified"] {
            let message = format!(
                "HTTP/1.1 {status}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            let (parts, body) = read_all(vec![Bytes::from(message)], Method::GET).unwrap();
            assert!(parts.status == 204 || parts.status == 304);
            assert!(body.is_empty());
        }
    }

    #[test]
    fn interim_responses_are_skipped() {
        let message = b"HTTP/1.1 100 Continue\r\n\r\n\
HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n\
HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
        for cut in 1..message.len() {
            let chunks = split_at(message, &[cut]);
            let (parts, body) = read_all(chunks.clone(), Method::POST).unwrap();
            assert_eq!(parts.status, StatusCode::CREATED, "cut {cut}");
            assert!(parts.headers.get("link").is_none());
            assert_eq!(concat(&body), b"ok");
            assert_zero_copy(&chunks, &body);
        }
        let upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n";
        assert_eq!(
            read_all(vec![Bytes::from_static(upgrade)], Method::GET).unwrap_err(),
            H1Error::UnexpectedUpgrade
        );
        let many = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INTERIM_RESPONSES + 1);
        assert_eq!(
            read_all(vec![Bytes::from(many)], Method::GET).unwrap_err(),
            H1Error::TooManyInterimResponses
        );
    }

    #[test]
    fn leading_blank_lines_before_the_status_line() {
        let message = b"\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
        for cut in 1..message.len() {
            let (_, body) = read_all(split_at(message, &[cut]), Method::GET).unwrap();
            assert_eq!(concat(&body), b"x", "cut {cut}");
        }
    }

    #[test]
    fn oversized_and_malformed_heads_are_rejected() {
        // One huge header, in one chunk and across many.
        let mut big = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        big.resize(MAX_HEAD_SIZE + 10, b'a');
        assert_eq!(
            read_all(vec![Bytes::from(big.clone())], Method::GET).unwrap_err(),
            H1Error::HeadTooLarge
        );
        let pieces: Vec<Bytes> = big.chunks(1000).map(Bytes::copy_from_slice).collect();
        assert_eq!(
            read_all(pieces, Method::GET).unwrap_err(),
            H1Error::HeadTooLarge
        );
        // Complete but over the limit.
        big.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            read_all(vec![Bytes::from(big)], Method::GET).unwrap_err(),
            H1Error::HeadTooLarge
        );
        // Endless blank lines count towards the limit too.
        let blanks: Vec<Bytes> = (0..MAX_HEAD_SIZE)
            .map(|_| Bytes::from_static(b"\r\n"))
            .collect();
        assert_eq!(
            read_all(blanks, Method::GET).unwrap_err(),
            H1Error::HeadTooLarge
        );

        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..=MAX_HEADERS {
            many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(
            read_all(vec![Bytes::from(many.clone())], Method::GET).unwrap_err(),
            H1Error::TooManyHeaders
        );
        assert_eq!(
            read_all(split_at(&many, &[20]), Method::GET).unwrap_err(),
            H1Error::TooManyHeaders
        );

        for bad in [
            &b"HTTP/1.1 2000 OK\r\n\r\n"[..],
            b"HTTP/2.0 200 OK\r\n\r\n",
            b"FTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nFolded: a\r\n b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n",
            b"HTTP/1.1 099 Low\r\n\r\n",
            b"\x00\x01\x02\r\n\r\n",
        ] {
            let error = read_all(vec![Bytes::copy_from_slice(bad)], Method::GET).unwrap_err();
            assert_eq!(
                error,
                H1Error::MalformedHead,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
            let error = read_all(single_bytes(bad), Method::GET).unwrap_err();
            assert_eq!(
                error,
                H1Error::MalformedHead,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            read_all(vec![], Method::GET).unwrap_err(),
            H1Error::IncompleteHead
        );
    }

    #[test]
    fn content_length_must_be_valid_and_consistent() {
        let ok = |value: &str| {
            let message = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nabc");
            read_all(vec![Bytes::from(message)], Method::GET).map(|(_, body)| concat(&body))
        };
        assert_eq!(ok("3").unwrap(), b"abc");
        assert_eq!(ok("3, 3").unwrap(), b"abc");
        assert_eq!(ok("003").unwrap(), b"abc");
        for bad in [
            "3, 4",
            "-1",
            "+3",
            "abc",
            "",
            "3 3",
            "0x3",
            "99999999999999999999999",
        ] {
            assert_eq!(
                ok(bad).unwrap_err(),
                H1Error::InvalidContentLength,
                "{bad:?}"
            );
        }
        let twice = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 2\r\n\r\nabc";
        assert_eq!(
            read_all(vec![Bytes::from_static(twice)], Method::GET).unwrap_err(),
            H1Error::InvalidContentLength
        );
        // Transfer-Encoding wins over Content-Length.
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n";
        let (_, body) = read_all(vec![Bytes::from_static(both)], Method::GET).unwrap();
        assert_eq!(concat(&body), b"ab");
        // ...but not on HTTP/1.0.
        let old = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(
            read_all(vec![Bytes::from_static(old)], Method::GET).unwrap_err(),
            H1Error::InvalidTransferEncoding
        );
    }

    #[test]
    fn malformed_chunked_framing_is_rejected() {
        let check = |framing: &[u8], expected: H1Error| {
            let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            message.extend_from_slice(framing);
            let one = read_all(vec![Bytes::from(message.clone())], Method::GET);
            assert_eq!(
                one.unwrap_err(),
                expected,
                "{:?}",
                String::from_utf8_lossy(framing)
            );
            let split = read_all(single_bytes(&message), Method::GET);
            assert_eq!(split.unwrap_err(), expected);
        };
        // 17 hex digits overflow; 16 do not (but then the body is truncated).
        check(b"10000000000000000\r\n", H1Error::ChunkSizeOverflow);
        check(b"ffffffffffffffff\r\nabc", H1Error::Truncated);
        check(b"zz\r\n", H1Error::MalformedChunk);
        check(b"\r\n", H1Error::MalformedChunk);
        check(b";ext\r\n", H1Error::MalformedChunk);
        check(b"-1\r\n", H1Error::MalformedChunk);
        check(b"3\nabc\r\n0\r\n\r\n", H1Error::MalformedChunk);
        check(b"3\r\nabcX\r\n0\r\n\r\n", H1Error::MalformedChunk);
        check(b"3\r\nabc\rX0\r\n\r\n", H1Error::MalformedChunk);
        check(b"3 x\r\nabc\r\n", H1Error::MalformedChunk);
        check(b"0\r\nTrailer: x\n\r\n", H1Error::MalformedChunk);
        check(b"0\r\n\rX", H1Error::MalformedChunk);
        let mut long_ext = b"1;".to_vec();
        long_ext.resize(MAX_CHUNK_LINE + 1, b'e');
        check(&long_ext, H1Error::ChunkLineTooLong);
        let mut leading_zeros = vec![b'0'; MAX_CHUNK_LINE + 1];
        leading_zeros.push(b'1');
        check(&leading_zeros, H1Error::ChunkLineTooLong);
        let mut trailers = b"0\r\n".to_vec();
        while trailers.len() < MAX_TRAILERS_SIZE + 100 {
            trailers.extend_from_slice(b"T: vvvvvvvvvvvvvvvv\r\n");
        }
        check(&trailers, H1Error::TrailersTooLarge);
    }

    #[test]
    fn collect_returns_a_single_chunk_as_is_and_concatenates_otherwise() {
        let chunk = Bytes::from_static(CL_RESPONSE);
        let collected = block_on(async {
            let (_, body) = read_response(Mock::new([chunk.clone()]), &Method::GET).await?;
            body.collect().await
        })
        .unwrap();
        assert_eq!(collected, "hello world");
        assert_eq!(collected.as_ptr(), chunk[CL_RESPONSE.len() - 11..].as_ptr());

        for chunks in [single_bytes(CHUNKED_RESPONSE), single_bytes(CL_RESPONSE)] {
            let collected = block_on(async {
                let (_, body) = read_response(Mock::new(chunks).stalling(), &Method::GET).await?;
                body.collect().await
            })
            .unwrap();
            assert!(collected == CHUNKED_BODY || collected == "hello world");
        }
        let truncated = block_on(async {
            let chunks = split_at(&CL_RESPONSE[..CL_RESPONSE.len() - 1], &[70]);
            let (_, body) = read_response(Mock::new(chunks), &Method::GET).await?;
            body.collect().await
        });
        assert_eq!(truncated, Err(H1Error::Truncated));
    }

    #[test]
    fn body_is_a_stream_of_http_results() {
        let chunks = split_at(CHUNKED_RESPONSE, &[60, 70]);
        let items: Vec<_> = block_on(async {
            let (_, body) = read_response(Mock::new(chunks), &Method::GET)
                .await
                .unwrap();
            StreamExt::collect::<Vec<_>>(body).await
        });
        let data: Vec<Bytes> = items.into_iter().map(Result::unwrap).collect();
        assert_eq!(concat(&data), CHUNKED_BODY);
        let items: Vec<_> = block_on(async {
            let chunks = vec![Bytes::from_static(&CL_RESPONSE[..CL_RESPONSE.len() - 1])];
            let (_, body) = read_response(Mock::new(chunks), &Method::GET)
                .await
                .unwrap();
            StreamExt::collect::<Vec<_>>(body).await
        });
        assert_eq!(items.last(), Some(&Err(HttpError::Protocol)));
    }

    fn parts(method: Method, uri: &str, headers: &[(&str, &str)]) -> request::Parts {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "example.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    /// Sends the request into a mock and returns what went out.
    fn sent(parts: request::Parts, body: EncodedBody) -> Result<Vec<Bytes>, HttpError> {
        let request = PreparedRequest::new(parts, body)?;
        let head = request.encode_head(None);
        let mut mock = Mock::new([]).stalling();
        block_on(async {
            send(&mut mock, head).await?;
            send_body(&mut mock, request.body, request.framing).await
        })?;
        Ok(mock.sent.lock().unwrap().clone())
    }

    fn text(sent: &[Bytes]) -> String {
        String::from_utf8(concat(sent)).unwrap()
    }

    #[test]
    fn full_body_request_serialisation() {
        let body = Bytes::from_static(b"hello");
        let out = sent(
            parts(Method::POST, "/p?q=1", &[("content-type", "text/plain")]),
            EncodedBody::Full(body.clone()),
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0],
            "POST /p?q=1 HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\
content-length: 5\r\nconnection: close\r\n\r\n"
        );
        // The body goes out untouched.
        assert_eq!(out[1].as_ptr(), body.as_ptr());

        // No body on GET: no Content-Length; on POST: Content-Length: 0.
        let out = sent(
            parts(Method::GET, "/", &[]),
            EncodedBody::Full(Bytes::new()),
        )
        .unwrap();
        assert_eq!(
            text(&out),
            "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n"
        );
        let out = sent(
            parts(Method::POST, "/", &[]),
            EncodedBody::Full(Bytes::new()),
        )
        .unwrap();
        assert!(text(&out).contains("content-length: 0\r\n"));

        // The caller's Connection and Content-Length are respected.
        let out = sent(
            parts(
                Method::PUT,
                "/x",
                &[("connection", "keep-alive"), ("content-length", "5")],
            ),
            EncodedBody::Full(body.clone()),
        )
        .unwrap();
        let head = text(&out[..1]);
        assert!(!head.contains("close"));
        assert_eq!(head.matches("content-length").count(), 1);
        assert_eq!(
            sent(
                parts(Method::PUT, "/x", &[("content-length", "4")]),
                EncodedBody::Full(body.clone()),
            )
            .unwrap_err(),
            HttpError::MalformedRequest
        );
        // A caller's chunked Transfer-Encoding chunks the full body.
        let out = sent(
            parts(Method::POST, "/", &[("transfer-encoding", "chunked")]),
            EncodedBody::Full(body.clone()),
        )
        .unwrap();
        assert!(text(&out).ends_with("\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
        assert_eq!(out[2].as_ptr(), body.as_ptr());
        for bad in [
            &[("transfer-encoding", "gzip")][..],
            &[("transfer-encoding", "chunked"), ("content-length", "5")],
            &[("content-length", "x")],
        ] {
            assert_eq!(
                sent(
                    parts(Method::POST, "/", bad),
                    EncodedBody::Full(body.clone())
                )
                .unwrap_err(),
                HttpError::MalformedRequest
            );
        }
        // A query without a path still gets an origin-form path.
        let out = sent(
            parts(Method::GET, "http://h?q", &[]),
            EncodedBody::Full(Bytes::new()),
        );
        assert!(text(&out.unwrap()).starts_with("GET /?q HTTP/1.1\r\n"));
    }

    fn stream_of(chunks: &[Bytes]) -> EncodedBody {
        EncodedBody::Stream(ByteStream::from(futures::stream::iter(chunks.to_vec())))
    }

    #[test]
    fn streamed_body_request_serialisation() {
        let a = Bytes::from_static(b"hello");
        let b = Bytes::from(vec![b'x'; 300]);
        let out = sent(
            parts(Method::POST, "/up", &[]),
            stream_of(&[a.clone(), Bytes::new(), b.clone()]),
        )
        .unwrap();
        assert_eq!(
            out[0],
            "POST /up HTTP/1.1\r\nhost: example.com\r\ntransfer-encoding: chunked\r\n\
connection: close\r\n\r\n"
        );
        assert_eq!(out[1], "5\r\n");
        assert_eq!(out[2].as_ptr(), a.as_ptr());
        assert_eq!(out[3], "\r\n12c\r\n");
        assert_eq!(out[4].as_ptr(), b.as_ptr());
        assert_eq!(out[5], "\r\n0\r\n\r\n");
        assert_eq!(out.len(), 6);

        let out = sent(parts(Method::POST, "/", &[]), stream_of(&[])).unwrap();
        assert_eq!(out[1], "0\r\n\r\n");

        // A caller's Content-Length sends the stream raw, and must match.
        let length = |n: &str| {
            sent(
                parts(Method::POST, "/", &[("content-length", n)]),
                stream_of(&[a.clone(), a.clone()]),
            )
        };
        let out = length("10").unwrap();
        assert_eq!(&out[1..], [a.clone(), a.clone()]);
        assert_eq!(length("9").unwrap_err(), HttpError::MalformedRequest);
        assert_eq!(length("11").unwrap_err(), HttpError::MalformedRequest);

        // A producer error aborts the request with that error.
        let failing = EncodedBody::Stream(ByteStream::new(futures::stream::iter([
            Ok(a.clone()),
            Err(HttpError::BodyProducer(io::ErrorKind::BrokenPipe)),
        ])));
        assert_eq!(
            sent(parts(Method::POST, "/", &[]), failing).unwrap_err(),
            HttpError::BodyProducer(io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn chunk_prefix_formats_hex_sizes() {
        assert_eq!(chunk_prefix(1, true), "1\r\n");
        assert_eq!(chunk_prefix(255, false), "\r\nff\r\n");
        assert_eq!(chunk_prefix(0x10000, false), "\r\n10000\r\n");
        assert_eq!(decimal(0, &mut [0; 20]), b"0");
        assert_eq!(decimal(u64::MAX, &mut [0; 20]), b"18446744073709551615");
        assert_eq!(hex(u64::MAX, &mut [0; 16]), b"ffffffffffffffff");
    }

    #[test]
    fn full_exchange_sends_then_reads() {
        let request = PreparedRequest::new(
            parts(Method::HEAD, "/h", &[]),
            EncodedBody::Full(Bytes::new()),
        )
        .unwrap();
        let head = request.encode_head(None);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n";
        let mock = Mock::new([Bytes::from_static(response)]).stalling();
        let sent = mock.sent.clone();
        let response = block_on(async {
            let response = request.exchange(mock, head).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body();
            // A HEAD response has no body, so the connection is already gone.
            assert!(body.io.is_none());
            body.collect().await
        });
        assert_eq!(response, Ok(Bytes::new()));
        assert_eq!(
            text(&sent.lock().unwrap()),
            "HEAD /h HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n"
        );
    }
}

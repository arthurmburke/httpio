//! Tests for the HTTP/2 codec: frame-level ones against a scripted peer,
//! and end-to-end ones against hyper's HTTP/2 server over an in-memory
//! pipe.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Version};

use super::frame::{FrameHead, flag, kind, setting};
use super::*;
use crate::http::codec::ByteStream;

// ---------------------------------------------------------------------------
// A scripted peer
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PeerState {
    reads: VecDeque<Bytes>,
    eof: bool,
    error: Option<io::ErrorKind>,
    sent: Vec<Bytes>,
    waker: Option<Waker>,
    /// Refuse writes (as a transport out of send credit does).
    block_sends: bool,
    /// Return `Pending` (after waking) on every other poll.
    stall: bool,
    polls: usize,
}

/// The test's handle on the transport the codec runs over.
#[derive(Clone, Default)]
struct Peer(Arc<Mutex<PeerState>>);

struct Mock(Peer);

impl Peer {
    fn state(&self) -> std::sync::MutexGuard<'_, PeerState> {
        self.0.lock().unwrap()
    }

    fn wake(&self) {
        if let Some(waker) = self.state().waker.take() {
            waker.wake();
        }
    }

    /// Queues bytes for the client to receive, as one chunk.
    fn push(&self, bytes: impl Into<Vec<u8>>) -> Bytes {
        let bytes = Bytes::from(bytes.into());
        self.state().reads.push_back(bytes.clone());
        self.wake();
        bytes
    }

    /// Queues `bytes` cut into chunks of `size`.
    fn push_cut(&self, bytes: &[u8], size: usize) {
        for piece in bytes.chunks(size) {
            self.push(piece);
        }
    }

    fn eof(&self) {
        self.state().eof = true;
        self.wake();
    }

    fn fail(&self, kind: io::ErrorKind) {
        self.state().error = Some(kind);
        self.wake();
    }

    fn block_sends(&self, block: bool) {
        self.state().block_sends = block;
        self.wake();
    }

    /// Everything the client sent since the last call, as its buffers.
    fn take_sent(&self) -> Vec<Bytes> {
        std::mem::take(&mut self.state().sent)
    }

    /// Everything the client sent since the last call, parsed as frames
    /// (after the connection preface, if it is there).
    fn take_frames(&self) -> Vec<(FrameHead, Vec<u8>)> {
        let bytes: Vec<u8> = self.take_sent().iter().flat_map(|b| b.to_vec()).collect();
        let mut rest = bytes.strip_prefix(PREFACE).unwrap_or(&bytes);
        let mut frames = Vec::new();
        while !rest.is_empty() {
            let head = FrameHead::parse(rest[..9].try_into().unwrap());
            let end = 9 + head.len as usize;
            frames.push((head, rest[9..end].to_vec()));
            rest = &rest[end..];
        }
        frames
    }
}

impl Transport for Mock {
    type Recv = Bytes;

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.state();
        state.polls += 1;
        if state.block_sends || (state.stall && state.polls % 2 == 1) {
            if state.stall && !state.block_sends {
                cx.waker().wake_by_ref();
            } else {
                state.waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        state.sent.push(data.take().unwrap());
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        let mut state = self.0.state();
        state.polls += 1;
        if state.stall && state.polls % 2 == 1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(bytes) = state.reads.pop_front() {
            return Poll::Ready(Ok(Some(bytes)));
        }
        if let Some(kind) = state.error {
            return Poll::Ready(Err(kind.into()));
        }
        if state.eof {
            return Poll::Ready(Ok(None));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// A connection over a scripted peer whose SETTINGS have been queued. The
/// driver is returned unpolled: these tests run one task.
fn connect() -> (SendRequest<Mock>, Connection<Mock>, Peer) {
    let peer = Peer::default();
    let (send, conn) = handshake(Mock(peer.clone()));
    peer.push(settings(&[]));
    (send, conn, peer)
}

fn block_on<F: Future>(future: F) -> F::Output {
    futures::executor::block_on(future)
}

/// Polls `future` once, expecting it not to be done.
fn pending<F: Future + Unpin>(future: &mut F) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(future).poll(&mut cx).is_pending());
}

// ---- building what a server sends ----------------------------------------

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let head = FrameHead {
        len: payload.len() as u32,
        kind,
        flags,
        stream,
    };
    let mut out = head.encode().to_vec();
    out.extend_from_slice(payload);
    out
}

fn settings(entries: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (id, value) in entries {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    frame(kind::SETTINGS, 0, 0, &payload)
}

/// A header block of literals, none of them indexed.
fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        assert!(name.len() < 127 && value.len() < 127);
        out.push(0x00);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn headers(stream: u32, fields: &[(&str, &str)], end_stream: bool) -> Vec<u8> {
    let flags = flag::END_HEADERS | if end_stream { flag::END_STREAM } else { 0 };
    frame(kind::HEADERS, flags, stream, &block(fields))
}

fn data(stream: u32, payload: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { flag::END_STREAM } else { 0 };
    frame(kind::DATA, flags, stream, payload)
}

fn window_update(stream: u32, increment: u32) -> Vec<u8> {
    frame(kind::WINDOW_UPDATE, 0, stream, &increment.to_be_bytes())
}

fn rst_stream(stream: u32, reason: Reason) -> Vec<u8> {
    frame(kind::RST_STREAM, 0, stream, &reason.0.to_be_bytes())
}

fn goaway(last: u32, reason: Reason) -> Vec<u8> {
    let mut payload = last.to_be_bytes().to_vec();
    payload.extend_from_slice(&reason.0.to_be_bytes());
    frame(kind::GOAWAY, 0, 0, &payload)
}

const OK: &[(&str, &str)] = &[(":status", "200")];

// ---- building requests -----------------------------------------------------

fn request(method: Method, uri: &str) -> request::Parts {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn get(path: &str) -> request::Parts {
    request(Method::GET, &format!("https://example.com{path}"))
}

fn post(path: &str) -> request::Parts {
    request(Method::POST, &format!("https://example.com{path}"))
}

fn empty() -> EncodedBody {
    EncodedBody::Full(Bytes::new())
}

fn full(bytes: impl Into<Bytes>) -> EncodedBody {
    EncodedBody::Full(bytes.into())
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
        .collect()
}

/// Decodes a request header block the client sent.
fn decode_block(payload: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let limits = hpack::Limits {
        fields: 100,
        size: 1 << 20,
    };
    hpack::Decoder::new()
        .decode(payload, limits, |name, value| {
            let name = match name {
                hpack::Name::Status => ":status".to_owned(),
                hpack::Name::Pseudo(name) => String::from_utf8(name.to_vec()).unwrap(),
                hpack::Name::Field(name) => name.as_str().to_owned(),
            };
            out.push((name, value.to_str().unwrap().to_owned()));
        })
        .unwrap();
    out
}

async fn drain<T: Transport>(body: &mut Body<T>) -> Result<Vec<Bytes>, H2Error> {
    let mut out = Vec::new();
    while let Some(chunk) = body.chunk().await {
        out.push(chunk?);
    }
    Ok(out)
}

fn concat(chunks: &[Bytes]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}

fn h2_error<T: Transport>(result: Result<Response<Body<T>>, SendError>) -> H2Error {
    match result {
        Err(SendError::H2(error)) => error,
        Err(SendError::Request(error)) => panic!("request error {error:?}"),
        Ok(_) => panic!("expected an error"),
    }
}

// ---------------------------------------------------------------------------
// Requests on the wire
// ---------------------------------------------------------------------------

#[test]
fn first_get_leaves_as_one_buffer_with_the_preface() {
    let (send, _conn, peer) = connect();
    let response = send.send(get("/a?b=c"), empty()).unwrap();
    let chunk = peer.push([headers(1, OK, false), data(1, b"hello", true)].concat());
    let response = block_on(response).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);

    let sent = peer.take_sent();
    // The preface, SETTINGS and HEADERS in one buffer; the acknowledgement
    // of the server's SETTINGS follows once those have been read.
    assert_eq!(sent.len(), 2);
    assert!(sent[0].starts_with(PREFACE));
    assert_eq!(sent[1].len(), 9);
    peer.state().sent = sent;
    let frames = peer.take_frames();
    let kinds: Vec<u8> = frames.iter().map(|(head, _)| head.kind).collect();
    assert_eq!(
        kinds,
        [
            kind::SETTINGS,
            kind::WINDOW_UPDATE,
            kind::HEADERS,
            kind::SETTINGS
        ]
    );
    assert_eq!(frames[0].1.len(), 18);
    assert_eq!(
        frames[1].1,
        (CONNECTION_WINDOW - DEFAULT_WINDOW).to_be_bytes()
    );
    let (head, payload) = &frames[2];
    assert_eq!(head.stream, 1);
    assert_eq!(head.flags, flag::END_HEADERS | flag::END_STREAM);
    assert_eq!(
        decode_block(payload),
        [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/a?b=c"),
            (":authority", "example.com"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
    );
    // The acknowledgement of the server's SETTINGS.
    assert_eq!(frames[3].0.flags, flag::ACK);

    // The body is a slice of the chunk it arrived in.
    let mut body = response.into_body();
    let chunks = block_on(drain(&mut body)).unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0], "hello");
    assert_eq!(chunks[0].as_ptr(), chunk[chunk.len() - 5..].as_ptr());
}

#[test]
fn small_body_shares_the_head_buffer_and_large_one_is_sliced() {
    let (send, _conn, peer) = connect();
    let mut parts = post("/small");
    parts
        .headers
        .insert("content-type", "text/plain".parse().unwrap());
    let response = send.send(parts, full("tiny body")).unwrap();
    peer.push(headers(1, OK, true));
    block_on(response).unwrap();
    let sent = peer.take_sent();
    assert_eq!(sent.len(), 2);
    assert!(
        sent[0].ends_with(b"tiny body"),
        "head and body in one buffer"
    );
    peer.state().sent = sent;
    let frames = peer.take_frames();
    let (head, payload) = &frames[2];
    assert_eq!((head.kind, head.flags), (kind::HEADERS, flag::END_HEADERS));
    assert_eq!(
        decode_block(payload)[4..],
        [("content-type", "text/plain"), ("content-length", "9")]
            .map(|(n, v)| (n.to_owned(), v.to_owned()))
    );
    let (head, payload) = &frames[3];
    assert_eq!((head.kind, head.flags), (kind::DATA, flag::END_STREAM));
    assert_eq!(payload, b"tiny body");

    // A large body: frames of at most the peer's size, their payloads
    // slices of the caller's bytes, up to what is left of the 65,535-byte
    // connection window after the first request's nine bytes.
    let body = Bytes::from(pattern(100_000, 3));
    let response = send.send(post("/large"), full(body.clone())).unwrap();
    let mut response = Box::pin(response);
    pending(&mut response);
    let sent = peer.take_sent();
    let mut offset = 0;
    for payload in sent.iter().filter(|b| b.len() >= COPY_BODY_BELOW) {
        assert_eq!(payload.as_ptr(), body[offset..].as_ptr(), "body was copied");
        offset += payload.len();
    }
    peer.state().sent = sent;
    let frames = peer.take_frames();
    assert_eq!(frames[0].0.kind, kind::HEADERS);
    let sizes: Vec<u32> = frames[1..].iter().map(|(head, _)| head.len).collect();
    assert_eq!(sizes, [16_384, 16_384, 16_384, 16_374]);
    assert!(frames.iter().all(|(head, _)| !head.has(flag::END_STREAM)));

    // Stream window only: still blocked on the connection's.
    peer.push(window_update(3, 1_000_000));
    pending(&mut response);
    assert!(peer.take_frames().is_empty());
    peer.push(window_update(0, 20_000));
    pending(&mut response);
    let frames = peer.take_frames();
    let sizes: Vec<u32> = frames.iter().map(|(head, _)| head.len).collect();
    assert_eq!(sizes, [16_384, 3_616]);
    peer.push(window_update(0, 1_000_000));
    peer.push(headers(3, OK, true));
    block_on(response).unwrap();
    let frames = peer.take_frames();
    let total: u32 = frames.iter().map(|(head, _)| head.len).sum();
    assert_eq!(total, 100_000 - 65_526 - 20_000);
    let (last, _) = frames.last().unwrap();
    assert_eq!((last.kind, last.flags), (kind::DATA, flag::END_STREAM));
    let sent: Vec<u8> = frames.iter().flat_map(|(_, p)| p.clone()).collect();
    assert_eq!(sent, body[85_526..]);
}

#[test]
fn streamed_body_is_framed_chunk_by_chunk() {
    let (send, _conn, peer) = connect();
    let chunks = vec![
        Ok(Bytes::from_static(b"first ")),
        Ok(Bytes::new()),
        Ok(Bytes::from(pattern(5_000, 1))),
    ];
    let body = EncodedBody::Stream(ByteStream::new(futures::stream::iter(chunks)));
    let response = send.send(post("/stream"), body).unwrap();
    peer.push(headers(1, OK, true));
    block_on(response).unwrap();
    let frames = peer.take_frames();
    let data: Vec<_> = frames
        .iter()
        .filter(|(head, _)| head.kind == kind::DATA)
        .collect();
    assert_eq!(data.len(), 3);
    assert_eq!(data[0].1, b"first ");
    assert_eq!(data[1].1, pattern(5_000, 1));
    assert_eq!((data[2].0.len, data[2].0.flags), (0, flag::END_STREAM));
    // No content-length for a body of unknown size.
    let (_, block) = frames
        .iter()
        .find(|(h, _)| h.kind == kind::HEADERS)
        .unwrap();
    assert!(
        decode_block(block)
            .iter()
            .all(|(n, _)| n != "content-length")
    );
}

#[test]
fn failing_body_producer_resets_the_stream_and_reports_its_error() {
    let (send, _conn, peer) = connect();
    let chunks = vec![
        Ok(Bytes::from_static(b"some")),
        Err(HttpError::BodyProducer(io::ErrorKind::Other)),
    ];
    let body = EncodedBody::Stream(ByteStream::new(futures::stream::iter(chunks)));
    let response = send.send(post("/stream"), body).unwrap();
    assert_eq!(
        block_on(response).err(),
        Some(SendError::Request(HttpError::BodyProducer(
            io::ErrorKind::Other
        )))
    );
    let frames = peer.take_frames();
    let (last, payload) = frames.last().unwrap();
    assert_eq!(last.kind, kind::RST_STREAM);
    assert_eq!(payload, &Reason::CANCEL.0.to_be_bytes());

    // A body that breaks its announced length never exceeds it.
    let mut parts = post("/short");
    parts.headers.insert("content-length", "3".parse().unwrap());
    let chunks = vec![Ok(Bytes::from_static(b"four"))];
    let body = EncodedBody::Stream(ByteStream::new(futures::stream::iter(chunks)));
    let response = send.send(parts, body).unwrap();
    assert_eq!(
        block_on(response).err(),
        Some(SendError::Request(HttpError::MalformedRequest))
    );
    assert!(peer.take_frames().iter().all(|(h, _)| h.kind != kind::DATA));
    // And a mismatch known up front is refused before anything is sent.
    let mut parts = post("/short");
    parts.headers.insert("content-length", "3".parse().unwrap());
    assert_eq!(
        send.send(parts, full("four")).err(),
        Some(HttpError::MalformedRequest)
    );
    let parts = request(Method::GET, "/no-authority");
    assert_eq!(
        send.send(parts, empty()).err(),
        Some(HttpError::MissingHost)
    );
}

#[test]
fn oversized_header_block_is_continued() {
    let (send, _conn, peer) = connect();
    let mut parts = get("/");
    for i in 0..5 {
        let value = "v".repeat(8_000);
        parts.headers.insert(
            format!("x-large-{i}").parse::<http::HeaderName>().unwrap(),
            value.parse().unwrap(),
        );
    }
    let response = send.send(parts, empty()).unwrap();
    peer.push(headers(1, OK, true));
    block_on(response).unwrap();
    let frames = peer.take_frames();
    let block: Vec<_> = frames
        .iter()
        .filter(|(h, _)| matches!(h.kind, kind::HEADERS | kind::CONTINUATION))
        .collect();
    assert_eq!(block.len(), 3);
    assert_eq!(
        (block[0].0.kind, block[0].0.flags),
        (kind::HEADERS, flag::END_STREAM)
    );
    assert_eq!((block[1].0.kind, block[1].0.flags), (kind::CONTINUATION, 0));
    assert_eq!(
        (block[2].0.kind, block[2].0.flags),
        (kind::CONTINUATION, flag::END_HEADERS)
    );
    assert!(block.iter().all(|(h, _)| h.len as usize <= MAX_FRAME_SIZE));
    let whole: Vec<u8> = block.iter().flat_map(|(_, p)| p.clone()).collect();
    assert_eq!(decode_block(&whole).len(), 9);
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// A response exercising CONTINUATION, padding, priority, an interim
/// response, an unknown frame type and trailers.
fn elaborate_response() -> (Vec<u8>, Vec<u8>) {
    let fields = block(&[
        (":status", "200"),
        ("content-type", "text/plain"),
        ("x-a", "1"),
        ("x-a", "2"),
    ]);
    let (first, second) = fields.split_at(7);
    let mut padded_head = vec![3];
    padded_head.extend_from_slice(&[0, 0, 0, 0, 16]);
    padded_head.extend_from_slice(first);
    padded_head.extend_from_slice(&[0; 3]);
    let mut padded_data = vec![4];
    padded_data.extend_from_slice(b"hello ");
    padded_data.extend_from_slice(&[0; 4]);
    let body = pattern(3_000, 9);
    let wire = [
        headers(1, &[(":status", "103"), ("link", "</a>")], false),
        frame(
            kind::HEADERS,
            flag::PADDED | flag::PRIORITY,
            1,
            &padded_head,
        ),
        frame(kind::CONTINUATION, 0, 1, &second[..5]),
        frame(kind::CONTINUATION, flag::END_HEADERS, 1, &second[5..]),
        frame(0x42, 0xff, 1, b"unknown frame type"),
        frame(kind::DATA, flag::PADDED, 1, &padded_data),
        frame(kind::PING, 0, 0, b"12345678"),
        data(1, &body, false),
        frame(kind::PRIORITY, 0, 1, &[0, 0, 0, 0, 1]),
        data(1, b"", false),
        headers(1, &[("x-trailer", "t")], true),
    ]
    .concat();
    let mut expected = b"hello ".to_vec();
    expected.extend_from_slice(&body);
    (wire, expected)
}

#[test]
fn response_cut_at_every_byte_boundary() {
    let (wire, expected) = elaborate_response();
    let check = |cut: Option<usize>, piece: usize, stall: bool| {
        let (send, _conn, peer) = connect();
        peer.state().stall = stall;
        let response = send.send(get("/"), empty()).unwrap();
        match cut {
            Some(cut) => {
                peer.push(&wire[..cut]);
                peer.push(&wire[cut..]);
            }
            None => peer.push_cut(&wire, piece),
        }
        let response = block_on(response).unwrap();
        assert_eq!(response.status(), StatusCode::OK, "cut {cut:?}");
        assert_eq!(response.headers()["content-type"], "text/plain");
        let values: Vec<_> = response.headers().get_all("x-a").iter().collect();
        assert_eq!(values, ["1", "2"]);
        assert!(response.headers().get("link").is_none());
        assert!(response.headers().get("x-trailer").is_none());
        let mut body = response.into_body();
        let chunks = block_on(drain(&mut body)).unwrap();
        assert_eq!(concat(&chunks), expected, "cut {cut:?} piece {piece}");
        assert!(chunks.iter().all(|c| !c.is_empty()));
        let frames = peer.take_frames();
        let pings: Vec<_> = frames
            .iter()
            .filter(|(h, _)| h.kind == kind::PING)
            .collect();
        assert_eq!(pings.len(), 1);
        assert_eq!(
            (pings[0].0.flags, &pings[0].1[..]),
            (flag::ACK, &b"12345678"[..])
        );
    };
    for cut in 1..wire.len() {
        check(Some(cut), 0, false);
    }
    for piece in [1, 2, 3, 5, 8, 9, 10, 13, 100, 1448] {
        check(None, piece, false);
        check(None, piece, true);
    }
}

#[test]
fn bodiless_responses_and_length_checks() {
    let (send, _conn, peer) = connect();
    // HEAD: a content-length describes the body that is not sent.
    let response = send
        .send(request(Method::HEAD, "https://h/"), empty())
        .unwrap();
    peer.push(headers(
        1,
        &[(":status", "200"), ("content-length", "100")],
        true,
    ));
    let mut body = block_on(response).unwrap().into_body();
    assert!(block_on(drain(&mut body)).unwrap().is_empty());

    // 204 with END_STREAM on the head.
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(3, &[(":status", "204")], true));
    let response = block_on(response).unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(block_on(response.into_body().collect()).unwrap(), "");

    // Too little and too much body for the content-length.
    for (id, sent, end) in [(5, &b"abc"[..], true), (7, &b"abcdefgh"[..], false)] {
        let response = send.send(get("/"), empty()).unwrap();
        peer.push(headers(
            id,
            &[(":status", "200"), ("content-length", "5")],
            false,
        ));
        peer.push(data(id, sent, end));
        let mut body = block_on(response).unwrap().into_body();
        let result = block_on(drain(&mut body));
        assert_eq!(result, Err(H2Error::LengthMismatch), "stream {id}");
        // Fused after the error.
        assert!(block_on(body.chunk()).is_none());
        let frames = peer.take_frames();
        let (last, payload) = frames.last().unwrap();
        assert_eq!((last.kind, last.stream), (kind::RST_STREAM, id));
        assert_eq!(payload, &Reason::PROTOCOL_ERROR.0.to_be_bytes());
    }

    // An exact content-length, and a body collected from several slices.
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(
        9,
        &[(":status", "200"), ("content-length", "10")],
        false,
    ));
    peer.push(data(9, b"01234", false));
    peer.push(data(9, b"56789", true));
    let response = block_on(response).unwrap();
    assert_eq!(
        block_on(response.into_body().collect()).unwrap(),
        "0123456789"
    );
}

#[test]
fn malformed_responses_reset_the_stream_only() {
    let cases: [&[(&str, &str)]; 6] = [
        // No status, a bad status, a duplicate, one after a regular field.
        &[("content-type", "text/plain")],
        &[(":status", "abc")],
        &[(":status", "200"), (":status", "200")],
        &[("x", "y"), (":status", "200")],
        // A request pseudo-header field, and an invalid content-length.
        &[(":status", "200"), (":path", "/")],
        &[(":status", "200"), ("content-length", "1, 2")],
    ];
    let (send, _conn, peer) = connect();
    let mut id = 1;
    for fields in cases {
        let response = send.send(get("/"), empty()).unwrap();
        peer.push(headers(id, fields, false));
        assert_eq!(
            h2_error(block_on(response)),
            H2Error::MalformedResponse,
            "{fields:?}"
        );
        let frames = peer.take_frames();
        let (last, _) = frames.last().unwrap();
        assert_eq!((last.kind, last.stream), (kind::RST_STREAM, id));
        id += 2;
    }
    // 101, an interim response that ends the stream, and DATA before the
    // head are malformed too.
    for wire in [
        headers(id, &[(":status", "101")], false),
        headers(id + 2, &[(":status", "100")], true),
        data(id + 4, b"early", false),
    ] {
        let response = send.send(get("/"), empty()).unwrap();
        peer.push(wire);
        assert_eq!(h2_error(block_on(response)), H2Error::MalformedResponse);
    }
    id += 6;
    let response = send.send(get("/"), empty()).unwrap();
    for _ in 0..=MAX_INTERIM_RESPONSES {
        peer.push(headers(id, &[(":status", "100")], false));
    }
    assert_eq!(
        h2_error(block_on(response)),
        H2Error::TooManyInterimResponses
    );
    // Trailers that do not end the stream.
    id += 2;
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(id, OK, false));
    peer.push(headers(id, &[("x-trailer", "t")], false));
    let mut body = block_on(response).unwrap().into_body();
    assert_eq!(block_on(drain(&mut body)), Err(H2Error::MalformedResponse));

    // The connection is still good.
    id += 2;
    assert!(!send.is_closed());
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(id, OK, false));
    peer.push(data(id, b"fine", true));
    let response = block_on(response).unwrap();
    assert_eq!(block_on(response.into_body().collect()).unwrap(), "fine");
}

#[test]
fn dynamic_table_is_shared_across_responses_even_for_dropped_streams() {
    let (send, _conn, peer) = connect();
    let first = send.send(get("/1"), empty()).unwrap();
    let second = send.send(get("/2"), empty()).unwrap();
    // Cancelled before its response arrives: the block must still be
    // decoded, since it adds the entry the next response refers to.
    drop(first);
    let mut indexed = vec![0x88, 0x40, 5];
    indexed.extend_from_slice(b"x-dyn");
    indexed.push(5);
    indexed.extend_from_slice(b"value");
    peer.push(frame(
        kind::HEADERS,
        flag::END_HEADERS | flag::END_STREAM,
        1,
        &indexed,
    ));
    peer.push(frame(
        kind::HEADERS,
        flag::END_HEADERS | flag::END_STREAM,
        3,
        &[0x88, 0xbe],
    ));
    let response = block_on(second).unwrap();
    assert_eq!(response.headers()["x-dyn"], "value");
    let frames = peer.take_frames();
    assert!(frames.iter().any(|(h, p)| h.kind == kind::RST_STREAM
        && h.stream == 1
        && p == &Reason::CANCEL.0.to_be_bytes()));
}

// ---------------------------------------------------------------------------
// Stream and connection errors
// ---------------------------------------------------------------------------

#[test]
fn resets_and_goaway() {
    let (send, _conn, peer) = connect();
    let reset = send.send(get("/"), empty()).unwrap();
    let refused = send.send(get("/"), empty()).unwrap();
    peer.push(rst_stream(1, Reason::INTERNAL_ERROR));
    peer.push(rst_stream(3, Reason::REFUSED_STREAM));
    assert_eq!(
        h2_error(block_on(reset)),
        H2Error::Reset(Reason::INTERNAL_ERROR)
    );
    assert_eq!(h2_error(block_on(refused)), H2Error::Refused);

    // A reset in the middle of a body, after delivered data.
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(5, OK, false));
    let mut body = block_on(response).unwrap().into_body();
    peer.push(data(5, b"part", false));
    assert_eq!(block_on(body.chunk()).unwrap().unwrap(), "part");
    peer.push(rst_stream(5, Reason::CANCEL));
    assert_eq!(
        block_on(body.chunk()),
        Some(Err(H2Error::Reset(Reason::CANCEL)))
    );
    assert!(block_on(body.chunk()).is_none());

    // GOAWAY: the stream it covers finishes, the one past it is refused,
    // and no new request is accepted.
    let kept = send.send(get("/"), empty()).unwrap();
    let dropped = send.send(get("/"), empty()).unwrap();
    peer.push(goaway(7, Reason::NO_ERROR));
    peer.push(headers(7, OK, false));
    peer.push(data(7, b"still served", true));
    assert_eq!(h2_error(block_on(dropped)), H2Error::Refused);
    let kept = block_on(kept).unwrap();
    assert_eq!(
        block_on(kept.into_body().collect()).unwrap(),
        "still served"
    );
    assert!(send.is_closed());
    assert_eq!(
        send.send(get("/"), empty()).err(),
        Some(HttpError::Protocol)
    );
}

#[test]
fn protocol_violations_close_the_connection_with_goaway() {
    let big = frame(kind::PING, 0, 0, &vec![0; MAX_FRAME_SIZE + 1]);
    let mut flood = headers(1, OK, false);
    flood.extend(data(1, &vec![0; 16_384], false).repeat(STREAM_WINDOW as usize / 16_384 + 1));
    let cases: Vec<(Vec<u8>, Reason)> = vec![
        (
            frame(kind::PUSH_PROMISE, flag::END_HEADERS, 1, &[0, 0, 0, 2]),
            Reason::PROTOCOL_ERROR,
        ),
        (big, Reason::FRAME_SIZE_ERROR),
        (frame(kind::PING, 0, 0, b"short"), Reason::FRAME_SIZE_ERROR),
        (frame(kind::PING, 0, 1, b"12345678"), Reason::PROTOCOL_ERROR),
        (
            settings(&[(setting::ENABLE_PUSH, 1)]),
            Reason::PROTOCOL_ERROR,
        ),
        (
            settings(&[(setting::INITIAL_WINDOW_SIZE, 1 << 31)]),
            Reason::FLOW_CONTROL_ERROR,
        ),
        (
            settings(&[(setting::MAX_FRAME_SIZE, 100)]),
            Reason::PROTOCOL_ERROR,
        ),
        (
            frame(kind::SETTINGS, 0, 0, &[0; 5]),
            Reason::FRAME_SIZE_ERROR,
        ),
        (window_update(0, 0), Reason::PROTOCOL_ERROR),
        (window_update(0, 0x7fff_ffff), Reason::FLOW_CONTROL_ERROR),
        // Frames for a stream that was never opened.
        (headers(3, OK, true), Reason::PROTOCOL_ERROR),
        (data(2, b"x", false), Reason::PROTOCOL_ERROR),
        (data(0, b"x", false), Reason::PROTOCOL_ERROR),
        // A header block interrupted, and a stray CONTINUATION.
        (
            [frame(kind::HEADERS, 0, 1, &[0x88]), data(1, b"x", false)].concat(),
            Reason::PROTOCOL_ERROR,
        ),
        (
            frame(kind::CONTINUATION, flag::END_HEADERS, 1, &[]),
            Reason::PROTOCOL_ERROR,
        ),
        // An undecodable header block.
        (
            frame(kind::HEADERS, flag::END_HEADERS, 1, &[0xff]),
            Reason::COMPRESSION_ERROR,
        ),
        // Padding longer than the frame.
        (
            frame(
                kind::HEADERS,
                flag::END_HEADERS | flag::PADDED,
                1,
                &[9, 0x88],
            ),
            Reason::PROTOCOL_ERROR,
        ),
        // More data than the stream's window allows.
        (flood, Reason::FLOW_CONTROL_ERROR),
    ];
    for (wire, reason) in cases {
        let (send, _conn, peer) = connect();
        let response = send.send(get("/"), empty()).unwrap();
        peer.push(wire.clone());
        let error = match block_on(response) {
            Err(SendError::H2(error)) => error,
            // The flood: the head arrives, then the body fails.
            Ok(response) => {
                let mut body = response.into_body();
                block_on(drain(&mut body)).unwrap_err()
            }
            Err(other) => panic!("{other:?}"),
        };
        // A stream-level flow-control violation resets just that stream.
        if error == H2Error::Protocol(Reason::FLOW_CONTROL_ERROR) && !send.is_closed() {
            continue;
        }
        assert_eq!(
            error,
            H2Error::Protocol(reason),
            "{:x?}",
            &wire[..wire.len().min(16)]
        );
        assert!(send.is_closed());
        let frames = peer.take_frames();
        let (last, payload) = frames.last().unwrap();
        assert_eq!(last.kind, kind::GOAWAY);
        assert_eq!(payload[4..], reason.0.to_be_bytes());
    }

    // The server's preface must be SETTINGS.
    let peer = Peer::default();
    let (send, _conn) = handshake(Mock(peer.clone()));
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec());
    assert!(matches!(
        h2_error(block_on(response)),
        H2Error::Protocol(Reason::PROTOCOL_ERROR | Reason::FRAME_SIZE_ERROR)
    ));
}

#[test]
fn connection_window_violation_is_a_connection_error() {
    let (send, _conn, peer) = connect();
    // Three streams, each within its own window, together past the
    // connection's.
    let responses: Vec<_> = (0..3)
        .map(|_| send.send(get("/"), empty()).unwrap())
        .collect();
    let frames_each = STREAM_WINDOW as usize / 16_384;
    for id in [1, 3, 5] {
        let mut wire = headers(id, OK, false);
        wire.extend(data(id, &vec![0; 16_384], false).repeat(frames_each));
        peer.push_cut(&wire, 64 * 1024);
    }
    let mut failed = 0;
    for response in responses {
        match block_on(response) {
            Ok(response) => {
                let mut body = response.into_body();
                if block_on(drain(&mut body)).is_err() {
                    failed += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }
    assert!(failed >= 1);
    assert!(send.is_closed());
    let frames = peer.take_frames();
    let (last, payload) = frames.last().unwrap();
    assert_eq!(last.kind, kind::GOAWAY);
    assert_eq!(payload[4..], Reason::FLOW_CONTROL_ERROR.0.to_be_bytes());
}

#[test]
fn transport_end_and_failure() {
    // A clean end mid-response is not a clean end of the body.
    let (send, _conn, peer) = connect();
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(1, OK, false));
    peer.push(data(1, b"partial", false));
    peer.eof();
    let mut body = block_on(response).unwrap().into_body();
    assert_eq!(block_on(body.chunk()).unwrap().unwrap(), "partial");
    assert_eq!(block_on(body.chunk()), Some(Err(H2Error::Closed)));
    assert!(send.is_closed());

    // A complete response is delivered even if the connection then dies.
    let (send, _conn, peer) = connect();
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(1, OK, false));
    peer.push(data(1, b"whole", true));
    peer.fail(io::ErrorKind::ConnectionReset);
    let response = block_on(response).unwrap();
    assert_eq!(block_on(response.into_body().collect()).unwrap(), "whole");

    let (send, _conn, peer) = connect();
    let response = send.send(get("/"), empty()).unwrap();
    peer.fail(io::ErrorKind::ConnectionReset);
    assert_eq!(
        h2_error(block_on(response)),
        H2Error::Io(io::ErrorKind::ConnectionReset)
    );

    // Dropping the driver closes the connection.
    let (send, conn, _peer) = connect();
    let response = send.send(get("/"), empty()).unwrap();
    drop(conn);
    assert_eq!(h2_error(block_on(response)), H2Error::Closed);
    assert!(send.is_closed());
}

// ---------------------------------------------------------------------------
// Flow control and concurrency
// ---------------------------------------------------------------------------

#[test]
fn windows_are_replenished_as_the_body_is_consumed() {
    let (send, _conn, peer) = connect();
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(1, OK, false));
    let mut body = block_on(response).unwrap().into_body();
    peer.take_frames();
    // Six megabytes: more than either window, sent as fast as the
    // updates allow.
    let total = 6 * 1024 * 1024;
    let piece = vec![7u8; 16_384];
    let (mut sent, mut received) = (0usize, 0usize);
    let (mut stream_credit, mut conn_credit) = (STREAM_WINDOW as usize, CONNECTION_WINDOW as usize);
    let mut updates = (0, 0);
    while received < total {
        while sent < total && stream_credit >= piece.len() && conn_credit >= piece.len() {
            sent += piece.len();
            stream_credit -= piece.len();
            conn_credit -= piece.len();
            peer.push(data(1, &piece, sent == total));
        }
        let chunk = block_on(body.chunk()).expect("more body").unwrap();
        received += chunk.len();
        for (head, payload) in peer.take_frames() {
            assert_eq!(head.kind, kind::WINDOW_UPDATE);
            let increment = be32(&payload) as usize;
            if head.stream == 0 {
                conn_credit += increment;
                updates.0 += 1;
            } else {
                stream_credit += increment;
                updates.1 += 1;
            }
        }
    }
    assert!(block_on(body.chunk()).is_none());
    assert_eq!(received, total);
    // Half a window at a time, not a frame at a time.
    assert_eq!(updates, (2, 5));
}

#[test]
fn unread_data_of_a_dropped_body_is_credited_back() {
    let (send, _conn, peer) = connect();
    let mut bodies = Vec::new();
    for id in [1u32, 3] {
        let response = send.send(get("/"), empty()).unwrap();
        peer.push(headers(id, OK, false));
        bodies.push(block_on(response).unwrap().into_body());
    }
    // Nearly a whole stream window buffered on stream 1, read by nobody.
    let piece = vec![0u8; 16_384];
    for _ in 0..120 {
        peer.push(data(1, &piece, false));
    }
    peer.push(data(3, b"x", false));
    let mut other = bodies.pop().unwrap();
    assert_eq!(block_on(other.chunk()).unwrap().unwrap(), "x");
    peer.take_frames();
    drop(bodies);
    let frames = peer.take_frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        (frames[0].0.kind, frames[0].0.stream),
        (kind::RST_STREAM, 1)
    );
    // Frames still in flight for the cancelled stream are discarded, and
    // count, with what was dropped unread, towards the connection window.
    peer.push(data(1, &piece, false));
    for _ in 0..40 {
        peer.push(data(3, &piece, false));
    }
    peer.push(data(3, b"y", true));
    let mut read = 0;
    while let Some(chunk) = block_on(other.chunk()) {
        read += chunk.unwrap().len();
    }
    assert_eq!(read, 40 * 16_384 + 1);
    let updates: Vec<u32> = peer
        .take_frames()
        .iter()
        .filter(|(h, _)| h.kind == kind::WINDOW_UPDATE && h.stream == 0)
        .map(|(_, p)| be32(p))
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0] > 121 * 16_384, "{updates:?}");
    assert!(!send.is_closed());
}

#[test]
fn concurrency_limit_holds_requests_back() {
    let peer = Peer::default();
    let (send, _conn) = handshake(Mock(peer.clone()));
    peer.push(settings(&[(setting::MAX_CONCURRENT_STREAMS, 1)]));
    let first = send.send(get("/1"), empty()).unwrap();
    // Not known to be limited yet: the settings have not been read.
    let mut first = Box::pin(first);
    pending(&mut first);
    let second = send.send(get("/2"), empty()).unwrap();
    let mut second = Box::pin(second);
    pending(&mut second);
    let frames = peer.take_frames();
    let opened: Vec<u32> = frames
        .iter()
        .filter(|(h, _)| h.kind == kind::HEADERS)
        .map(|(h, _)| h.stream)
        .collect();
    assert_eq!(opened, [1]);
    peer.push(headers(1, OK, true));
    // Whichever task reads it, the waiting request goes out.
    pending(&mut second);
    let frames = peer.take_frames();
    assert!(
        frames
            .iter()
            .any(|(h, _)| h.kind == kind::HEADERS && h.stream == 3)
    );
    block_on(first).unwrap();
    peer.push(headers(3, OK, true));
    block_on(second).unwrap();

    // Cancelling a waiting request sends nothing for it.
    let third = send.send(get("/3"), empty()).unwrap();
    let fourth = send.send(get("/4"), empty()).unwrap();
    drop(fourth);
    peer.push(headers(5, OK, true));
    block_on(third).unwrap();
    assert!(peer.take_frames().iter().all(|(h, _)| h.stream <= 5));
}

#[test]
fn settings_change_open_stream_windows() {
    let (send, _conn, peer) = connect();
    let body = Bytes::from(pattern(70_000, 1));
    let mut response = Box::pin(send.send(post("/"), full(body)).unwrap());
    pending(&mut response);
    let count = |frames: &[(FrameHead, Vec<u8>)]| -> u32 {
        frames
            .iter()
            .filter(|(h, _)| h.kind == kind::DATA)
            .map(|(h, _)| h.len)
            .sum()
    };
    assert_eq!(count(&peer.take_frames()), 65_535);
    // The connection window opens, but the stream's is spent...
    peer.push(window_update(0, 100_000));
    pending(&mut response);
    assert_eq!(count(&peer.take_frames()), 0);
    // ...until a new initial window size raises it by the difference.
    peer.push(settings(&[(setting::INITIAL_WINDOW_SIZE, 65_535 + 1_000)]));
    pending(&mut response);
    assert_eq!(count(&peer.take_frames()), 1_000);
    peer.push(settings(&[(setting::INITIAL_WINDOW_SIZE, 1 << 20)]));
    peer.push(headers(1, OK, true));
    block_on(response).unwrap();
    assert_eq!(count(&peer.take_frames()), 70_000 - 65_535 - 1_000);
}

#[test]
fn early_response_abandons_the_upload() {
    let (send, _conn, peer) = connect();
    let body = Bytes::from(pattern(200_000, 1));
    let response = send.send(post("/"), full(body)).unwrap();
    peer.push(headers(1, &[(":status", "413")], true));
    let response = block_on(response).unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let frames = peer.take_frames();
    let (last, payload) = frames.last().unwrap();
    assert_eq!(last.kind, kind::RST_STREAM);
    assert_eq!(payload, &Reason::NO_ERROR.0.to_be_bytes());
    // More window changes nothing now.
    peer.push(window_update(0, 1_000_000));
    peer.push(window_update(1, 1_000_000));
    let next = send.send(get("/"), empty()).unwrap();
    peer.push(headers(3, OK, true));
    block_on(next).unwrap();
    assert!(peer.take_frames().iter().all(|(h, _)| h.kind != kind::DATA));
}

#[test]
fn blocked_transport_keeps_output_in_order() {
    let (send, _conn, peer) = connect();
    peer.block_sends(true);
    let mut response = Box::pin(send.send(post("/"), full(pattern(5_000, 2))).unwrap());
    pending(&mut response);
    assert!(peer.take_sent().is_empty());
    // Replies queue up behind the request while nothing can be written.
    peer.push(frame(kind::PING, 0, 0, b"abcdefgh"));
    peer.push(headers(1, OK, true));
    let response = block_on(response).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(peer.take_sent().is_empty());
    peer.block_sends(false);
    let next = send.send(get("/"), empty()).unwrap();
    peer.push(headers(3, OK, true));
    block_on(next).unwrap();
    let kinds: Vec<u8> = peer.take_frames().iter().map(|(h, _)| h.kind).collect();
    assert_eq!(
        kinds,
        [
            kind::SETTINGS,
            kind::WINDOW_UPDATE,
            kind::HEADERS,
            kind::DATA,
            kind::SETTINGS,
            kind::PING,
            kind::HEADERS
        ]
    );
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

#[test]
fn driver_serves_an_idle_connection_and_closes_it() {
    let (send, conn, peer) = connect();
    let mut conn = Box::pin(conn);
    // Before any request: the preface goes out and SETTINGS are answered.
    pending(&mut conn);
    let kinds: Vec<u8> = peer.take_frames().iter().map(|(h, _)| h.kind).collect();
    assert_eq!(kinds, [kind::SETTINGS, kind::WINDOW_UPDATE, kind::SETTINGS]);
    peer.push(frame(kind::PING, 0, 0, b"12345678"));
    pending(&mut conn);
    let frames = peer.take_frames();
    assert_eq!(
        (frames[0].0.kind, frames[0].0.flags),
        (kind::PING, flag::ACK)
    );

    // A request task takes over while it waits, and hands back after.
    let response = send.send(get("/"), empty()).unwrap();
    peer.push(headers(1, OK, false));
    peer.push(data(1, b"body", true));
    let response = block_on(response).unwrap();
    assert_eq!(block_on(response.into_body().collect()).unwrap(), "body");
    peer.push(frame(kind::PING, 0, 0, b"87654321"));
    pending(&mut conn);
    let frames = peer.take_frames();
    assert!(
        frames
            .iter()
            .any(|(h, p)| h.kind == kind::PING && p == b"87654321")
    );

    // The last handle gone: GOAWAY, and the driver finishes.
    drop(send);
    assert_eq!(block_on(conn), Ok(()));
    let frames = peer.take_frames();
    let (last, payload) = frames.last().unwrap();
    assert_eq!(last.kind, kind::GOAWAY);
    assert_eq!(payload[4..], Reason::NO_ERROR.0.to_be_bytes());
}

#[test]
fn driver_reports_what_ended_the_connection() {
    let (send, conn, peer) = connect();
    peer.push(goaway(0, Reason::NO_ERROR));
    assert_eq!(block_on(conn), Ok(()));
    assert!(send.is_closed());

    let (_send, conn, peer) = connect();
    peer.push(frame(kind::PUSH_PROMISE, 0, 1, &[0; 4]));
    assert_eq!(
        block_on(conn),
        Err(H2Error::Protocol(Reason::PROTOCOL_ERROR))
    );

    let (_send, conn, peer) = connect();
    peer.eof();
    assert_eq!(block_on(conn), Ok(()));
}

// ---------------------------------------------------------------------------
// Against hyper's server
// ---------------------------------------------------------------------------

/// One end of an in-memory pipe, delivering what it reads in chunks of
/// the given sizes (cycled) so frames are cut anywhere.
struct Pipe {
    io: tokio::io::DuplexStream,
    cuts: Vec<usize>,
    next: usize,
}

impl Transport for Pipe {
    type Recv = Bytes;

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;
        loop {
            let bytes = data.as_mut().expect("polled without a payload");
            if bytes.is_empty() {
                data.take();
                return Poll::Ready(Ok(()));
            }
            let n = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, bytes))?;
            Buf::advance(bytes, n);
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        use tokio::io::AsyncRead;
        let size = self.cuts[self.next % self.cuts.len()];
        let mut storage = vec![0; size];
        let mut buf = tokio::io::ReadBuf::new(&mut storage);
        std::task::ready!(Pin::new(&mut self.io).poll_read(cx, &mut buf))?;
        let n = buf.filled().len();
        self.next += 1;
        if n == 0 {
            return Poll::Ready(Ok(None));
        }
        storage.truncate(n);
        Poll::Ready(Ok(Some(Bytes::from(storage))))
    }
}

fn expected_reply(path: &str, len: usize, sum: u64) -> Vec<u8> {
    let size: usize = path.trim_start_matches("/r").parse().unwrap_or(0);
    let mut reply = format!("{path}:{len}:{sum}:").into_bytes();
    reply.extend_from_slice(&pattern(size, 5));
    reply
}

async fn serve(io: tokio::io::DuplexStream) {
    use http_body_util::{BodyExt, Full};
    let service = hyper::service::service_fn(
        |request: hyper::Request<hyper::body::Incoming>| async move {
            let path = request.uri().path().to_owned();
            assert_eq!(request.version(), Version::HTTP_2);
            assert_eq!(request.uri().host(), Some("test.local"));
            let body = request.into_body().collect().await?.to_bytes();
            let sum: u64 = body.iter().map(|&b| u64::from(b)).sum();
            let reply = expected_reply(&path, body.len(), sum);
            Ok::<_, hyper::Error>(
                hyper::Response::builder()
                    .header("content-type", "application/octet-stream")
                    .header("x-path", path)
                    .body(Full::new(Bytes::from(reply)))
                    .unwrap(),
            )
        },
    );
    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
        .await;
}

fn run<F: Future>(test: F) -> F::Output {
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

type Server = tokio::task::JoinHandle<()>;
type Driver = tokio::task::JoinHandle<Result<(), H2Error>>;

fn hyper_pair(cuts: &[usize], pipe: usize) -> (SendRequest<Pipe>, Driver, Server) {
    let (client, server) = tokio::io::duplex(pipe);
    let server = tokio::spawn(serve(server));
    let (send, conn) = handshake(Pipe {
        io: client,
        cuts: cuts.to_vec(),
        next: 0,
    });
    (send, tokio::spawn(conn), server)
}

async fn exchange(send: &SendRequest<Pipe>, size: usize, upload: usize, streamed: bool) {
    let path = format!("/r{size}");
    let payload = Bytes::from(pattern(upload, 7));
    let sum: u64 = payload.iter().map(|&b| u64::from(b)).sum();
    let method = if upload > 0 {
        Method::POST
    } else {
        Method::GET
    };
    let parts = request(method, &format!("https://test.local{path}"));
    let body = if streamed {
        let chunks: Vec<Result<Bytes, HttpError>> = payload
            .chunks(7_000)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        EncodedBody::Stream(ByteStream::new(futures::stream::iter(chunks)))
    } else {
        EncodedBody::Full(payload)
    };
    let response = send.send(parts, body).unwrap().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-path"], path.as_str());
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(&body[..], &expected_reply(&path, upload, sum)[..]);
}

#[test]
fn hyper_server_sequential_requests() {
    for cuts in [&[64 * 1024][..], &[1448], &[1, 7, 300, 9000], &[3]] {
        run(async {
            let (send, driver, server) = hyper_pair(cuts, 64 * 1024);
            let cases = if cuts == [3] {
                vec![(0, 0, false), (500, 300, false), (0, 2_000, true)]
            } else {
                vec![
                    (0, 0, false),
                    (64, 0, false),
                    (100_000, 0, false),
                    (5, 64, false),
                    (5, 300_000, false),
                    (20_000, 50_000, true),
                    (3_000_000, 0, false),
                    (0, 3_000_000, false),
                ]
            };
            for (size, upload, streamed) in cases {
                exchange(&send, size, upload, streamed).await;
            }
            drop(send);
            assert_eq!(driver.await.unwrap(), Ok(()));
            server.await.unwrap();
        });
    }
}

#[test]
fn hyper_server_concurrent_requests_across_tasks() {
    run(async {
        // A small pipe, so writes block and streams interleave.
        let (send, driver, server) = hyper_pair(&[1448, 5, 9000], 8 * 1024);
        let mut tasks = Vec::new();
        for i in 0..40usize {
            let send = send.clone();
            tasks.push(tokio::spawn(async move {
                for round in 0..3usize {
                    let size = [0, 10, 70_000, 400_000][(i + round) % 4];
                    let upload = [0, 30, 90_000, 250_000][(i / 4 + round) % 4];
                    exchange(&send, size, upload, i % 5 == 0 && upload > 0).await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        // Many streams in one task, too.
        let all = (0..50usize).map(|i| exchange(&send, i * 997, i * 131, false));
        futures::future::join_all(all).await;
        drop(send);
        assert_eq!(driver.await.unwrap(), Ok(()));
        server.await.unwrap();
    });
}

#[test]
fn hyper_server_cancelled_and_unread_responses() {
    run(async {
        let (send, driver, server) = hyper_pair(&[1448], 16 * 1024);
        // A response dropped at its head, one dropped mid-body, and a
        // request future dropped before any answer.
        let parts = request(Method::GET, "https://test.local/r500000");
        let response = send.send(parts, empty()).unwrap().await.unwrap();
        drop(response);
        let parts = request(Method::GET, "https://test.local/r500000");
        let mut body = send
            .send(parts, empty())
            .unwrap()
            .await
            .unwrap()
            .into_body();
        body.chunk().await.unwrap().unwrap();
        drop(body);
        let parts = request(Method::GET, "https://test.local/r500000");
        drop(send.send(parts, empty()).unwrap());

        // A body that nobody reads must not stall another stream: its
        // task is not polling, so the driver has to carry the connection.
        let parts = request(Method::GET, "https://test.local/r4000000");
        let unread = send.send(parts, empty()).unwrap().await.unwrap();
        let other = send.clone();
        tokio::spawn(async move {
            for _ in 0..5 {
                exchange(&other, 100_000, 100_000, false).await;
            }
        })
        .await
        .unwrap();
        drop(unread);
        exchange(&send, 1_000, 0, false).await;
        drop(send);
        assert_eq!(driver.await.unwrap(), Ok(()));
        server.await.unwrap();
    });
}

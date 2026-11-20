//! Entry points for fuzzing the parts of the codec that read what a server
//! sends: the frame parser and connection state machine, the HPACK
//! decoder and the Huffman decoder.
//!
//! Each takes arbitrary bytes, must not panic whatever they are, and
//! checks the invariants a wrong answer would break (flow-control credit
//! is never lost, no stream outlives its handle, the HPACK table's size
//! adds up). They are driven two ways: by the libFuzzer targets in
//! `fuzz/` (built with `--cfg fuzzing`), and by the seeded random tests in
//! [`tests`](super::tests), which run with the ordinary test suite.

use std::sync::atomic::AtomicBool;

use http::Request;

use super::*;
use crate::http::codec::ByteStream;

/// A transport that replays a script: `reads` in order, then nothing more
/// until `eof` is set, then a clean end. Writes are accepted and dropped,
/// until `writes_left` (if any) runs out; after that it never takes
/// another, as a peer that stopped reading would not.
struct FuzzIo {
    reads: VecDeque<Bytes>,
    eof: Arc<AtomicBool>,
    writes_left: Option<usize>,
}

impl Transport for FuzzIo {
    type Recv = Bytes;

    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        data: &mut Option<Bytes>,
    ) -> Poll<io::Result<()>> {
        match &mut self.writes_left {
            Some(0) => return Poll::Pending,
            Some(left) => *left -= 1,
            None => {}
        }
        data.take();
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match self.reads.pop_front() {
            Some(chunk) => Poll::Ready(Ok(Some(chunk))),
            None if self.eof.load(Ordering::SeqCst) => Poll::Ready(Ok(None)),
            None => Poll::Pending,
        }
    }
}

fn parts(method: Method, path: &str) -> request::Parts {
    Request::builder()
        .method(method)
        .uri(format!("https://fuzz.test{path}"))
        .body(())
        .expect("a valid request")
        .into_parts()
        .0
}

/// Runs a client connection against `data` as the server's side of it.
///
/// The first two bytes choose how: the size the rest is cut into as it
/// is "received", whether the server's SETTINGS preface is supplied (so
/// the rest need not begin with one), whether the transport stops taking
/// writes, whether the [`Connection`] driver runs, whether bodies are
/// dropped unread, whether the connection ends while requests are in
/// flight, and how many requests are added along the way. The rest is the
/// byte stream.
///
/// A handful of requests of every shape (no body, small and large
/// buffered bodies, a streamed body, HEAD) are sent, and everything is
/// polled until nothing moves.
pub fn connection(data: &[u8]) {
    let [control, more, stream @ ..] = data else {
        return;
    };
    let piece = 1 + usize::from(control & 0x1f) * 47;
    let blocked = control & 0x40 != 0;
    let drive = control & 0x20 != 0;
    let eof_in_flight = more & 0x01 != 0;
    let drop_unread = more & 0x02 != 0;
    let extra = usize::from(more >> 2 & 0x07);

    let mut wire = Vec::with_capacity(stream.len() + FRAME_HEADER_LEN);
    if control & 0x80 != 0 {
        wire.extend_from_slice(&[0, 0, 0, kind::SETTINGS, 0, 0, 0, 0, 0]);
    }
    wire.extend_from_slice(stream);
    let eof = Arc::new(AtomicBool::new(false));
    let io = FuzzIo {
        reads: wire.chunks(piece).map(Bytes::copy_from_slice).collect(),
        eof: eof.clone(),
        writes_left: blocked.then_some(3),
    };
    let (send, conn) = handshake(io);
    let mut conn = Some(Box::pin(conn));
    let mut cx = Context::from_waker(Waker::noop());

    let streamed = || {
        let chunks = [
            Bytes::from_static(b"first"),
            Bytes::new(),
            Bytes::from(vec![7; 20_000]),
        ];
        EncodedBody::Stream(ByteStream::from(futures::stream::iter(chunks)))
    };
    let requests = [
        (parts(Method::GET, "/"), EncodedBody::Full(Bytes::new())),
        (
            parts(Method::POST, "/small"),
            EncodedBody::Full(Bytes::from_static(b"body")),
        ),
        (
            parts(Method::POST, "/large"),
            EncodedBody::Full(Bytes::from(vec![1; 200_000])),
        ),
        (parts(Method::POST, "/stream"), streamed()),
        (
            parts(Method::HEAD, "/head"),
            EncodedBody::Full(Bytes::new()),
        ),
    ];
    let mut futures: Vec<ResponseFuture<FuzzIo>> = requests
        .into_iter()
        .filter_map(|(parts, body)| send.send(parts, body).ok())
        .collect();
    let mut bodies: Vec<Body<FuzzIo>> = Vec::new();
    let mut extra_sent = 0;

    for round in 0..512 {
        let mut progress = false;
        if drive
            && let Some(driver) = &mut conn
            && driver.as_mut().poll(&mut cx).is_ready()
        {
            conn = None;
            progress = true;
        }
        let mut heads = Vec::new();
        futures.retain_mut(|future| match Pin::new(future).poll(&mut cx) {
            Poll::Pending => true,
            Poll::Ready(result) => {
                progress = true;
                if let Ok(response) = result {
                    assert_eq!(response.version(), Version::HTTP_2);
                    assert!(!response.status().is_informational());
                    heads.push(response.into_body());
                }
                false
            }
        });
        bodies.append(&mut heads);
        bodies.retain_mut(|body| {
            for slices in 0..4096 {
                match body.poll_slice(&mut cx) {
                    Poll::Pending => return true,
                    Poll::Ready(Some(Ok(slice))) => {
                        progress = true;
                        assert!(!slice.is_empty(), "empty slices are never yielded");
                        if drop_unread && slices == 0 {
                            return false;
                        }
                    }
                    Poll::Ready(Some(Err(_)) | None) => {
                        progress = true;
                        return false;
                    }
                }
            }
            true
        });
        // More requests once the first frames have been seen, so that some
        // start under the peer's settings and after its GOAWAY.
        if round > 0 && extra_sent < extra {
            extra_sent += 1;
            let body = EncodedBody::Full(Bytes::from(vec![2; 70_000]));
            if let Ok(future) = send.send(parts(Method::PUT, "/extra"), body) {
                futures.push(future);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }

    if eof_in_flight {
        // The connection ends under whatever is still running: everything
        // must finish, one way or the other.
        eof.store(true, Ordering::SeqCst);
        for future in &mut futures {
            // More than one poll: a task that has read its budget of
            // other streams' frames yields before reading on.
            let done = (0..100_000).any(|_| Pin::new(&mut *future).poll(&mut cx).is_ready());
            assert!(done, "a request is waiting on a connection that ended");
        }
        for body in &mut bodies {
            // Pending here is a task yielding after its read budget, not
            // one waiting: the connection has nothing left to wait for.
            let done = (0..100_000)
                .any(|_| matches!(body.poll_slice(&mut cx), Poll::Ready(Some(Err(_)) | None)));
            assert!(done, "a body is waiting on a connection that ended");
        }
    }
    drop(futures);
    drop(bodies);

    {
        let inner = send.shared.lock();
        assert_eq!(inner.streams.len, 0, "a stream outlived its handle");
        assert_eq!(inner.active, 0);
        assert!(inner.ids.is_empty());
        assert!(inner.pending_open.is_empty());
        assert!((0..=i64::from(CONNECTION_WINDOW)).contains(&inner.recv_window));
        assert!(inner.send_window <= MAX_WINDOW);
        // With no stream left and no frame half read, every byte of DATA
        // the peer sent has been credited back or is waiting to be.
        if inner.error.is_none() && matches!(inner.parse, Parse::Head) {
            assert_eq!(
                inner.recv_window + i64::from(inner.unreleased),
                i64::from(CONNECTION_WINDOW),
                "connection flow-control credit was lost"
            );
        }
    }

    // The last handle goes, then the peer: the driver must finish.
    drop(send);
    eof.store(true, Ordering::SeqCst);
    if let Some(mut driver) = conn {
        let done = (0..100_000).any(|_| driver.as_mut().poll(&mut cx).is_ready());
        assert!(done, "the driver outlived a connection nobody uses");
    }
}

/// Decodes `data` as a series of header blocks on one HPACK decoder.
///
/// Each block is preceded by a byte giving a quarter of its length; the
/// last takes whatever is left. Decoding stops at the first error, as a
/// connection would.
pub fn hpack(data: &[u8]) {
    let mut decoder = hpack::Decoder::new();
    let limits = hpack::Limits {
        fields: MAX_HEADERS,
        size: MAX_HEADER_LIST_SIZE,
    };
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let len = (usize::from(len) * 4).min(tail.len());
        let (block, tail) = tail.split_at(len);
        rest = tail;
        let mut fields = 0;
        let mut size = 0;
        let result = decoder.decode(block, limits, |name, value| {
            fields += 1;
            size += value.len()
                + match &name {
                    hpack::Name::Status => 7,
                    hpack::Name::Pseudo(name) => name.len(),
                    hpack::Name::Field(name) => name.as_str().len(),
                };
        });
        decoder.check_invariants();
        if result.is_err() {
            return;
        }
        assert!(fields <= limits.fields);
        assert!(size <= limits.size);
    }
}

/// Decodes `data` as a Huffman-coded string, and checks that the coding
/// round-trips both ways: whatever decodes re-encodes to the same bytes
/// (a valid encoding is canonical), and `data` itself survives being
/// encoded and decoded.
pub fn huffman(data: &[u8]) {
    let mut decoded = BytesMut::new();
    if huffman::decode(data, &mut decoded).is_ok() {
        let mut encoded = Vec::new();
        huffman::encode(&decoded, &mut encoded);
        assert_eq!(encoded, data, "a second encoding of the same string");
    }
    let mut encoded = Vec::new();
    huffman::encode(data, &mut encoded);
    let mut decoded = BytesMut::new();
    huffman::decode(&encoded, &mut decoded).expect("what was just encoded");
    assert_eq!(&decoded[..], data);
}

//! WebSocket client (RFC 6455) over this crate's HTTP client and DPDK TCP
//! stream.
//!
//! The opening handshake is an HTTP/1.1 GET + `Upgrade: websocket` sent
//! through [`Client::h1_upgrade_request`], so it inherits the client's
//! dialing, `--resolve` mapping, and TLS (custom CAs, SNI) as-is: `ws://`
//! is plain TCP, `wss://` goes through the h1-only TLS connector. After a
//! validated `101 Switching Protocols`, the connection is taken over via
//! `hyper::upgrade` and spoken as WebSocket frames.
//!
//! Two transports carry the frames (see [`Transport`]):
//!
//! - `ws://` recovers the raw [`TcpStream`] from hyper's `Upgraded` and
//!   runs on its owned-`Bytes` API. Received payloads are slices of the
//!   received chunks (views of the NIC's packet buffers) whenever a frame's
//!   payload lies within one chunk; only what straddles chunks is copied to
//!   make it contiguous. Outgoing frames are masked in one pass straight
//!   into DMA memory the engine attaches to packets without another copy.
//! - `wss://` (anything that isn't a bare `TcpStream`) stays on the
//!   copying `AsyncRead`/`AsyncWrite` of hyper's `Upgraded`: the bytes
//!   there are TLS plaintext, which rustls copies anyway.
//!
//! The frame logic (parsing rules, Ping/Close handling, ordering) is the
//! same for both; only where bytes come from and go to differs.
//!
//! Corking is not allowed for WebSocket connections: a corked connection
//! holds its sub-MSS tail for a manual flush, which would stall every
//! small frame of an interactive protocol. The upgrade path structurally
//! never corks (and rejects a request that asks for it); connections are
//! dialed `nodelay: true, cork: false`.
//!
//! Framing notes: client-to-server frames are masked (required by the
//! RFC), server frames must arrive unmasked; inbound fragmentation is
//! reassembled; Pings are auto-answered with Pongs (and still surfaced);
//! the close handshake is echoed. Extensions and subprotocols are not
//! offered, so RSV bits or a server-selected protocol fail the handshake.

use std::{
    collections::VecDeque,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, ready};
use http::{Extensions, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, Version, header};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::client::Client;
use crate::dpdk::tcp::stream::TcpStream;
use crate::http::errors::{
    HttpError::{self, InvalidHeaderValue},
    WebSocketError,
};

/// Upper bound on a single inbound frame's payload.
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Upper bound on a reassembled (fragmented) inbound message.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Minimum free space offered to each socket read.
const READ_CHUNK: usize = 8 * 1024;
/// Longest inbound (server) frame header: 2 bytes plus an 8-byte extended
/// length. Server frames carry no masking key.
const MAX_INBOUND_HEADER: usize = 10;
/// Longest outbound (client) frame header: 2 bytes, an 8-byte extended
/// length, and the 4-byte masking key.
const MAX_OUTBOUND_HEADER: usize = 14;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The IO the frames run over on the copying path: the connection hyper
/// handed back after the 101, re-wrapped for tokio.
type WsIo = TokioIo<Upgraded>;

// The message types are the generic ones from the transport-agnostic
// `http::websocket` module; re-exported here so callers holding a [`Ws`]
// can name them without reaching across modules.
pub use crate::http::websocket::{CloseFrame, Message};

/// The closing handshake (RFC 6455 §7.1.2). A peer-initiated Close is
/// echoed at once, so it goes straight from `Open` to `Closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseState {
    /// No Close frame in either direction.
    Open,
    /// Our Close is queued or sent; the peer's has not arrived. Sends are
    /// refused, Pings are no longer answered, and receiving continues.
    CloseSent,
    /// Close frames have gone both ways: `recv` ends once ours is flushed.
    Closed,
}

/// An established WebSocket connection.
pub struct WebSocketClient {
    io: Transport,
    rng: SystemRandom,
    /// In-progress fragmented message: (data opcode, accumulated payload).
    fragment: Option<(u8, BytesMut)>,
    close: CloseState,
    /// The subprotocol the server selected from the request's offers.
    protocol: Option<String>,
    /// The `101 Switching Protocols` response parts (status, headers,
    /// extensions), kept for callers that need e.g. `Set-Cookie`.
    handshake: http::response::Parts,
    /// Outgoing bytes, already masked and encoded, in wire order: Sink
    /// messages plus automatic replies (Pong, Close echo) queued while
    /// reading. A frame may span several entries (one per DMA block it was
    /// written into); only the front entry may be partly written.
    write_queue: VecDeque<Bytes>,
    /// A received message held back until the automatic reply it triggered
    /// has been written and flushed (see [`Self::poll_recv`]).
    ready_message: Option<Message>,
}

impl WebSocketClient {
    /// Opens a WebSocket connection from a caller-built handshake request,
    /// preserving its URI (including query parameters) and headers -- e.g.
    /// `Authorization`, `Cookie`, `Origin`, or `Sec-WebSocket-Protocol`
    /// offers. The method must be GET and the URI scheme `ws`/`wss`.
    ///
    /// The protocol-mandated fields (`Upgrade`, `Connection`,
    /// `Sec-WebSocket-Key`, `Sec-WebSocket-Version`) are set here and
    /// override anything the caller put in those headers -- the key in
    /// particular must match what the accept check below expects.
    ///
    /// If the request offers subprotocols, the server's selection is
    /// validated against the offers and exposed via [`Self::protocol`]. The
    /// full `101` handshake response (e.g. its `Set-Cookie` headers) is
    /// kept on [`Self::handshake`].
    ///
    /// Corking is not allowed for WebSocket connections: a `TcpOptions`
    /// extension with `cork: true` is rejected; `nodelay` is honored.
    pub async fn open(
        client: &Client,
        uri: Uri,
        mut headers: HeaderMap<HeaderValue>,
        extensions: Extensions,
    ) -> Result<Self, WebSocketError> {
        // `http::Uri` only lowercases `http`/`https`, so `WSS://` keeps its
        // case; compare ASCII-case-insensitively.
        match uri.scheme_str() {
            Some(s) if s.eq_ignore_ascii_case("ws") || s.eq_ignore_ascii_case("wss") => {}
            _ => return Err(WebSocketError::UnsupportedScheme),
        }

        // The subprotocols the caller is offering, remembered so the
        // server's selection can be validated.
        let offered_protocols: Vec<String> = headers
            .get_all(header::SEC_WEBSOCKET_PROTOCOL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        // Sec-WebSocket-Key: 16 random bytes, base64 (RFC 6455 §4.1).
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 16];
        rng.fill(&mut key_bytes).map_err(|_| WebSocketError::Rng)?;
        let key = base64(&key_bytes);

        // Force the protocol-mandated fields (insert replaces any caller
        // values), leaving all other caller headers untouched.

        headers.insert(header::UPGRADE, http::HeaderValue::from_static("websocket"));
        headers.insert(
            header::CONNECTION,
            http::HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            header::SEC_WEBSOCKET_KEY,
            // The key is base64, always a valid header value.
            http::HeaderValue::from_str(&key).map_err(|_| {
                InvalidHeaderValue("base64 Sec-WebSocket-Key is a valid header value")
            })?,
        );
        headers.insert(
            header::SEC_WEBSOCKET_VERSION,
            http::HeaderValue::from_static("13"),
        );
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .uri(uri)
            .method(Method::GET)
            .body(Bytes::new())
            .map_err(|_| HttpError::MalformedRequest)?;

        *request.headers_mut() = headers;
        *request.extensions_mut() = extensions;

        let mut response = client.h1_upgrade_request(request).await?;

        // Validate the server's half of the handshake (RFC 6455 §4.1).
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(WebSocketError::UnexpectedStatus(response.status()));
        }
        require_token(
            response.headers(),
            &header::UPGRADE,
            "websocket",
            WebSocketError::MissingUpgradeHeader,
            WebSocketError::BadUpgradeHeader,
        )?;
        require_token(
            response.headers(),
            &header::CONNECTION,
            "upgrade",
            WebSocketError::MissingConnectionHeader,
            WebSocketError::BadConnectionHeader,
        )?;
        let accept = response
            .headers()
            .get(header::SEC_WEBSOCKET_ACCEPT)
            .and_then(|v| v.to_str().ok())
            .ok_or(WebSocketError::MissingAcceptHeader)?;
        if accept != accept_key(&key) {
            return Err(WebSocketError::AcceptMismatch);
        }
        // The server may select at most one of the offered subprotocols
        // (RFC 6455 §4.2.2); a selection we never offered fails the
        // handshake.
        let protocol = match response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .map(|v| v.to_str().map(str::trim))
        {
            None => None,
            Some(Err(_)) => return Err(WebSocketError::InvalidProtocolHeader),
            Some(Ok(selected)) => {
                if !offered_protocols.iter().any(|p| p == selected) {
                    return Err(WebSocketError::UnofferedSubprotocol);
                }
                Some(selected.to_string())
            }
        };

        // Take the upgrade slot via `&mut` so the response parts (headers
        // like Set-Cookie) can be kept for the caller.
        let on_upgrade = hyper::upgrade::on(&mut response);
        let (handshake, _body) = response.into_parts();
        let upgraded = on_upgrade
            .await
            .map_err(|_| WebSocketError::UpgradeIncomplete)?;

        Ok(WebSocketClient::from_upgraded(
            upgraded, rng, protocol, handshake,
        ))
    }

    /// Wraps a connection whose opening handshake has been validated, on
    /// the zero-copy transport when it is a plain [`TcpStream`].
    fn from_upgraded(
        upgraded: Upgraded,
        rng: SystemRandom,
        protocol: Option<String>,
        handshake: http::response::Parts,
    ) -> Self {
        Self::with_transport(Transport::from_upgraded(upgraded), rng, protocol, handshake)
    }

    fn with_transport(
        io: Transport,
        rng: SystemRandom,
        protocol: Option<String>,
        handshake: http::response::Parts,
    ) -> Self {
        WebSocketClient {
            io,
            rng,
            fragment: None,
            close: CloseState::Open,
            protocol,
            handshake,
            write_queue: VecDeque::new(),
            ready_message: None,
        }
    }

    /// The subprotocol the server selected from the handshake request's
    /// `Sec-WebSocket-Protocol` offers, if any.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// The `101 Switching Protocols` handshake response (status, headers,
    /// extensions) -- e.g. for reading `Set-Cookie`.
    pub fn handshake(&self) -> &http::response::Parts {
        &self.handshake
    }

    /// Receives the next message. `Ok(None)` means the connection ended
    /// cleanly (close handshake completed, or EOF after a close). Inbound
    /// Pings are answered automatically and also returned.
    ///
    /// Cancel-safe: all progress (buffered input, a partly written reply)
    /// is kept on `self`, so dropping a pending `recv` loses nothing.
    pub async fn recv(&mut self) -> Result<Option<Message>, WebSocketError> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Sends one message (never fragmented on the wire; sizes up to the
    /// frame maximum go out as a single frame) and flushes it.
    pub async fn send(&mut self, message: Message) -> Result<(), WebSocketError> {
        SinkExt::send(self, message).await
    }

    /// Starts (or completes) the closing handshake. After this, `send`
    /// fails and `recv` keeps delivering anything already in flight until
    /// the peer's Close (or EOF) arrives.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> Result<(), WebSocketError> {
        if self.close != CloseState::Open {
            return Ok(());
        }
        SinkExt::send(self, Message::Close(frame)).await
    }

    /// The receive state machine behind [`Self::recv`] and `poll_next`.
    ///
    /// A frame that needs an automatic reply (Ping, peer-initiated Close)
    /// queues the reply, and the message is held in `ready_message` until
    /// the reply has been written and flushed -- the same ordering the
    /// reply had when it was written inline, but resumable: a `Pending`
    /// part-way through the reply leaves it at the head of the queue to be
    /// finished on the next poll, instead of being dropped with a future.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Message>, WebSocketError>> {
        loop {
            if self.ready_message.is_some() || self.close == CloseState::Closed {
                ready!(self.poll_flush_writes(cx))?;
                // `None` here is the end of a completed close handshake.
                return Poll::Ready(Ok(self.ready_message.take()));
            }

            let Some(frame) = ready!(self.io.poll_frame(cx))? else {
                // EOF. Clean only if the close handshake got at least our
                // half out (some peers close TCP without echoing Close).
                if self.close != CloseState::Open {
                    return Poll::Ready(Ok(None));
                }
                return Poll::Ready(Err(WebSocketError::UncleanClose));
            };
            let queued = self.write_queue.len();
            match self.handle_frame(frame)? {
                Some(message) if self.write_queue.len() > queued => {
                    self.ready_message = Some(message);
                }
                Some(message) => return Poll::Ready(Ok(Some(message))),
                None => {}
            }
        }
    }

    /// Applies one parsed frame; returns a `Message` when one is complete.
    /// Automatic replies are queued, not written; the caller drives them.
    fn handle_frame(&mut self, frame: RawFrame) -> Result<Option<Message>, WebSocketError> {
        match frame.opcode {
            OP_TEXT | OP_BINARY => {
                if self.fragment.is_some() {
                    return Err(WebSocketError::UnexpectedDataFrame);
                }
                if frame.fin {
                    return Ok(Some(into_data_message(frame.opcode, frame.payload)?));
                }
                // A payload this side assembled (it straddled chunks) is
                // uniquely owned and grows in place; one that is a view of
                // received data is copied into an owned buffer.
                let buffered = frame
                    .payload
                    .try_into_mut()
                    .unwrap_or_else(|shared| BytesMut::from(&shared[..]));
                self.fragment = Some((frame.opcode, buffered));
                Ok(None)
            }
            OP_CONTINUATION => {
                let Some((_, buffered)) = self.fragment.as_mut() else {
                    return Err(WebSocketError::UnexpectedContinuation);
                };
                if buffered.len() + frame.payload.len() > MAX_MESSAGE {
                    return Err(WebSocketError::MessageTooLarge);
                }
                buffered.put_slice(&frame.payload);
                if !frame.fin {
                    return Ok(None);
                }
                let (opcode, buffered) = self.fragment.take().expect("fragment checked above");
                Ok(Some(into_data_message(opcode, buffered.freeze())?))
            }
            OP_PING => {
                validate_control(&frame)?;
                // Auto-pong with the same payload (RFC 6455 §5.5.3),
                // unless we've already sent our Close.
                if self.close == CloseState::Open {
                    self.queue_frame(OP_PONG, &frame.payload)?;
                }
                Ok(Some(Message::Ping(frame.payload)))
            }
            OP_PONG => {
                validate_control(&frame)?;
                Ok(Some(Message::Pong(frame.payload)))
            }
            OP_CLOSE => {
                validate_control(&frame)?;
                let close_frame = parse_close_payload(&frame.payload)?;
                let peer_initiated = self.close == CloseState::Open;
                self.close = CloseState::Closed;
                // Echo the close (same code) if the peer initiated.
                if peer_initiated {
                    let echo: Bytes = if frame.payload.len() >= 2 {
                        frame.payload.slice(..2)
                    } else {
                        Bytes::new()
                    };
                    self.queue_frame(OP_CLOSE, &echo)?;
                }
                Ok(Some(Message::Close(close_frame)))
            }
            other => Err(WebSocketError::UnknownOpcode(other)),
        }
    }

    /// Encodes one masked frame (client frames must be masked, RFC 6455
    /// §5.3) onto the end of the outgoing queue.
    fn queue_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WebSocketError> {
        let mut mask = [0u8; 4];
        self.rng.fill(&mut mask).map_err(|_| WebSocketError::Rng)?;
        let head = OutboundHeader::new(opcode, payload.len(), mask);
        self.io.encode(&head, payload, &mut self.write_queue);
        Ok(())
    }

    /// Writes the queued frames out, whole and in order (no flush).
    fn poll_write_queue(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketError>> {
        self.io.poll_write_queue(cx, &mut self.write_queue)
    }

    /// Writes every queued frame, then flushes the transport.
    fn poll_flush_writes(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketError>> {
        ready!(self.poll_write_queue(cx))?;
        self.io.poll_flush(cx)
    }
}

/// The transport-agnostic face of this client: `open` takes the DPDK HTTP
/// [`Client`], and a `TcpOptions` extension with `cork: true` is rejected
/// (`nodelay` is honored), exactly as [`WebSocketClient::open`].
impl crate::http::websocket::WebSocket for WebSocketClient {
    type Client = Client;

    fn open(
        client: &Client,
        uri: Uri,
        headers: HeaderMap<HeaderValue>,
        extensions: Extensions,
    ) -> impl Future<Output = Result<Self, WebSocketError>> + Send {
        // Inherent methods take precedence, so this is the inherent `open`.
        WebSocketClient::open(client, uri, headers, extensions)
    }

    fn protocol(&self) -> Option<&str> {
        WebSocketClient::protocol(self)
    }

    fn handshake(&self) -> &http::response::Parts {
        WebSocketClient::handshake(self)
    }
}

impl Stream for WebSocketClient {
    type Item = Result<Message, WebSocketError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_recv(cx).map(Result::transpose)
    }
}

impl Sink<Message> for WebSocketClient {
    type Error = WebSocketError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.close != CloseState::Open {
            return Poll::Ready(Err(WebSocketError::SendAfterClose));
        }
        // One-frame buffer: everything queued before (including automatic
        // replies) must be written before another message is accepted.
        this.poll_write_queue(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.close != CloseState::Open {
            return Err(WebSocketError::SendAfterClose);
        }
        match message {
            Message::Text(text) => this.queue_frame(OP_TEXT, text.as_bytes()),
            Message::Binary(data) => this.queue_frame(OP_BINARY, &data),
            Message::Ping(data) => {
                check_control_len(&data)?;
                this.queue_frame(OP_PING, &data)
            }
            Message::Pong(data) => {
                check_control_len(&data)?;
                this.queue_frame(OP_PONG, &data)
            }
            Message::Close(frame) => {
                let mut payload = BytesMut::new();
                if let Some(frame) = frame {
                    payload.put_u16(frame.code);
                    payload.put_slice(frame.reason.as_bytes());
                }
                check_control_len(&payload)?;
                // No further messages may be enqueued, even if encoding
                // fails below.
                this.close = CloseState::CloseSent;
                this.queue_frame(OP_CLOSE, &payload)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_flush_writes(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.close == CloseState::Open {
            this.close = CloseState::CloseSent;
            this.queue_frame(OP_CLOSE, &[])?;
        }
        this.poll_flush_writes(cx)
    }
}

/// What the frames run over once the handshake is done. The frame logic in
/// [`WebSocketClient`] is shared; each variant only supplies parsed frames
/// and takes encoded ones.
enum Transport {
    /// `ws://`: the raw TCP stream, spoken through its owned-`Bytes` API so
    /// neither direction copies at the stream boundary.
    Tcp(TcpTransport),
    /// Anything else hyper hands back (i.e. `wss://`, where rustls sits
    /// between us and the stream): the copying tokio IO traits.
    Upgraded(UpgradedTransport),
}

/// The zero-copy transport over a plain [`TcpStream`].
struct TcpTransport {
    stream: TcpStream,
    reader: ChunkReader,
}

/// The copying transport over hyper's `Upgraded`.
struct UpgradedTransport {
    io: WsIo,
    /// Raw inbound bytes not yet parsed into frames.
    read_buf: BytesMut,
    /// A spare encode buffer, recycled from fully written frames.
    write_buffer: BytesMut,
    /// Bytes of the front queue entry already written.
    write_pos: usize,
}

impl Transport {
    /// Recovers the raw [`TcpStream`] from a plaintext upgrade, keeping the
    /// bytes hyper read past the 101 head as the first input. Any other
    /// connection (TLS) stays wrapped.
    fn from_upgraded(upgraded: Upgraded) -> Self {
        match upgraded.downcast::<TokioIo<TcpStream>>() {
            Ok(parts) => Transport::Tcp(TcpTransport {
                stream: parts.io.into_inner(),
                reader: ChunkReader::new(parts.read_buf),
            }),
            Err(upgraded) => Transport::Upgraded(UpgradedTransport {
                io: TokioIo::new(upgraded),
                read_buf: BytesMut::with_capacity(8 * 1024),
                write_buffer: BytesMut::new(),
                write_pos: 0,
            }),
        }
    }

    /// The next complete inbound frame; `Ok(None)` at EOF.
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RawFrame>, WebSocketError>> {
        match self {
            Transport::Tcp(tcp) => tcp.poll_frame(cx),
            Transport::Upgraded(upgraded) => upgraded.poll_frame(cx),
        }
    }

    /// Appends one encoded frame to `queue`.
    fn encode(&mut self, head: &OutboundHeader, payload: &[u8], queue: &mut VecDeque<Bytes>) {
        match self {
            Transport::Tcp(tcp) => tcp.encode(head, payload, queue),
            Transport::Upgraded(upgraded) => upgraded.encode(head, payload, queue),
        }
    }

    /// Writes `queue` out, whole and in order (no flush).
    fn poll_write_queue(
        &mut self,
        cx: &mut Context<'_>,
        queue: &mut VecDeque<Bytes>,
    ) -> Poll<Result<(), WebSocketError>> {
        match self {
            Transport::Tcp(tcp) => tcp.poll_write_queue(cx, queue),
            Transport::Upgraded(upgraded) => upgraded.poll_write_queue(cx, queue),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketError>> {
        match self {
            // `poll_send` hands each chunk to the worker as it goes; there
            // is no buffer on this side to flush (and the connection is
            // never corked).
            Transport::Tcp(_) => Poll::Ready(Ok(())),
            Transport::Upgraded(upgraded) => Pin::new(&mut upgraded.io)
                .poll_flush(cx)
                .map_err(|e| WebSocketError::Io(e.kind())),
        }
    }
}

impl TcpTransport {
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RawFrame>, WebSocketError>> {
        loop {
            if let Some(frame) = self.reader.next_frame()? {
                return Poll::Ready(Ok(Some(frame)));
            }
            match ready!(self.stream.poll_recv(cx)) {
                Ok(Some(chunk)) => self.reader.push(chunk),
                Ok(None) => return Poll::Ready(Ok(None)),
                Err(e) => return Poll::Ready(Err(WebSocketError::Io(e.kind()))),
            }
        }
    }

    /// Writes header and masked payload in one pass straight into DMA
    /// memory, one entry per block the frame lands in, so the engine
    /// attaches them to packets as they are. A port without multi-segment
    /// transmit has no DMA writer (and the worker copies into an mbuf
    /// regardless); then, or if DMA memory runs out, the rest of the frame
    /// goes to the heap -- still in one pass.
    fn encode(&mut self, head: &OutboundHeader, payload: &[u8], queue: &mut VecDeque<Bytes>) {
        let total = head.len() + payload.len();
        let mut done = 0;
        if let Some(writer) = self.stream.dma_writer() {
            while done < total {
                let Some(chunk) = writer.fill_with(total - done, |dst| {
                    write_frame_range(as_uninit(dst), done, head, payload)
                }) else {
                    break;
                };
                done += chunk.len();
                queue.push_back(chunk);
            }
        }
        if done < total {
            let mut out = BytesMut::new();
            append_frame_range(&mut out, done, head, payload);
            queue.push_back(out.freeze());
        }
    }

    fn poll_write_queue(
        &mut self,
        cx: &mut Context<'_>,
        queue: &mut VecDeque<Bytes>,
    ) -> Poll<Result<(), WebSocketError>> {
        while let Some(front) = queue.pop_front() {
            let mut unsent = Some(front);
            let result = self.stream.poll_send(cx, &mut unsent);
            // On `Pending` (or an error) the unsent suffix stays at the
            // front, so the next poll resumes exactly there.
            if let Some(rest) = unsent {
                queue.push_front(rest);
            }
            match result {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(WebSocketError::Io(e.kind()))),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl UpgradedTransport {
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RawFrame>, WebSocketError>> {
        loop {
            if let Some(frame) = try_parse_frame(&mut self.read_buf)? {
                return Poll::Ready(Ok(Some(frame)));
            }
            if ready!(self.poll_fill_read_buf(cx))? == 0 {
                return Poll::Ready(Ok(None));
            }
        }
    }

    /// Reads more inbound bytes onto the end of `read_buf`; `Ok(0)` at EOF.
    fn poll_fill_read_buf(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, WebSocketError>> {
        self.read_buf.reserve(READ_CHUNK);
        let n = {
            let mut buf = ReadBuf::uninit(self.read_buf.spare_capacity_mut());
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut buf))
                .map_err(|e| WebSocketError::Io(e.kind()))?;
            buf.filled().len()
        };
        // SAFETY: `poll_read` initialized the first `n` spare bytes.
        unsafe { self.read_buf.set_len(self.read_buf.len() + n) };
        Poll::Ready(Ok(n))
    }

    /// Encodes into the recycled heap buffer; `poll_write` copies it on.
    fn encode(&mut self, head: &OutboundHeader, payload: &[u8], queue: &mut VecDeque<Bytes>) {
        let mut out = std::mem::take(&mut self.write_buffer);
        out.clear();
        append_frame_range(&mut out, 0, head, payload);
        queue.push_back(out.freeze());
    }

    fn poll_write_queue(
        &mut self,
        cx: &mut Context<'_>,
        queue: &mut VecDeque<Bytes>,
    ) -> Poll<Result<(), WebSocketError>> {
        while let Some(frame) = queue.front() {
            if self.write_pos == frame.len() {
                let frame = queue.pop_front().unwrap();
                if let Ok(mut buffer) = frame.try_into_mut() {
                    buffer.clear();
                    if buffer.capacity() > self.write_buffer.capacity() {
                        self.write_buffer = buffer;
                    }
                }
                self.write_pos = 0;
                continue;
            }
            let n = match ready!(Pin::new(&mut self.io).poll_write(cx, &frame[self.write_pos..])) {
                Ok(0) => {
                    return Poll::Ready(Err(WebSocketError::Io(std::io::ErrorKind::WriteZero)));
                }
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(WebSocketError::Io(e.kind()))),
            };
            self.write_pos += n;
        }
        Poll::Ready(Ok(()))
    }
}

/// Frame parsing over a sequence of received chunks, without first copying
/// them into one buffer.
///
/// A frame whose payload lies within one chunk is returned as a slice of
/// that chunk. Only bytes that straddle a chunk boundary are copied: a
/// split header (at most [`MAX_INBOUND_HEADER`] bytes) into `head`, a split
/// payload into one buffer of exactly its size. The copy is made as the
/// chunks arrive, so a large payload never pins more than one received
/// packet buffer at a time.
struct ChunkReader {
    /// The unparsed rest of the latest chunk. Empty whenever
    /// [`next_frame`](Self::next_frame) returns `None`.
    chunk: Bytes,
    state: RecvState,
}

/// Where [`ChunkReader`] stands within the current frame.
enum RecvState {
    /// Expecting a frame header. `head[..filled]` is the start of a header
    /// that straddles a chunk boundary; `filled == 0` means none is pending
    /// and the next header is parsed in place from the chunk.
    Header {
        head: [u8; MAX_INBOUND_HEADER],
        filled: usize,
    },
    /// The header is parsed and the payload straddles chunks: it is being
    /// assembled in `payload`, with `remaining` bytes still to come.
    Payload {
        fin: bool,
        opcode: u8,
        payload: BytesMut,
        remaining: usize,
    },
}

impl RecvState {
    const START: RecvState = RecvState::Header {
        head: [0; MAX_INBOUND_HEADER],
        filled: 0,
    };
}

impl ChunkReader {
    /// A reader whose first input is `leftover`: what hyper read past the
    /// 101 response head.
    fn new(leftover: Bytes) -> Self {
        ChunkReader {
            chunk: leftover,
            state: RecvState::START,
        }
    }

    /// Supplies the next received chunk, once `next_frame` has asked for
    /// more input.
    fn push(&mut self, chunk: Bytes) {
        debug_assert!(
            self.chunk.is_empty(),
            "chunk pushed before the last was used"
        );
        self.chunk = chunk;
    }

    /// The next complete frame, or `None` once the current chunk is used up
    /// and more input is needed. Enforces the same rules as
    /// [`try_parse_frame`].
    fn next_frame(&mut self) -> Result<Option<RawFrame>, WebSocketError> {
        let header = match &mut self.state {
            RecvState::Payload {
                payload, remaining, ..
            } => {
                let n = (*remaining).min(self.chunk.len());
                payload.extend_from_slice(&self.chunk[..n]);
                self.chunk.advance(n);
                *remaining -= n;
                if *remaining > 0 {
                    return Ok(None);
                }
                let RecvState::Payload {
                    fin,
                    opcode,
                    payload,
                    ..
                } = std::mem::replace(&mut self.state, RecvState::START)
                else {
                    unreachable!("matched Payload above");
                };
                return Ok(Some(RawFrame {
                    fin,
                    opcode,
                    payload: payload.freeze(),
                }));
            }
            RecvState::Header { head, filled } if *filled == 0 => {
                match parse_header(&self.chunk)? {
                    Some(header) => {
                        self.chunk.advance(header.header_len);
                        header
                    }
                    None => {
                        // Too short for a header (so under
                        // MAX_INBOUND_HEADER bytes): keep it for the next
                        // chunk to complete.
                        let n = self.chunk.len();
                        head[..n].copy_from_slice(&self.chunk);
                        *filled = n;
                        self.chunk = Bytes::new();
                        return Ok(None);
                    }
                }
            }
            RecvState::Header { head, filled } => loop {
                if let Some(header) = parse_header(&head[..*filled])? {
                    break header;
                }
                if self.chunk.is_empty() {
                    return Ok(None);
                }
                // Take just the header's bytes, so the payload that follows
                // stays in the chunk to be sliced.
                let n = (header_len_hint(&head[..*filled]) - *filled).min(self.chunk.len());
                head[*filled..*filled + n].copy_from_slice(&self.chunk[..n]);
                self.chunk.advance(n);
                *filled += n;
            },
        };
        self.state = RecvState::START;

        if self.chunk.len() >= header.payload_len {
            return Ok(Some(RawFrame {
                fin: header.fin,
                opcode: header.opcode,
                payload: self.chunk.split_to(header.payload_len),
            }));
        }
        let mut payload = BytesMut::with_capacity(header.payload_len);
        payload.extend_from_slice(&self.chunk);
        let remaining = header.payload_len - self.chunk.len();
        self.chunk = Bytes::new();
        self.state = RecvState::Payload {
            fin: header.fin,
            opcode: header.opcode,
            payload,
            remaining,
        };
        Ok(None)
    }
}

struct RawFrame {
    fin: bool,
    opcode: u8,
    payload: Bytes,
}

/// A parsed inbound frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboundHeader {
    fin: bool,
    opcode: u8,
    header_len: usize,
    payload_len: usize,
}

/// Parses the frame header at the front of `buf`, or `Ok(None)` if more
/// bytes are needed. Enforces client-side rules: RSV bits clear (no
/// extensions were negotiated), server frames unmasked, and the frame size
/// limit -- each as soon as the bytes that decide it are present.
fn parse_header(buf: &[u8]) -> Result<Option<InboundHeader>, WebSocketError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    if b0 & 0x70 != 0 {
        return Err(WebSocketError::ReservedBitsSet);
    }
    if b1 & 0x80 != 0 {
        return Err(WebSocketError::MaskedServerFrame);
    }

    let (header_len, payload_len) = match (b1 & 0x7F) as usize {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (4, u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let len = u64::from_be_bytes(buf[2..10].try_into().expect("10 bytes checked"));
            if len > MAX_FRAME as u64 {
                return Err(WebSocketError::FrameTooLarge);
            }
            (10, len as usize)
        }
        n => (2, n),
    };
    if payload_len > MAX_FRAME {
        return Err(WebSocketError::FrameTooLarge);
    }
    Ok(Some(InboundHeader {
        fin: b0 & 0x80 != 0,
        opcode: b0 & 0x0F,
        header_len,
        payload_len,
    }))
}

/// The full length of the header that `head` begins, as far as its bytes
/// tell: 2 until the length byte is known.
fn header_len_hint(head: &[u8]) -> usize {
    match head.get(1).map(|b1| b1 & 0x7F) {
        Some(126) => 4,
        Some(127) => 10,
        _ => 2,
    }
}

/// Parses one complete frame off the front of `buf`, or `Ok(None)` if more
/// bytes are needed (leaving `buf` untouched). See [`parse_header`] for the
/// rules enforced.
fn try_parse_frame(buf: &mut BytesMut) -> Result<Option<RawFrame>, WebSocketError> {
    let Some(header) = parse_header(buf)? else {
        return Ok(None);
    };
    if buf.len() < header.header_len + header.payload_len {
        return Ok(None);
    }
    buf.advance(header.header_len);
    let payload = buf.split_to(header.payload_len).freeze();
    Ok(Some(RawFrame {
        fin: header.fin,
        opcode: header.opcode,
        payload,
    }))
}

/// An encoded outbound frame header, with its masking key.
struct OutboundHeader {
    bytes: [u8; MAX_OUTBOUND_HEADER],
    len: usize,
    mask: [u8; 4],
}

impl OutboundHeader {
    /// FIN set (messages are never fragmented on the wire), the MASK bit
    /// and key (client frames must be masked, RFC 6455 §5.3).
    fn new(opcode: u8, payload_len: usize, mask: [u8; 4]) -> Self {
        let mut bytes = [0u8; MAX_OUTBOUND_HEADER];
        bytes[0] = 0x80 | opcode;
        let mut len = 2;
        if payload_len <= 125 {
            bytes[1] = 0x80 | payload_len as u8;
        } else if payload_len <= u16::MAX as usize {
            bytes[1] = 0x80 | 126;
            bytes[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
            len = 4;
        } else {
            bytes[1] = 0x80 | 127;
            bytes[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
            len = 10;
        }
        bytes[len..len + 4].copy_from_slice(&mask);
        OutboundHeader {
            bytes,
            len: len + 4,
            mask,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }
}

/// Writes bytes `offset..offset + dst.len()` of the encoded frame (header,
/// then masked payload) into `dst`, initializing all of it. Producing any
/// range lets a frame be written block by block into DMA memory, each byte
/// written once.
fn write_frame_range(
    dst: &mut [MaybeUninit<u8>],
    offset: usize,
    head: &OutboundHeader,
    payload: &[u8],
) {
    let head_bytes = head.as_slice();
    let mut dst = dst;
    let mut pos = offset;
    if pos < head_bytes.len() {
        let n = (head_bytes.len() - pos).min(dst.len());
        for (d, &b) in dst[..n].iter_mut().zip(&head_bytes[pos..pos + n]) {
            d.write(b);
        }
        dst = &mut dst[n..];
        pos += n;
        if dst.is_empty() {
            // The range ends within the header (e.g. a DMA block with only
            // a few bytes of room left).
            return;
        }
    }
    let at = pos - head_bytes.len();
    let len = dst.len();
    mask_into(dst, &payload[at..at + len], head.mask, at);
}

/// Appends bytes `offset..` of the encoded frame to `out`, in one pass.
fn append_frame_range(out: &mut BytesMut, offset: usize, head: &OutboundHeader, payload: &[u8]) {
    let n = head.len() + payload.len() - offset;
    out.reserve(n);
    let start = out.len();
    write_frame_range(&mut out.spare_capacity_mut()[..n], offset, head, payload);
    // SAFETY: `write_frame_range` initialized all `n` reserved bytes.
    unsafe { out.set_len(start + n) };
}

/// `dst[i] = src[i] ^ mask[(phase + i) % 4]`: the masking transform
/// (RFC 6455 §5.3) for a payload range starting at payload offset `phase`.
/// Eight bytes at a time; 8 is a multiple of the 4-byte key, so the key's
/// phase is the same at the start of every word.
fn mask_into(dst: &mut [MaybeUninit<u8>], src: &[u8], mask: [u8; 4], phase: usize) {
    debug_assert_eq!(dst.len(), src.len());
    let key: [u8; 4] = std::array::from_fn(|i| mask[(phase + i) & 3]);
    let word = u64::from_ne_bytes([
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
    ]);
    let mut dst_words = dst.chunks_exact_mut(8);
    let mut src_words = src.chunks_exact(8);
    for (d, s) in (&mut dst_words).zip(&mut src_words) {
        let masked = u64::from_ne_bytes(s.try_into().expect("8-byte chunk")) ^ word;
        for (d, b) in d.iter_mut().zip(masked.to_ne_bytes()) {
            d.write(b);
        }
    }
    for (i, (d, &b)) in dst_words
        .into_remainder()
        .iter_mut()
        .zip(src_words.remainder())
        .enumerate()
    {
        d.write(b ^ key[i & 3]);
    }
}

/// Views initialized memory as possibly-uninitialized, for the writers
/// above.
fn as_uninit(bytes: &mut [u8]) -> &mut [MaybeUninit<u8>] {
    // SAFETY: same layout; the writers above only ever store initialized
    // bytes through the view, so `bytes` stays initialized.
    unsafe { &mut *(bytes as *mut [u8] as *mut [MaybeUninit<u8>]) }
}

fn into_data_message(opcode: u8, payload: Bytes) -> Result<Message, WebSocketError> {
    if opcode == OP_TEXT {
        // Text messages must be valid UTF-8 (RFC 6455 §5.6); invalid data
        // fails the connection. `Message::Text` owns a `String`, so a view
        // of received data is copied here; a payload this side assembled
        // (uniquely owned) becomes the String's buffer as-is.
        let text =
            String::from_utf8(Vec::from(payload)).map_err(|_| WebSocketError::InvalidUtf8Text)?;
        Ok(Message::Text(text))
    } else {
        Ok(Message::Binary(payload))
    }
}

/// Control frames must not be fragmented and carry at most 125 bytes
/// (RFC 6455 §5.5).
fn validate_control(frame: &RawFrame) -> Result<(), WebSocketError> {
    if !frame.fin {
        return Err(WebSocketError::FragmentedControlFrame);
    }
    check_control_len(&frame.payload)
}

fn check_control_len(payload: &[u8]) -> Result<(), WebSocketError> {
    if payload.len() > 125 {
        return Err(WebSocketError::ControlFrameTooLarge);
    }
    Ok(())
}

/// Close payloads are empty, or a 2-byte code plus an optional UTF-8
/// reason (RFC 6455 §5.5.1).
fn parse_close_payload(payload: &[u8]) -> Result<Option<CloseFrame>, WebSocketError> {
    match payload.len() {
        0 => Ok(None),
        1 => Err(WebSocketError::MalformedClosePayload),
        _ => Ok(Some(CloseFrame {
            code: u16::from_be_bytes([payload[0], payload[1]]),
            reason: String::from_utf8(payload[2..].to_vec())
                .map_err(|_| WebSocketError::InvalidUtf8CloseReason)?,
        })),
    }
}

/// The expected `Sec-WebSocket-Accept` for `key`: base64(SHA-1(key ||
/// GUID)) per RFC 6455 §4.2.2. SHA-1 is what the RFC mandates here (it
/// binds request to response; it isn't used for security), hence ring's
/// legacy-use digest.
fn accept_key(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    base64(digest.as_ref())
}

/// Standard base64 with padding (RFC 4648). Hand-rolled: the handshake
/// only needs encode, which isn't worth a dependency.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = u32::from_be_bytes([
            0,
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ]);
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Requires `headers[name]` to contain `token` in its comma-separated
/// token list, case-insensitively (how Upgrade/Connection are matched).
/// Reports `missing` if the header is absent and `mismatch` if it's present
/// but lacks the token.
fn require_token(
    headers: &http::HeaderMap,
    name: &header::HeaderName,
    token: &str,
    missing: WebSocketError,
    mismatch: WebSocketError,
) -> Result<(), WebSocketError> {
    let value = headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(missing)?;
    if value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
    {
        Ok(())
    } else {
        Err(mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn accept_key_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn parse_unmasked_text_frame() {
        // FIN | text, 5-byte payload "hello".
        let mut buf = BytesMut::from(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o'][..]);
        let frame = try_parse_frame(&mut buf).unwrap().unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, OP_TEXT);
        assert_eq!(&frame.payload[..], b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn parse_extended_length_frame() {
        let payload = vec![0xAB; 300];
        let mut buf = BytesMut::new();
        buf.put_u8(0x82); // FIN | binary
        buf.put_u8(126);
        buf.put_u16(300);
        buf.put_slice(&payload);
        let frame = try_parse_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, OP_BINARY);
        assert_eq!(frame.payload.len(), 300);
    }

    #[test]
    fn parse_needs_more_bytes() {
        // Header promises 5 bytes; only 2 present.
        let mut buf = BytesMut::from(&[0x81, 0x05, b'h', b'e'][..]);
        assert!(try_parse_frame(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 4); // untouched
    }

    #[test]
    fn masked_server_frame_rejected() {
        let mut buf = BytesMut::from(&[0x81, 0x85, 1, 2, 3, 4, 0, 0, 0, 0, 0][..]);
        assert!(try_parse_frame(&mut buf).is_err());
    }

    #[test]
    fn close_payload_parsing() {
        assert_eq!(parse_close_payload(&[]).unwrap(), None);
        assert!(parse_close_payload(&[0x03]).is_err());
        let frame = parse_close_payload(&[0x03, 0xE8, b'b', b'y', b'e'])
            .unwrap()
            .unwrap();
        assert_eq!(frame.code, 1000);
        assert_eq!(frame.reason, "bye");
    }

    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use http_body_util::Empty;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf, simplex};

    /// The raw server end of a [`pair`]: what the client wrote, and where
    /// to write server frames.
    struct Server {
        from_client: ReadHalf<SimplexStream>,
        to_client: WriteHalf<SimplexStream>,
    }

    impl Server {
        /// Reads one masked client frame (payload < 126 bytes) and returns
        /// (opcode, unmasked payload).
        async fn read_frame(&mut self) -> (u8, Vec<u8>) {
            let mut head = [0u8; 6];
            self.from_client.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0] & 0x80, 0x80, "FIN set");
            assert_eq!(head[1] & 0x80, 0x80, "client frames are masked");
            let len = (head[1] & 0x7F) as usize;
            assert!(len < 126);
            let mut payload = vec![0u8; len];
            self.from_client.read_exact(&mut payload).await.unwrap();
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= head[2 + (i & 3)];
            }
            (head[0] & 0x0F, payload)
        }
    }

    /// A client over in-memory pipes, upgraded through a real hyper
    /// HTTP/1.1 exchange so `io` is the same `Upgraded` that `open` yields.
    /// The client-to-server pipe holds only `write_capacity` bytes, so
    /// larger client frames are written in pieces.
    async fn pair(write_capacity: usize) -> (WebSocketClient, Server) {
        let (from_client, client_tx) = simplex(write_capacity);
        let (client_rx, to_client) = simplex(64 * 1024);
        let mut server = Server {
            from_client,
            to_client,
        };

        let io = TokioIo::new(tokio::io::join(client_rx, client_tx));
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .unwrap();
        tokio::spawn(conn.with_upgrades());

        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "test")
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .body(Empty::new())
            .unwrap();
        let accept = async {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.from_client.read_u8().await.unwrap());
            }
            server
                .to_client
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
        };
        let (response, ()) = tokio::join!(sender.send_request(request), accept);
        let mut response = response.unwrap();
        let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
        let (handshake, _) = response.into_parts();
        let ws = WebSocketClient::from_upgraded(upgraded, SystemRandom::new(), None, handshake);
        (ws, server)
    }

    /// Bounds a step that would hang on a regression.
    async fn within<F: Future>(fut: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .expect("timed out")
    }

    /// A `poll_next` that returns Pending part-way through writing the
    /// automatic Pong must finish that Pong on the next poll -- not drop
    /// it (corrupting the stream) and not lose the Ping.
    #[tokio::test]
    async fn interrupted_auto_pong_is_finished_on_next_poll() {
        // The 106-byte Pong can't fit in the 32-byte pipe in one go.
        let (mut ws, mut server) = pair(32).await;
        let ping = [0x5Au8; 100];
        let mut frames = vec![0x89, 100];
        frames.extend_from_slice(&ping);
        frames.extend_from_slice(&[0x81, 5]);
        frames.extend_from_slice(b"after");
        server.to_client.write_all(&frames).await.unwrap();

        // First poll: Ping parsed, Pong partly written, then blocked.
        assert!(futures::poll!(ws.next()).is_pending());

        // The server drains the Pong while the client keeps polling.
        let (message, (opcode, payload)) =
            within(async { tokio::join!(ws.next(), server.read_frame()) }).await;
        assert_eq!(
            message,
            Some(Ok(Message::Ping(Bytes::copy_from_slice(&ping))))
        );
        assert_eq!(opcode, OP_PONG);
        assert_eq!(payload, ping);

        assert_eq!(
            within(ws.next()).await,
            Some(Ok(Message::Text("after".into())))
        );
    }

    /// The same for the Close echo, after which the stream ends.
    #[tokio::test]
    async fn interrupted_close_echo_is_finished_on_next_poll() {
        let (mut ws, mut server) = pair(4).await;
        // Close 1000 "bye": a 9-byte echo frame (code only, masked).
        server
            .to_client
            .write_all(&[0x88, 5, 0x03, 0xE8, b'b', b'y', b'e'])
            .await
            .unwrap();
        assert!(futures::poll!(ws.next()).is_pending());

        let (message, (opcode, payload)) =
            within(async { tokio::join!(ws.next(), server.read_frame()) }).await;
        assert_eq!(
            message,
            Some(Ok(Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "bye".into()
            }))))
        );
        assert_eq!(opcode, OP_CLOSE);
        assert_eq!(payload, [0x03, 0xE8]);
        assert_eq!(within(ws.next()).await, None);
    }

    /// Sink and Stream share the write path: frames go out whole and in
    /// order, and `send` after `close` fails.
    #[tokio::test]
    async fn sink_frames_go_out_whole_and_in_order() {
        let (mut ws, mut server) = pair(8).await;
        let reader = async {
            let mut got = Vec::new();
            for _ in 0..3 {
                got.push(server.read_frame().await);
            }
            got
        };
        let writer = async {
            ws.send(Message::Text("one".into())).await.unwrap();
            ws.send(Message::Binary(Bytes::from_static(&[2; 40])))
                .await
                .unwrap();
            SinkExt::close(&mut ws).await.unwrap();
        };
        let ((), got) = within(async { tokio::join!(writer, reader) }).await;
        assert_eq!(
            got,
            vec![
                (OP_TEXT, b"one".to_vec()),
                (OP_BINARY, vec![2; 40]),
                (OP_CLOSE, vec![]),
            ]
        );
        assert_eq!(
            ws.send(Message::Text("late".into())).await,
            Err(WebSocketError::SendAfterClose)
        );
    }

    // ---- The upgraded (TLS) fallback is what in-memory pipes get. ----

    #[tokio::test]
    async fn non_tcp_upgrades_fall_back_to_the_copying_transport() {
        let (ws, _server) = pair(64).await;
        assert!(matches!(ws.io, Transport::Upgraded(_)));
    }

    // ---- Frame encoding. ----

    /// The straightforward masking transform, to check the word-wise one.
    fn naive_mask(src: &[u8], mask: [u8; 4], phase: usize) -> Vec<u8> {
        src.iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[(phase + i) % 4])
            .collect()
    }

    fn masked(src: &[u8], mask: [u8; 4], phase: usize) -> Vec<u8> {
        let mut out = vec![0u8; src.len()];
        mask_into(as_uninit(&mut out), src, mask, phase);
        out
    }

    #[test]
    fn word_wise_masking_matches_the_rfc_transform() {
        let mask = [0x37, 0xFA, 0x21, 0x3D];
        let src: Vec<u8> = (0..64u8).collect();
        for phase in 0..8 {
            for len in 0..src.len() {
                assert_eq!(
                    masked(&src[..len], mask, phase),
                    naive_mask(&src[..len], mask, phase),
                    "phase {phase} len {len}"
                );
            }
        }
        // RFC 6455 §5.7: "Hello" masked with 37 fa 21 3d.
        assert_eq!(masked(b"Hello", mask, 0), [0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    }

    /// The whole frame, encoded in one go.
    fn encode_whole(head: &OutboundHeader, payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        append_frame_range(&mut out, 0, head, payload);
        out.to_vec()
    }

    #[test]
    fn frame_written_in_pieces_equals_frame_written_whole() {
        // As when a frame spans DMA blocks: every split point, for each
        // header size, gives the same bytes as writing it whole.
        let mask = [1, 2, 3, 4];
        for len in [0usize, 5, 125, 126, 300, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let head = OutboundHeader::new(OP_BINARY, len, mask);
            let whole = encode_whole(&head, &payload);
            let total = whole.len();
            let splits: Vec<usize> = if total < 400 {
                (0..=total).collect()
            } else {
                (0..20).chain([total / 2, total - 3, total]).collect()
            };
            for split in splits {
                let mut pieces = vec![0u8; total];
                let (a, b) = pieces.split_at_mut(split);
                write_frame_range(as_uninit(a), 0, &head, &payload);
                write_frame_range(as_uninit(b), split, &head, &payload);
                assert!(pieces == whole, "len {len} split {split}");
            }
        }
    }

    // ---- The zero-copy TCP transport. ----

    use crate::dpdk::tcp::worker::{CmdRx, Command, Inbound, InboundTx};

    /// The worker's ends of a test [`TcpStream`]'s rings.
    struct Wire {
        cmd_rx: CmdRx,
        inbound_tx: InboundTx,
    }

    impl Wire {
        fn push(&self, chunk: Bytes) {
            assert!(self.inbound_tx.push(Inbound::Data(chunk)).is_ok());
        }

        /// Everything the client has sent so far, concatenated.
        fn sent(&self) -> Vec<u8> {
            let mut out = Vec::new();
            while let Some(cmd) = self.cmd_rx.pop() {
                if let Command::Send(bytes) = cmd {
                    out.extend_from_slice(&bytes);
                }
            }
            out
        }
    }

    /// Decodes masked client frames (any length) into (opcode, payload),
    /// checking FIN and the MASK bit.
    fn decode_client_frames(mut wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = Vec::new();
        while !wire.is_empty() {
            assert_eq!(wire[0] & 0x80, 0x80, "FIN set");
            assert_eq!(wire[1] & 0x80, 0x80, "client frames are masked");
            let (len, at) = match wire[1] & 0x7F {
                126 => (u16::from_be_bytes([wire[2], wire[3]]) as usize, 4),
                127 => (
                    u64::from_be_bytes(wire[2..10].try_into().unwrap()) as usize,
                    10,
                ),
                n => (n as usize, 2),
            };
            let mask: [u8; 4] = wire[at..at + 4].try_into().unwrap();
            let payload = naive_mask(&wire[at + 4..at + 4 + len], mask, 0);
            frames.push((wire[0] & 0x0F, payload));
            wire = &wire[at + 4 + len..];
        }
        frames
    }

    fn handshake_parts() -> http::response::Parts {
        http::Response::new(()).into_parts().0
    }

    /// A client on the TCP transport with no worker behind it; `leftover`
    /// plays the bytes hyper read past the 101 head.
    fn tcp_client(leftover: Bytes) -> (WebSocketClient, Wire) {
        let (stream, cmd_rx, inbound_tx, _credit) = TcpStream::test_stream();
        let io = Transport::Tcp(TcpTransport {
            stream,
            reader: ChunkReader::new(leftover),
        });
        let ws = WebSocketClient::with_transport(io, SystemRandom::new(), None, handshake_parts());
        (ws, Wire { cmd_rx, inbound_tx })
    }

    fn poll_message(ws: &mut WebSocketClient) -> Poll<Result<Option<Message>, WebSocketError>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        ws.poll_recv(&mut cx)
    }

    fn recv_now(ws: &mut WebSocketClient) -> Message {
        match poll_message(ws) {
            Poll::Ready(Ok(Some(message))) => message,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// An unmasked server frame.
    fn server_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![first];
        match payload.len() {
            n if n <= 125 => out.push(n as u8),
            n if n <= u16::MAX as usize => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    fn binary_payload(message: Message) -> Bytes {
        match message {
            Message::Binary(payload) => payload,
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn payloads_within_a_chunk_are_views_of_it() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        let mut bytes = server_frame(0x82, b"hello");
        bytes.extend(server_frame(0x82, &[9; 300]));
        let chunk = Bytes::from(bytes);
        wire.push(chunk.clone());

        let first = binary_payload(recv_now(&mut ws));
        assert_eq!(&first[..], b"hello");
        assert_eq!(first.as_ptr(), chunk[2..].as_ptr());
        let second = binary_payload(recv_now(&mut ws));
        assert_eq!(&second[..], &[9; 300]);
        assert_eq!(second.as_ptr(), chunk[7 + 4..].as_ptr());
        assert!(poll_message(&mut ws).is_pending());
    }

    #[test]
    fn a_split_header_is_copied_but_its_payload_is_not() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        // A 4-byte header split 3 + 1, the payload whole in the second chunk.
        let frame = server_frame(0x82, &[5; 200]);
        wire.push(Bytes::copy_from_slice(&frame[..3]));
        let second = Bytes::copy_from_slice(&frame[3..]);
        wire.push(second.clone());
        let payload = binary_payload(recv_now(&mut ws));
        assert_eq!(&payload[..], &[5; 200]);
        assert_eq!(payload.as_ptr(), second[1..].as_ptr());
    }

    #[test]
    fn a_split_payload_is_assembled_once() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        let payload: Vec<u8> = (0..100).collect();
        let frame = server_frame(0x82, &payload);
        for piece in [&frame[..10], &frame[10..50], &frame[50..]] {
            wire.push(Bytes::copy_from_slice(piece));
        }
        assert_eq!(binary_payload(recv_now(&mut ws)), payload);
    }

    /// A mixed sequence of frames, cut into chunks at every pair of points
    /// (and byte by byte), parses to the same messages every time.
    #[test]
    fn frames_parse_the_same_however_the_stream_is_chunked() {
        let mut stream = Vec::new();
        stream.extend(server_frame(0x82, b""));
        stream.extend(server_frame(0x81, "héllo".as_bytes()));
        stream.extend(server_frame(0x02, b"frag-"));
        stream.extend(server_frame(0x80, b"mented"));
        stream.extend(server_frame(0x82, &[3; 126]));
        stream.extend(server_frame(0x8A, b"pong"));
        stream.extend(server_frame(0x82, &[4; 125]));
        let expected = vec![
            Message::Binary(Bytes::new()),
            Message::Text("héllo".into()),
            Message::Binary(Bytes::from_static(b"frag-mented")),
            Message::Binary(Bytes::from(vec![3; 126])),
            Message::Pong(Bytes::from_static(b"pong")),
            Message::Binary(Bytes::from(vec![4; 125])),
        ];

        let check = |chunks: Vec<&[u8]>| {
            let (mut ws, wire) = tcp_client(Bytes::new());
            let mut got = Vec::new();
            for chunk in chunks {
                wire.push(Bytes::copy_from_slice(chunk));
                while let Poll::Ready(message) = poll_message(&mut ws) {
                    got.push(message.unwrap().unwrap());
                }
            }
            assert_eq!(got, expected);
        };
        let n = stream.len();
        for a in 0..=n {
            for b in (a..=n).step_by(7) {
                check(vec![&stream[..a], &stream[a..b], &stream[b..]]);
            }
        }
        check(stream.chunks(1).collect());
    }

    #[test]
    fn a_large_frame_straddling_many_chunks_is_assembled() {
        // 70 000 bytes: a 64-bit length, in MSS-sized segments.
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let frame = server_frame(0x82, &payload);
        let (mut ws, wire) = tcp_client(Bytes::new());
        let mut got = None;
        for segment in frame.chunks(1448) {
            wire.push(Bytes::copy_from_slice(segment));
            if let Poll::Ready(message) = poll_message(&mut ws) {
                got = Some(binary_payload(message.unwrap().unwrap()));
            }
        }
        assert_eq!(got.unwrap(), payload);
    }

    #[test]
    fn leftover_bytes_from_the_handshake_are_parsed_first() {
        // Hyper's read held one whole frame and half the next header.
        let mut leftover = server_frame(0x82, b"early");
        let next = server_frame(0x82, &[7; 130]);
        leftover.extend_from_slice(&next[..1]);
        let leftover = Bytes::from(leftover);
        let (mut ws, wire) = tcp_client(leftover.clone());

        let first = binary_payload(recv_now(&mut ws));
        assert_eq!(&first[..], b"early");
        assert_eq!(first.as_ptr(), leftover[2..].as_ptr());
        assert!(poll_message(&mut ws).is_pending());

        let rest = Bytes::copy_from_slice(&next[1..]);
        wire.push(rest.clone());
        let second = binary_payload(recv_now(&mut ws));
        assert_eq!(&second[..], &[7; 130]);
        assert_eq!(second.as_ptr(), rest[3..].as_ptr());
    }

    #[test]
    fn protocol_violations_fail_even_mid_split_header() {
        for (bytes, error) in [
            (vec![0xC2], WebSocketError::ReservedBitsSet),
            (vec![0x82], WebSocketError::MaskedServerFrame),
            (vec![0x82], WebSocketError::FrameTooLarge),
        ] {
            let (mut ws, wire) = tcp_client(Bytes::from(bytes));
            assert!(poll_message(&mut ws).is_pending());
            let rest: &[u8] = match &error {
                WebSocketError::ReservedBitsSet => &[0x00],
                WebSocketError::MaskedServerFrame => &[0x81, 0, 0, 0, 0, 0],
                _ => &[127, 0, 0, 0, 0, 0x01, 0, 0, 1],
            };
            wire.push(Bytes::copy_from_slice(rest));
            assert!(matches!(poll_message(&mut ws), Poll::Ready(Err(e)) if e == error));
        }
    }

    #[test]
    fn sends_are_masked_and_go_out_in_order() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        let sizes = [0usize, 1, 7, 8, 9, 125, 126, 65_535, 65_536];
        futures::executor::block_on(async {
            for &n in &sizes {
                let payload: Vec<u8> = (0..n).map(|i| (i % 253) as u8).collect();
                ws.send(Message::Binary(Bytes::from(payload)))
                    .await
                    .unwrap();
            }
            ws.send(Message::Text("done".into())).await.unwrap();
        });
        let frames = decode_client_frames(&wire.sent());
        assert_eq!(frames.len(), sizes.len() + 1);
        for (&n, (opcode, payload)) in sizes.iter().zip(&frames) {
            assert_eq!(*opcode, OP_BINARY);
            assert_eq!(payload.len(), n);
            assert!(
                payload
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == (i % 253) as u8)
            );
        }
        assert_eq!(frames[sizes.len()], (OP_TEXT, b"done".to_vec()));
    }

    #[test]
    fn a_send_stalled_on_credit_resumes_where_it_stopped() {
        use crate::dpdk::tcp::worker::SEND_CAPACITY;
        let (stream, cmd_rx, inbound_tx, credit) = TcpStream::test_stream();
        let io = Transport::Tcp(TcpTransport {
            stream,
            reader: ChunkReader::new(Bytes::new()),
        });
        let mut ws =
            WebSocketClient::with_transport(io, SystemRandom::new(), None, handshake_parts());
        let wire = Wire { cmd_rx, inbound_tx };
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let payload = Bytes::from(vec![0xEE; SEND_CAPACITY + 100]);
        Pin::new(&mut ws)
            .start_send(Message::Binary(payload.clone()))
            .unwrap();
        assert!(Pin::new(&mut ws).poll_flush(&mut cx).is_pending());
        let mut sent = wire.sent();
        // The worker acknowledges what it has.
        credit
            .bytes
            .fetch_sub(SEND_CAPACITY, std::sync::atomic::Ordering::AcqRel);
        assert!(matches!(
            Pin::new(&mut ws).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        sent.extend(wire.sent());
        assert_eq!(
            decode_client_frames(&sent),
            vec![(OP_BINARY, payload.to_vec())]
        );
    }

    #[test]
    fn pings_are_answered_over_tcp_before_they_are_returned() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        wire.push(Bytes::from(server_frame(0x89, b"are you there")));
        assert_eq!(
            recv_now(&mut ws),
            Message::Ping(Bytes::from_static(b"are you there"))
        );
        assert_eq!(
            decode_client_frames(&wire.sent()),
            vec![(OP_PONG, b"are you there".to_vec())]
        );
    }

    #[test]
    fn a_peer_close_over_tcp_is_echoed_and_ends_the_stream() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        wire.push(Bytes::from(server_frame(
            0x88,
            &[0x03, 0xE8, b'b', b'y', b'e'],
        )));
        assert_eq!(
            recv_now(&mut ws),
            Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "bye".into()
            }))
        );
        assert_eq!(
            decode_client_frames(&wire.sent()),
            vec![(OP_CLOSE, vec![0x03, 0xE8])]
        );
        assert!(matches!(poll_message(&mut ws), Poll::Ready(Ok(None))));
        assert_eq!(
            futures::executor::block_on(ws.send(Message::Text("late".into()))),
            Err(WebSocketError::SendAfterClose)
        );
    }

    #[test]
    fn eof_over_tcp_without_a_close_is_unclean() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        // Half a frame, then the peer's FIN.
        wire.push(Bytes::from_static(&[0x82, 5, b'h']));
        assert!(wire.inbound_tx.push(Inbound::Eof).is_ok());
        assert!(matches!(
            poll_message(&mut ws),
            Poll::Ready(Err(WebSocketError::UncleanClose))
        ));
    }

    #[test]
    fn a_reset_over_tcp_surfaces_as_an_io_error() {
        let (mut ws, wire) = tcp_client(Bytes::new());
        assert!(wire.inbound_tx.push(Inbound::Reset).is_ok());
        assert!(matches!(
            poll_message(&mut ws),
            Poll::Ready(Err(WebSocketError::Io(std::io::ErrorKind::ConnectionReset)))
        ));
    }

    /// The whole path `open` takes for `ws://`: a hyper HTTP/1.1 upgrade
    /// over a real `TcpStream`, then the downcast back to it. The server's
    /// first frame arrives in the same chunk as the 101, so hyper reads it
    /// past the head and it must come back through `read_buf`.
    #[tokio::test]
    async fn a_plaintext_upgrade_recovers_the_tcp_stream_and_its_leftover() {
        let (stream, cmd_rx, inbound_tx, _credit) = TcpStream::test_stream();
        let server = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                match cmd_rx.pop() {
                    Some(Command::Send(bytes)) => head.extend_from_slice(&bytes),
                    Some(_) => {}
                    None => tokio::task::yield_now().await,
                }
            }
            let mut reply = b"HTTP/1.1 101 Switching Protocols\r\n\
                Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .to_vec();
            reply.extend(server_frame(0x81, b"welcome"));
            assert!(inbound_tx.push(Inbound::Data(Bytes::from(reply))).is_ok());
            Wire { cmd_rx, inbound_tx }
        });

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(conn.with_upgrades());
        let request = Request::builder()
            .uri("/")
            .header(header::HOST, "test")
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .body(Empty::new())
            .unwrap();
        let mut response = within(sender.send_request(request)).await.unwrap();
        let upgraded = within(hyper::upgrade::on(&mut response)).await.unwrap();
        let wire = within(server).await.unwrap();

        let mut ws =
            WebSocketClient::from_upgraded(upgraded, SystemRandom::new(), None, handshake_parts());
        let Transport::Tcp(tcp) = &ws.io else {
            panic!("a plaintext upgrade must run on the raw TcpStream");
        };
        assert!(
            !tcp.reader.chunk.is_empty(),
            "hyper read the frame past the head"
        );

        assert_eq!(
            within(ws.recv()).await.unwrap(),
            Some(Message::Text("welcome".into()))
        );
        within(ws.send(Message::Binary(Bytes::from_static(b"hi"))))
            .await
            .unwrap();
        assert_eq!(
            decode_client_frames(&wire.sent()),
            vec![(OP_BINARY, b"hi".to_vec())]
        );
    }
}

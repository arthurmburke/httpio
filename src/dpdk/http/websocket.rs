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

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The IO the frames run over: the connection hyper handed back after the
/// 101, re-wrapped for tokio.
type WsIo = TokioIo<Upgraded>;

// The message types are the generic ones from the transport-agnostic
// `http::websocket` module; re-exported here so callers holding a [`Ws`]
// can name them without reaching across modules.
pub use crate::http::websocket::{CloseFrame, Message};

/// An established WebSocket connection.
pub struct WebSocketClient {
    io: WsIo,
    rng: SystemRandom,
    /// Raw inbound bytes not yet parsed into frames.
    read_buf: BytesMut,
    /// In-progress fragmented message: (data opcode, accumulated payload).
    fragment: Option<(u8, BytesMut)>,
    close_sent: bool,
    close_received: bool,
    /// The subprotocol the server selected from the request's offers.
    protocol: Option<String>,
    /// The `101 Switching Protocols` response parts (status, headers,
    /// extensions), kept for callers that need e.g. `Set-Cookie`.
    handshake: http::response::Parts,
    /// Outgoing frames, already masked and encoded, in wire order: Sink
    /// messages plus automatic replies (Pong, Close echo) queued while
    /// reading. Only the front frame may be partly written.
    write_queue: VecDeque<Bytes>,
    /// Bytes of the front frame already written.
    write_pos: usize,
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
        match uri.scheme_str() {
            Some("ws" | "wss") => {}
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

    /// Wraps a connection whose opening handshake has been validated.
    fn from_upgraded(
        upgraded: Upgraded,
        rng: SystemRandom,
        protocol: Option<String>,
        handshake: http::response::Parts,
    ) -> Self {
        WebSocketClient {
            io: TokioIo::new(upgraded),
            rng,
            read_buf: BytesMut::with_capacity(8 * 1024),
            fragment: None,
            close_sent: false,
            close_received: false,
            protocol,
            handshake,
            write_queue: VecDeque::new(),
            write_pos: 0,
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
        if self.close_sent {
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
            if self.ready_message.is_some() || (self.close_sent && self.close_received) {
                ready!(self.poll_flush_writes(cx))?;
                // `None` here is the end of a completed close handshake.
                return Poll::Ready(Ok(self.ready_message.take()));
            }

            if let Some(frame) = try_parse_frame(&mut self.read_buf)? {
                let queued = self.write_queue.len();
                match self.handle_frame(frame)? {
                    Some(message) if self.write_queue.len() > queued => {
                        self.ready_message = Some(message);
                    }
                    Some(message) => return Poll::Ready(Ok(Some(message))),
                    None => {}
                }
                continue;
            }

            if ready!(self.poll_fill_read_buf(cx))? == 0 {
                // EOF. Clean only if the close handshake got at least our
                // half out (some peers close TCP without echoing Close).
                if self.close_received || self.close_sent {
                    return Poll::Ready(Ok(None));
                }
                return Poll::Ready(Err(WebSocketError::UncleanClose));
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
                self.fragment = Some((frame.opcode, BytesMut::from(&frame.payload[..])));
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
                if !self.close_sent {
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
                self.close_received = true;
                // Echo the close (same code) if the peer initiated.
                if !self.close_sent {
                    let echo: Bytes = if frame.payload.len() >= 2 {
                        frame.payload.slice(..2)
                    } else {
                        Bytes::new()
                    };
                    self.close_sent = true;
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
        let frame = self.encode_frame(opcode, payload)?;
        self.write_queue.push_back(frame);
        Ok(())
    }

    fn encode_frame(&self, opcode: u8, payload: &[u8]) -> Result<Bytes, WebSocketError> {
        let mut mask = [0u8; 4];
        self.rng.fill(&mut mask).map_err(|_| WebSocketError::Rng)?;

        let n = payload.len();
        let mut out = BytesMut::with_capacity(14 + n);

        // FIN | opcode
        out.put_u8(0x80 | opcode);

        if n <= 125 {
            out.put_u8(0x80 | n as u8);
        } else if n <= u16::MAX as usize {
            out.put_u8(0x80 | 126);
            out.put_u16(n as u16);
        } else {
            out.put_u8(0x80 | 127);
            out.put_u64(n as u64);
        }

        out.put_slice(&mask);

        let start = out.len();
        out.put_slice(payload);

        for (i, byte) in out[start..].iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }

        Ok(out.freeze())
    }

    /// Writes the queued frames out, whole and in order (no flush).
    fn poll_write_queue(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketError>> {
        while let Some(frame) = self.write_queue.front() {
            if self.write_pos == frame.len() {
                self.write_queue.pop_front();
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

    /// Writes every queued frame, then flushes the transport.
    fn poll_flush_writes(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketError>> {
        ready!(self.poll_write_queue(cx))?;
        Pin::new(&mut self.io)
            .poll_flush(cx)
            .map_err(|e| WebSocketError::Io(e.kind()))
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
        if this.close_sent {
            return Poll::Ready(Err(WebSocketError::SendAfterClose));
        }
        // One-frame buffer: everything queued before (including automatic
        // replies) must be written before another message is accepted.
        this.poll_write_queue(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.close_sent {
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
                this.close_sent = true;
                this.queue_frame(OP_CLOSE, &payload)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_flush_writes(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.close_sent = true;
            this.queue_frame(OP_CLOSE, &[])?;
        }
        this.poll_flush_writes(cx)
    }
}

struct RawFrame {
    fin: bool,
    opcode: u8,
    payload: Bytes,
}

/// Parses one complete frame off the front of `buf`, or `Ok(None)` if more
/// bytes are needed. Enforces client-side rules: RSV bits clear (no
/// extensions were negotiated) and server frames unmasked.
fn try_parse_frame(buf: &mut BytesMut) -> Result<Option<RawFrame>, WebSocketError> {
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
    if buf.len() < header_len + payload_len {
        return Ok(None);
    }

    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    buf.advance(header_len);
    let payload = buf.split_to(payload_len).freeze();
    Ok(Some(RawFrame {
        fin,
        opcode,
        payload,
    }))
}

fn into_data_message(opcode: u8, payload: Bytes) -> Result<Message, WebSocketError> {
    if opcode == OP_TEXT {
        // Text messages must be valid UTF-8 (RFC 6455 §5.6); invalid data
        // fails the connection.
        let text =
            String::from_utf8(payload.to_vec()).map_err(|_| WebSocketError::InvalidUtf8Text)?;
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
}

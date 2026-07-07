//! WebSocket client (RFC 6455) over this crate's HTTP client and DPDK TCP
//! stream.
//!
//! The opening handshake is an HTTP/1.1 GET + `Upgrade: websocket` sent
//! through [`HttpClient::h1_upgrade_request`], so it inherits the client's
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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Request, StatusCode, Uri, header};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::client::{Error, HttpClient};

/// Upper bound on a single inbound frame's payload.
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Upper bound on a reassembled (fragmented) inbound message.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The IO the frames run over: the connection hyper handed back after the
/// 101, re-wrapped for tokio.
type WsIo = TokioIo<Upgraded>;

/// A complete WebSocket message (inbound fragmentation already
/// reassembled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Bytes),
    /// Surfaced for observability; a Pong reply has already been sent
    /// automatically.
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<CloseFrame>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

impl HttpClient {
    /// Opens a WebSocket connection to a `ws://` or `wss://` URL.
    ///
    /// Corking is not allowed for WebSocket connections; the underlying
    /// TCP connection is always `nodelay: true, cork: false`.
    pub async fn websocket(&self, url: &str) -> Result<WebSocket, Error> {
        let uri: Uri = url.parse()?;
        match uri.scheme_str() {
            Some("ws" | "wss") => {}
            other => {
                return Err(format!(
                    "unsupported WebSocket scheme {other:?} (use ws:// or wss://)"
                )
                .into());
            }
        }

        // Sec-WebSocket-Key: 16 random bytes, base64 (RFC 6455 §4.1).
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 16];
        rng.fill(&mut key_bytes)
            .map_err(|_| "system RNG failure generating Sec-WebSocket-Key")?;
        let key = base64(&key_bytes);

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .header(header::SEC_WEBSOCKET_KEY, key.as_str())
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .body(Bytes::new())?;

        let response = self.h1_upgrade_request(request).await?;

        // Validate the server's half of the handshake (RFC 6455 §4.1).
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(format!(
                "WebSocket handshake failed: expected 101 Switching Protocols, got {}",
                response.status()
            )
            .into());
        }
        require_token(response.headers(), &header::UPGRADE, "websocket")?;
        require_token(response.headers(), &header::CONNECTION, "upgrade")?;
        let accept = response
            .headers()
            .get(header::SEC_WEBSOCKET_ACCEPT)
            .and_then(|v| v.to_str().ok())
            .ok_or("WebSocket handshake response is missing Sec-WebSocket-Accept")?;
        if accept != accept_key(&key) {
            return Err("Sec-WebSocket-Accept does not match the sent key".into());
        }
        // We offered no subprotocols, so the server must not select one.
        if response
            .headers()
            .contains_key(header::SEC_WEBSOCKET_PROTOCOL)
        {
            return Err("server selected a subprotocol that was not offered".into());
        }

        let upgraded = hyper::upgrade::on(response).await?;
        Ok(WebSocket {
            io: TokioIo::new(upgraded),
            rng,
            read_buf: BytesMut::with_capacity(8 * 1024),
            fragment: None,
            close_sent: false,
            close_received: false,
        })
    }
}

/// An established WebSocket connection.
pub struct WebSocket {
    io: WsIo,
    rng: SystemRandom,
    /// Raw inbound bytes not yet parsed into frames.
    read_buf: BytesMut,
    /// In-progress fragmented message: (data opcode, accumulated payload).
    fragment: Option<(u8, BytesMut)>,
    close_sent: bool,
    close_received: bool,
}

impl WebSocket {
    /// Receives the next message. `Ok(None)` means the connection ended
    /// cleanly (close handshake completed, or EOF after a close). Inbound
    /// Pings are answered automatically and also returned.
    pub async fn recv(&mut self) -> Result<Option<Message>, Error> {
        loop {
            if self.close_sent && self.close_received {
                return Ok(None);
            }
            while let Some(frame) = try_parse_frame(&mut self.read_buf)? {
                if let Some(message) = self.handle_frame(frame).await? {
                    return Ok(Some(message));
                }
            }
            let n = self.io.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                // EOF. Clean only if the close handshake got at least our
                // half out (some peers close TCP without echoing Close).
                if self.close_received || self.close_sent {
                    return Ok(None);
                }
                return Err("connection closed without a Close frame".into());
            }
        }
    }

    /// Sends one message (never fragmented on the wire; sizes up to the
    /// frame maximum go out as a single frame).
    pub async fn send(&mut self, message: Message) -> Result<(), Error> {
        if self.close_sent {
            return Err("websocket is closing or closed".into());
        }
        match message {
            Message::Text(text) => self.write_frame(OP_TEXT, text.as_bytes()).await,
            Message::Binary(data) => self.write_frame(OP_BINARY, &data).await,
            Message::Ping(data) => {
                check_control_len(&data)?;
                self.write_frame(OP_PING, &data).await
            }
            Message::Pong(data) => {
                check_control_len(&data)?;
                self.write_frame(OP_PONG, &data).await
            }
            Message::Close(frame) => self.close(frame).await,
        }
    }

    /// Starts (or completes) the closing handshake. After this, `send`
    /// fails and `recv` keeps delivering anything already in flight until
    /// the peer's Close (or EOF) arrives.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> Result<(), Error> {
        if self.close_sent {
            return Ok(());
        }
        let mut payload = BytesMut::new();
        if let Some(frame) = frame {
            payload.put_u16(frame.code);
            payload.put_slice(frame.reason.as_bytes());
            check_control_len(&payload)?;
        }
        // Mark before writing so a transport error can't leave us able to
        // "close" twice.
        self.close_sent = true;
        self.write_frame(OP_CLOSE, &payload).await
    }

    /// Applies one parsed frame; returns a `Message` when one is complete.
    async fn handle_frame(&mut self, frame: RawFrame) -> Result<Option<Message>, Error> {
        match frame.opcode {
            OP_TEXT | OP_BINARY => {
                if self.fragment.is_some() {
                    return Err("new data frame arrived inside a fragmented message".into());
                }
                if frame.fin {
                    return Ok(Some(into_data_message(frame.opcode, frame.payload)?));
                }
                self.fragment = Some((frame.opcode, BytesMut::from(&frame.payload[..])));
                Ok(None)
            }
            OP_CONTINUATION => {
                let Some((_, buffered)) = self.fragment.as_mut() else {
                    return Err("continuation frame without a started message".into());
                };
                if buffered.len() + frame.payload.len() > MAX_MESSAGE {
                    return Err("fragmented message exceeds the maximum message size".into());
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
                    self.write_frame(OP_PONG, &frame.payload).await?;
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
                    self.write_frame(OP_CLOSE, &echo).await?;
                }
                Ok(Some(Message::Close(close_frame)))
            }
            other => Err(format!("unknown WebSocket opcode {other:#x}").into()),
        }
    }

    /// Writes one masked frame (client frames must be masked, RFC 6455
    /// §5.3) and flushes.
    async fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Error> {
        let mut mask = [0u8; 4];
        self.rng
            .fill(&mut mask)
            .map_err(|_| "system RNG failure generating mask")?;

        let n = payload.len();
        let mut out = BytesMut::with_capacity(14 + n);
        out.put_u8(0x80 | opcode); // FIN | opcode: sends are never fragmented
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

        self.io.write_all(&out).await?;
        self.io.flush().await?;
        Ok(())
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
fn try_parse_frame(buf: &mut BytesMut) -> Result<Option<RawFrame>, Error> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    if b0 & 0x70 != 0 {
        return Err("RSV bits set but no extension was negotiated".into());
    }
    if b1 & 0x80 != 0 {
        return Err("server-to-client frame is masked".into());
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
                return Err("frame exceeds the maximum frame size".into());
            }
            (10, len as usize)
        }
        n => (2, n),
    };
    if payload_len > MAX_FRAME {
        return Err("frame exceeds the maximum frame size".into());
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

fn into_data_message(opcode: u8, payload: Bytes) -> Result<Message, Error> {
    if opcode == OP_TEXT {
        // Text messages must be valid UTF-8 (RFC 6455 §5.6); invalid data
        // fails the connection.
        let text = String::from_utf8(payload.to_vec())
            .map_err(|_| "text message contains invalid UTF-8")?;
        Ok(Message::Text(text))
    } else {
        Ok(Message::Binary(payload))
    }
}

/// Control frames must not be fragmented and carry at most 125 bytes
/// (RFC 6455 §5.5).
fn validate_control(frame: &RawFrame) -> Result<(), Error> {
    if !frame.fin {
        return Err("control frame is fragmented".into());
    }
    check_control_len(&frame.payload)
}

fn check_control_len(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > 125 {
        return Err("control frame payload exceeds 125 bytes".into());
    }
    Ok(())
}

/// Close payloads are empty, or a 2-byte code plus an optional UTF-8
/// reason (RFC 6455 §5.5.1).
fn parse_close_payload(payload: &[u8]) -> Result<Option<CloseFrame>, Error> {
    match payload.len() {
        0 => Ok(None),
        1 => Err("close frame payload of one byte is invalid".into()),
        _ => Ok(Some(CloseFrame {
            code: u16::from_be_bytes([payload[0], payload[1]]),
            reason: String::from_utf8(payload[2..].to_vec())
                .map_err(|_| "close reason contains invalid UTF-8")?,
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
fn require_token(
    headers: &http::HeaderMap,
    name: &header::HeaderName,
    token: &str,
) -> Result<(), Error> {
    let value = headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("WebSocket handshake response is missing {name}"))?;
    if value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
    {
        Ok(())
    } else {
        Err(format!("WebSocket handshake response {name} does not include {token:?}").into())
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
}

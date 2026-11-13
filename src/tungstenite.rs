//! WebSocket client over the kernel network stack, using tokio-tungstenite,
//! behind the same [`WebSocket`] trait as the DPDK client.
//!
//! [`TungsteniteWebSocket`] wraps a tokio-tungstenite [`WebSocketStream`]
//! and translates at the edges: tungstenite's messages become this crate's
//! [`Message`]/[`CloseFrame`], and its errors become [`WebSocketError`]
//! (mapped onto the same variants the DPDK client reports wherever the
//! cause is the same). Code generic over [`WebSocket`] therefore runs
//! unchanged on either backend:
//!
//! ```no_run
//! use futures::{SinkExt, StreamExt};
//! use httpio::http::errors::WebSocketError;
//! use httpio::http::websocket::{Message, WebSocket};
//!
//! async fn echo_once<W: WebSocket>(client: &W::Client) -> Result<(), WebSocketError> {
//!     let uri = "wss://echo.example.com/".parse().unwrap();
//!     let mut ws = W::open(client, uri, Default::default(), Default::default()).await?;
//!     ws.send(Message::Text("hello".into())).await?;
//!     let _reply = ws.next().await;
//!     ws.close().await
//! }
//! ```
//!
//! Behavior matches the DPDK client (Pings auto-answered and surfaced,
//! peer Close echoed, `None` from the stream once the close handshake
//! completes, `UncleanClose` on EOF without one), with one difference
//! inherited from tungstenite: if the request offers subprotocols and the
//! server selects none, the handshake fails (the DPDK client accepts it
//! and reports `protocol() == None`).

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, Stream, ready};
use http::{Extensions, HeaderMap, HeaderValue, Uri, header};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_with_config,
    tungstenite::{
        self as tg,
        client::IntoClientRequest,
        error::{CapacityError, ProtocolError, SubProtocolError, UrlError},
        handshake::client::Response,
        protocol::{CloseFrame as TgCloseFrame, WebSocketConfig},
    },
};

use crate::http::{
    errors::{HttpError, WebSocketError},
    websocket::{CloseFrame, Message, WebSocket},
};

/// Connection settings for [`TungsteniteWebSocket::open`]: the
/// [`WebSocket::Client`] of the tungstenite backend. Cheap to clone and
/// reusable across connections.
#[derive(Debug, Clone)]
pub struct TungsteniteClient {
    tls: Arc<rustls::ClientConfig>,
    config: Option<WebSocketConfig>,
    nodelay: bool,
}

impl TungsteniteClient {
    /// TLS against the Mozilla (webpki) roots, tungstenite's default
    /// limits, and `TCP_NODELAY` on (WebSocket traffic is interactive; this
    /// matches the DPDK client, which always dials `nodelay`).
    pub fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // No ALPN: the handshake is HTTP/1.1 only.
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TungsteniteClient {
            tls: Arc::new(tls),
            config: None,
            nodelay: true,
        }
    }

    /// Replaces the TLS configuration used for `wss://` (e.g. one trusting
    /// custom CAs). It must not offer `h2` via ALPN: the WebSocket handshake
    /// is HTTP/1.1.
    pub fn tls_config(mut self, tls: Arc<rustls::ClientConfig>) -> Self {
        self.tls = tls;
        self
    }

    /// Sets tungstenite's limits and buffer sizes (max message/frame size,
    /// write buffering) for every connection opened with this client. A
    /// [`WebSocketConfig`] in `open`'s extensions overrides it for that
    /// connection.
    pub fn websocket_config(mut self, config: WebSocketConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets `TCP_NODELAY` on new connections (default: on).
    pub fn nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }
}

impl Default for TungsteniteClient {
    fn default() -> Self {
        Self::new()
    }
}

/// An established WebSocket connection driven by tokio-tungstenite.
///
/// `S` is the byte stream underneath; [`WebSocket::open`] produces the
/// default, a kernel TCP socket with optional TLS. Any other already
/// handshaken tokio-tungstenite stream can be wrapped with
/// [`from_parts`](Self::from_parts) and gets the same `Stream`/`Sink`
/// translation.
pub struct TungsteniteWebSocket<S = MaybeTlsStream<TcpStream>> {
    inner: WebSocketStream<S>,
    handshake: http::response::Parts,
}

impl<S> TungsteniteWebSocket<S> {
    /// Wraps a tokio-tungstenite stream whose client handshake has
    /// completed, along with the handshake response it returned.
    pub fn from_parts(inner: WebSocketStream<S>, response: Response) -> Self {
        let (handshake, _body) = response.into_parts();
        TungsteniteWebSocket { inner, handshake }
    }

    /// The underlying tokio-tungstenite stream.
    pub fn get_ref(&self) -> &WebSocketStream<S> {
        &self.inner
    }

    /// The underlying tokio-tungstenite stream, mutably. Messages sent or
    /// received through it bypass this wrapper's translation.
    pub fn get_mut(&mut self) -> &mut WebSocketStream<S> {
        &mut self.inner
    }

    /// Unwraps the underlying tokio-tungstenite stream.
    pub fn into_inner(self) -> WebSocketStream<S> {
        self.inner
    }
}

/// `open` dials the URI's host over a kernel TCP socket (DNS via the
/// system resolver; TLS for `wss://` through the client's rustls config)
/// and runs tungstenite's client handshake.
///
/// `extensions` are attached to the handshake request; a [`WebSocketConfig`]
/// among them overrides the client's for this connection.
impl WebSocket for TungsteniteWebSocket {
    type Client = TungsteniteClient;

    async fn open(
        client: &TungsteniteClient,
        uri: Uri,
        headers: HeaderMap<HeaderValue>,
        extensions: Extensions,
    ) -> Result<Self, WebSocketError> {
        let config = extensions
            .get::<WebSocketConfig>()
            .copied()
            .or(client.config);
        let tls = matches!(uri.scheme_str(), Some("wss"));
        let request = handshake_request(uri, headers, extensions)?;

        let host = request
            .uri()
            .host()
            .ok_or(WebSocketError::Upgrade(HttpError::MissingHost))?;
        // IPv6 literals come bracketed in URIs, but not as socket addresses.
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = request
            .uri()
            .port_u16()
            .unwrap_or(if tls { 443 } else { 80 });

        let socket = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| WebSocketError::Upgrade(HttpError::Connect(e.kind())))?;
        if client.nodelay {
            socket
                .set_nodelay(true)
                .map_err(|e| WebSocketError::Upgrade(HttpError::Connect(e.kind())))?;
        }

        // TLS here rather than inside tungstenite, so a failed TLS
        // handshake is reported as one (not as a generic I/O error).
        let stream = if tls {
            let server_name = ServerName::try_from(host)
                .map_err(|_| WebSocketError::Upgrade(HttpError::InvalidHost))?;
            let tls_stream = TlsConnector::from(client.tls.clone())
                .connect(server_name, socket)
                .await
                .map_err(|e| WebSocketError::Upgrade(HttpError::TlsHandshake(e.kind())))?;
            MaybeTlsStream::Rustls(tls_stream)
        } else {
            MaybeTlsStream::Plain(socket)
        };

        let (inner, response) = client_async_with_config(request, stream, config)
            .await
            .map_err(handshake_error)?;
        Ok(Self::from_parts(inner, response))
    }

    fn protocol(&self) -> Option<&str> {
        // tungstenite has already checked the selection against the offers.
        self.handshake
            .headers
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    }

    fn handshake(&self) -> &http::response::Parts {
        &self.handshake
    }
}

impl<S> Stream for TungsteniteWebSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<Message, WebSocketError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // tokio-tungstenite already yields `None` (not an error) once
            // the close handshake has completed.
            let item = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => Err(frame_error(e)),
                Some(Ok(message)) => match from_tungstenite(message) {
                    Some(message) => Ok(message),
                    // Raw frames are never yielded by reads; skip if one is.
                    None => continue,
                },
            };
            return Poll::Ready(Some(item));
        }
    }
}

impl<S> Sink<Message> for TungsteniteWebSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Error = WebSocketError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(frame_error)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        let message = to_tungstenite(message)?;
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(frame_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(frame_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(frame_error)
    }
}

/// Builds tungstenite's handshake request: the protocol-mandated fields
/// (and a fresh `Sec-WebSocket-Key`) from tungstenite, everything else from
/// the caller, as the DPDK client does.
fn handshake_request(
    uri: Uri,
    mut headers: HeaderMap<HeaderValue>,
    extensions: Extensions,
) -> Result<tg::handshake::client::Request, WebSocketError> {
    match uri.scheme_str() {
        Some("ws" | "wss") => {}
        _ => return Err(WebSocketError::UnsupportedScheme),
    }
    let mut request = uri.into_client_request().map_err(handshake_error)?;
    for mandated in [
        header::UPGRADE,
        header::CONNECTION,
        header::SEC_WEBSOCKET_KEY,
        header::SEC_WEBSOCKET_VERSION,
    ] {
        headers.remove(mandated);
    }
    // Caller headers replace same-named generated ones (only `Host` is
    // left to collide) and keep all their values.
    request.headers_mut().extend(headers);
    *request.extensions_mut() = extensions;
    Ok(request)
}

/// Converts a received tungstenite message; `None` for a raw frame.
fn from_tungstenite(message: tg::Message) -> Option<Message> {
    Some(match message {
        tg::Message::Text(text) => Message::Text(text.as_str().to_owned()),
        tg::Message::Binary(data) => Message::Binary(data),
        tg::Message::Ping(data) => Message::Ping(data),
        tg::Message::Pong(data) => Message::Pong(data),
        tg::Message::Close(frame) => Message::Close(frame.map(|f| CloseFrame {
            code: f.code.into(),
            reason: f.reason.as_str().to_owned(),
        })),
        tg::Message::Frame(_) => return None,
    })
}

/// Converts an outgoing message, rejecting oversized control payloads up
/// front with the same error the DPDK client gives.
fn to_tungstenite(message: Message) -> Result<tg::Message, WebSocketError> {
    let check_control = |len: usize| {
        if len > 125 {
            Err(WebSocketError::ControlFrameTooLarge)
        } else {
            Ok(())
        }
    };
    Ok(match message {
        Message::Text(text) => tg::Message::Text(text.into()),
        Message::Binary(data) => tg::Message::Binary(data),
        Message::Ping(data) => {
            check_control(data.len())?;
            tg::Message::Ping(data)
        }
        Message::Pong(data) => {
            check_control(data.len())?;
            tg::Message::Pong(data)
        }
        Message::Close(frame) => {
            if let Some(frame) = &frame {
                check_control(2 + frame.reason.len())?;
            }
            tg::Message::Close(frame.map(|f| TgCloseFrame {
                code: f.code.into(),
                reason: f.reason.into(),
            }))
        }
    })
}

/// Maps an error from the opening handshake: as [`frame_error`], plus the
/// failures only the handshake can produce.
fn handshake_error(e: tg::Error) -> WebSocketError {
    match e {
        tg::Error::Http(response) => WebSocketError::UnexpectedStatus(response.status()),
        tg::Error::HttpFormat(_) => WebSocketError::Upgrade(HttpError::MalformedRequest),
        tg::Error::Url(UrlError::UnsupportedUrlScheme | UrlError::TlsFeatureNotEnabled) => {
            WebSocketError::UnsupportedScheme
        }
        tg::Error::Url(UrlError::NoHostName | UrlError::EmptyHostName) => {
            WebSocketError::Upgrade(HttpError::MissingHost)
        }
        tg::Error::Url(UrlError::NoPathOrQuery) => WebSocketError::Upgrade(HttpError::MalformedUri),
        tg::Error::Protocol(e) => match e {
            ProtocolError::WrongHttpMethod => WebSocketError::MethodNotGet,
            ProtocolError::MissingUpgradeWebSocketHeader => WebSocketError::BadUpgradeHeader,
            ProtocolError::MissingConnectionUpgradeHeader => WebSocketError::BadConnectionHeader,
            ProtocolError::SecWebSocketAcceptKeyMismatch => WebSocketError::AcceptMismatch,
            ProtocolError::SecWebSocketSubProtocolError(
                SubProtocolError::InvalidSubProtocol
                | SubProtocolError::ServerSentSubProtocolNoneRequested,
            ) => WebSocketError::UnofferedSubprotocol,
            ProtocolError::HandshakeIncomplete => WebSocketError::UpgradeIncomplete,
            ProtocolError::HttparseError(_) | ProtocolError::WrongHttpVersion => {
                WebSocketError::Upgrade(HttpError::Protocol)
            }
            other => frame_error(tg::Error::Protocol(other)),
        },
        other => frame_error(other),
    }
}

/// Maps an error from an established connection onto the variants the
/// DPDK client reports for the same cause.
fn frame_error(e: tg::Error) -> WebSocketError {
    match e {
        tg::Error::Io(e) => WebSocketError::Io(e.kind()),
        tg::Error::AlreadyClosed => WebSocketError::SendAfterClose,
        tg::Error::Utf8(_) => WebSocketError::InvalidUtf8Text,
        tg::Error::Capacity(CapacityError::MessageTooLong { .. }) => {
            WebSocketError::MessageTooLarge
        }
        tg::Error::Protocol(e) => match e {
            ProtocolError::SendAfterClosing => WebSocketError::SendAfterClose,
            ProtocolError::ResetWithoutClosingHandshake => WebSocketError::UncleanClose,
            ProtocolError::NonZeroReservedBits => WebSocketError::ReservedBitsSet,
            ProtocolError::MaskedFrameFromServer => WebSocketError::MaskedServerFrame,
            ProtocolError::FragmentedControlFrame => WebSocketError::FragmentedControlFrame,
            ProtocolError::ControlFrameTooBig => WebSocketError::ControlFrameTooLarge,
            ProtocolError::UnknownControlFrameType(op)
            | ProtocolError::UnknownDataFrameType(op)
            | ProtocolError::InvalidOpcode(op) => WebSocketError::UnknownOpcode(op),
            ProtocolError::UnexpectedContinueFrame => WebSocketError::UnexpectedContinuation,
            ProtocolError::ExpectedFragment(_) => WebSocketError::UnexpectedDataFrame,
            ProtocolError::InvalidCloseSequence => WebSocketError::MalformedClosePayload,
            other => WebSocketError::Backend(other.to_string()),
        },
        other => WebSocketError::Backend(other.to_string()),
    }
}

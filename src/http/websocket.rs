use bytes::Bytes;
use futures::{Sink, Stream};
use http::{Extensions, HeaderMap, HeaderValue, Uri};

use crate::http::errors::WebSocketError;

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

/// A client-side WebSocket connection, independent of the transport and
/// implementation underneath it.
///
/// Implemented by the DPDK client
/// (`dpdk::http::websocket::WebSocketClient`) and by the tokio-tungstenite
/// client ([`TungsteniteWebSocket`](crate::tungstenite::TungsteniteWebSocket)),
/// so code written against this trait runs over either.
///
/// Messages are received through [`Stream`] (`None` once the connection has
/// ended cleanly) and sent through [`Sink`]. Inbound Pings are answered
/// automatically and still surfaced; a peer-initiated Close is echoed.
pub trait WebSocket:
    Stream<Item = Result<Message, WebSocketError>>
    + Sink<Message, Error = WebSocketError>
    + Unpin
    + Sized
{
    /// What [`open`](Self::open) connects through: the DPDK HTTP `Client`
    /// for the DPDK stack, or a
    /// [`TungsteniteClient`](crate::tungstenite::TungsteniteClient) for
    /// tokio-tungstenite.
    type Client;

    /// Opens a WebSocket connection to a `ws://` or `wss://` `uri`.
    ///
    /// `headers` are sent with the handshake request (e.g. `Authorization`,
    /// `Cookie`, `Origin`, or `Sec-WebSocket-Protocol` offers); the
    /// protocol-mandated fields (`Upgrade`, `Connection`,
    /// `Sec-WebSocket-Key`, `Sec-WebSocket-Version`) are always set by the
    /// implementation and override caller values. `extensions` carry
    /// implementation-specific per-connection options (see each
    /// implementation).
    ///
    /// If subprotocols are offered, the server's selection is validated
    /// against the offers and exposed via [`protocol`](Self::protocol).
    fn open(
        client: &Self::Client,
        uri: Uri,
        headers: HeaderMap<HeaderValue>,
        extensions: Extensions,
    ) -> impl Future<Output = Result<Self, WebSocketError>> + Send;

    /// The subprotocol the server selected from the handshake request's
    /// `Sec-WebSocket-Protocol` offers, if any.
    fn protocol(&self) -> Option<&str>;

    /// The `101 Switching Protocols` handshake response (status, headers,
    /// extensions) -- e.g. for reading `Set-Cookie`.
    fn handshake(&self) -> &http::response::Parts;
}

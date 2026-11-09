use bytes::Bytes;
use futures::{Sink, Stream};

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
pub trait WebSocket:
    Stream<Item = Result<Message, WebSocketError>> + Sink<Message, Error = WebSocketError> + Unpin
{
}

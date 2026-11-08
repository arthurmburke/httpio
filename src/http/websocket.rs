use bytes::Bytes;

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

use super::errors::WebSocketError;

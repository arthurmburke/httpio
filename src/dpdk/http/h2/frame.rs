//! HTTP/2 frame layout (RFC 9113 §4, §6): the nine-byte frame header, the
//! frame types and flags, settings identifiers and error codes.

use std::fmt;

/// Every frame starts with a header this long.
pub(super) const FRAME_HEADER_LEN: usize = 9;

/// Frame types (RFC 9113 §6).
pub(super) mod kind {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// Frame flags. Which apply depends on the frame type.
pub(super) mod flag {
    /// DATA, HEADERS.
    pub const END_STREAM: u8 = 0x1;
    /// SETTINGS, PING.
    pub const ACK: u8 = 0x1;
    /// HEADERS, CONTINUATION.
    pub const END_HEADERS: u8 = 0x4;
    /// DATA, HEADERS.
    pub const PADDED: u8 = 0x8;
    /// HEADERS.
    pub const PRIORITY: u8 = 0x20;
}

/// Settings identifiers (RFC 9113 §6.5.2).
pub(super) mod setting {
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// Largest flow-control window (RFC 9113 §6.9.1).
pub(super) const MAX_WINDOW: i64 = (1 << 31) - 1;

/// An HTTP/2 error code (RFC 9113 §7), as carried by RST_STREAM and
/// GOAWAY. Codes this implementation does not know are kept as they are.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Reason(pub u32);

impl Reason {
    pub const NO_ERROR: Reason = Reason(0x0);
    pub const PROTOCOL_ERROR: Reason = Reason(0x1);
    pub const INTERNAL_ERROR: Reason = Reason(0x2);
    pub const FLOW_CONTROL_ERROR: Reason = Reason(0x3);
    pub const SETTINGS_TIMEOUT: Reason = Reason(0x4);
    pub const STREAM_CLOSED: Reason = Reason(0x5);
    pub const FRAME_SIZE_ERROR: Reason = Reason(0x6);
    pub const REFUSED_STREAM: Reason = Reason(0x7);
    pub const CANCEL: Reason = Reason(0x8);
    pub const COMPRESSION_ERROR: Reason = Reason(0x9);
    pub const CONNECT_ERROR: Reason = Reason(0xa);
    pub const ENHANCE_YOUR_CALM: Reason = Reason(0xb);
    pub const INADEQUATE_SECURITY: Reason = Reason(0xc);
    pub const HTTP_1_1_REQUIRED: Reason = Reason(0xd);
}

impl fmt::Debug for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "PROTOCOL_ERROR",
            0x2 => "INTERNAL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "SETTINGS_TIMEOUT",
            0x5 => "STREAM_CLOSED",
            0x6 => "FRAME_SIZE_ERROR",
            0x7 => "REFUSED_STREAM",
            0x8 => "CANCEL",
            0x9 => "COMPRESSION_ERROR",
            0xa => "CONNECT_ERROR",
            0xb => "ENHANCE_YOUR_CALM",
            0xc => "INADEQUATE_SECURITY",
            0xd => "HTTP_1_1_REQUIRED",
            other => return write!(f, "Reason({other:#x})"),
        };
        f.write_str(name)
    }
}

/// A frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FrameHead {
    /// Payload length: 24 bits on the wire.
    pub len: u32,
    pub kind: u8,
    pub flags: u8,
    /// Stream identifier, without the reserved bit.
    pub stream: u32,
}

impl FrameHead {
    pub(super) fn parse(bytes: &[u8; FRAME_HEADER_LEN]) -> Self {
        Self {
            len: u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
            kind: bytes[3],
            flags: bytes[4],
            stream: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7fff_ffff,
        }
    }

    pub(super) fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let len = self.len.to_be_bytes();
        let stream = self.stream.to_be_bytes();
        [
            len[1], len[2], len[3], self.kind, self.flags, stream[0], stream[1], stream[2],
            stream[3],
        ]
    }

    pub(super) fn has(self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// A big-endian `u32` at the start of `bytes`.
pub(super) fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trips() {
        let head = FrameHead {
            len: 0x01_02_03,
            kind: kind::HEADERS,
            flags: flag::END_HEADERS | flag::END_STREAM,
            stream: 0x7fff_fffe,
        };
        let bytes = head.encode();
        assert_eq!(bytes, [1, 2, 3, 1, 5, 0x7f, 0xff, 0xff, 0xfe]);
        assert_eq!(FrameHead::parse(&bytes), head);
        // The reserved bit is ignored on receipt.
        let mut reserved = bytes;
        reserved[5] |= 0x80;
        assert_eq!(FrameHead::parse(&reserved), head);
    }
}

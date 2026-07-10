//! Descriptive, non-allocating error types for the HTTP client.
//!
//! These replace an opaque `Box<dyn Error>`: each is a plain `enum` returned
//! by value -- no heap allocation on the error path, and callers can `match`
//! on the exact cause instead of string-sniffing. Every variant documents
//! and (via [`Display`](std::fmt::Display)) describes what went wrong; the
//! few that wrap an underlying failure keep a `Copy` [`io::ErrorKind`] so the
//! reason survives without allocating.

use std::fmt;
use std::io;

use http::StatusCode;

use super::codec::CodecError;

/// Why an HTTP request -- or a WebSocket upgrade request -- could not be
/// completed. Returned by [`HttpClient`](crate::http::client::HttpClient).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// The request was malformed during construction. This can occur if the
    /// body cannot be written to the output.
    MalformedRequest,
    /// The request URI had no host. An absolute URI with a scheme and host
    /// (e.g. `https://example.com/path`) is required, since the URI is also
    /// what decides where to connect.
    MissingHost,
    /// The request URI (or a URL passed to `get`) was malformed: it could
    /// not be parsed, or could not be rewritten into HTTP/1.1 origin form.
    MalformedUri,
    /// The host cannot be used as an HTTP `Host` header value or as a TLS
    /// server name (e.g. it contains bytes disallowed in those positions).
    InvalidHost,
    /// A corked request was submitted without a `FlushHandle` in its
    /// extensions. Corking holds the request's final segment until a manual
    /// flush, so a handle to trigger that flush must be supplied.
    CorkWithoutFlushHandle,
    /// Corking was requested on a protocol-upgrade (WebSocket) connection,
    /// where it is forbidden: a held tail would stall the interactive
    /// protocol the upgrade hands the connection over to.
    CorkOnUpgrade,
    /// The host could not be resolved to an address. This stack has no DNS,
    /// so use an IP-literal URL or map the name to an address with the
    /// client builder's `resolve`.
    UnresolvedHost,
    /// The TCP connection to the origin could not be established; the
    /// [`io::ErrorKind`] gives the reason (e.g. `ConnectionRefused`,
    /// `TimedOut`).
    Connect(io::ErrorKind),
    /// The TLS handshake with the origin failed -- an untrusted or invalid
    /// certificate, a protocol mismatch, or a transport error mid-handshake
    /// (see the [`io::ErrorKind`]).
    TlsHandshake(io::ErrorKind),
    /// The HTTP protocol exchange with the origin failed: the HTTP/1.1 or
    /// HTTP/2 connection handshake, sending the request, or reading the
    /// response body.
    Protocol,
    /// The provided HeaderValue is invalid. Provides some context regarding
    /// why the header is invalid and what it was used for but does not include
    /// the exact header content.
    InvalidHeaderValue(&'static str),
    /// The request body could not be encoded, or the response body decoded,
    /// for its `Content-Type`; see the [`CodecError`].
    Codec(CodecError),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::MissingHost => f.write_str(
                "the request URI has no host; an absolute URI (scheme and host) is required",
            ),
            HttpError::MalformedUri => {
                f.write_str("the request URI is malformed and could not be parsed")
            }
            HttpError::InvalidHost => {
                f.write_str("the host is not a valid HTTP Host header value or TLS server name")
            }
            HttpError::CorkWithoutFlushHandle => f.write_str(
                "a corked request requires a FlushHandle in its extensions to release the \
                 held tail",
            ),
            HttpError::CorkOnUpgrade => {
                f.write_str("corking is not allowed on protocol-upgrade (WebSocket) connections")
            }
            HttpError::UnresolvedHost => f.write_str(
                "cannot resolve the host: this stack has no DNS -- use an IP-literal URL or map \
                 the name with the client builder's resolve()",
            ),
            HttpError::Connect(kind) => {
                write!(
                    f,
                    "could not establish the TCP connection to the origin: {kind}"
                )
            }
            HttpError::TlsHandshake(kind) => {
                write!(f, "the TLS handshake with the origin failed: {kind}")
            }
            HttpError::Protocol => f.write_str(
                "the HTTP protocol exchange with the origin failed (connection handshake, \
                 request, or response body)",
            ),
            HttpError::InvalidHeaderValue(reason) => {
                write!(f, "the provided header value is invalid: {}", reason)
            }
            HttpError::Codec(e) => write!(f, "body codec error: {e}"),
            HttpError::MalformedRequest => f.write_str("the http Request was malformed"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpError::Codec(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CodecError> for HttpError {
    fn from(e: CodecError) -> Self {
        HttpError::Codec(e)
    }
}

/// Why the HTTP client builder could not load a CA certificate bundle (its
/// `add_root_ca_pem` / `add_root_ca_pem_file` methods).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderError {
    /// The CA PEM file could not be read from disk; the [`io::ErrorKind`]
    /// gives the reason (e.g. `NotFound`, `PermissionDenied`).
    ReadFile(io::ErrorKind),
    /// The PEM input contained a certificate that could not be parsed.
    MalformedPem,
    /// A certificate parsed from the PEM input was rejected by the trust
    /// store (e.g. it is not a valid X.509 certificate).
    InvalidCertificate,
    /// The PEM input parsed successfully but contained no certificates.
    NoCertificates,
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuilderError::ReadFile(kind) => {
                write!(f, "could not read the CA PEM file: {kind}")
            }
            BuilderError::MalformedPem => {
                f.write_str("the PEM input contains a malformed certificate")
            }
            BuilderError::InvalidCertificate => {
                f.write_str("a certificate in the PEM input was rejected by the trust store")
            }
            BuilderError::NoCertificates => {
                f.write_str("no CA certificates were found in the PEM input")
            }
        }
    }
}

impl std::error::Error for BuilderError {}

/// Why a WebSocket connection could not be opened, or why a frame exchange
/// on an open connection failed. Returned by
/// [`WebSocket`](crate::http::websocket::WebSocket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketError {
    /// The handshake request URI scheme was not `ws` or `wss`.
    UnsupportedScheme,
    /// The handshake request used a method other than GET (RFC 6455 §4.1).
    MethodNotGet,
    /// The system random number generator failed while producing the
    /// `Sec-WebSocket-Key` or a frame's masking key.
    Rng,
    /// The underlying HTTP/1.1 upgrade request failed; see the [`HttpError`].
    Upgrade(HttpError),
    /// The server returned `101` but handing the connection over
    /// (`hyper::upgrade`) did not complete.
    UpgradeIncomplete,
    /// The handshake response status was not `101 Switching Protocols`.
    UnexpectedStatus(StatusCode),
    /// The handshake response was missing the `Upgrade` header.
    MissingUpgradeHeader,
    /// The handshake response `Upgrade` header did not name `websocket`.
    BadUpgradeHeader,
    /// The handshake response was missing the `Connection` header.
    MissingConnectionHeader,
    /// The handshake response `Connection` header did not include `upgrade`.
    BadConnectionHeader,
    /// The handshake response was missing the `Sec-WebSocket-Accept` header.
    MissingAcceptHeader,
    /// The `Sec-WebSocket-Accept` value did not match the key that was sent,
    /// so the peer did not complete a conforming handshake.
    AcceptMismatch,
    /// The `Sec-WebSocket-Protocol` response header was not valid UTF-8.
    InvalidProtocolHeader,
    /// The server selected a subprotocol that the request never offered
    /// (RFC 6455 §4.2.2).
    UnofferedSubprotocol,
    /// Reading from or writing to the upgraded connection failed; the
    /// [`io::ErrorKind`] gives the reason.
    Io(io::ErrorKind),
    /// The connection reached EOF without a WebSocket Close frame, before
    /// the closing handshake had been sent or received.
    UncleanClose,
    /// A message was sent after the connection had begun closing.
    SendAfterClose,
    /// A frame set a reserved (RSV) bit, but no extension was negotiated.
    ReservedBitsSet,
    /// A server-to-client frame was masked (only client frames are masked).
    MaskedServerFrame,
    /// An inbound frame's payload exceeded the maximum frame size.
    FrameTooLarge,
    /// A reassembled (fragmented) message exceeded the maximum message size.
    MessageTooLarge,
    /// A new data frame arrived while a fragmented message was in progress.
    UnexpectedDataFrame,
    /// A continuation frame arrived with no fragmented message in progress.
    UnexpectedContinuation,
    /// A control frame was fragmented (control frames must not be, §5.5).
    FragmentedControlFrame,
    /// A control frame payload exceeded 125 bytes (§5.5).
    ControlFrameTooLarge,
    /// A frame used an opcode this client does not recognize.
    UnknownOpcode(u8),
    /// A text message's payload was not valid UTF-8 (§5.6).
    InvalidUtf8Text,
    /// A Close frame carried a one-byte payload, which is invalid (§5.5.1).
    MalformedClosePayload,
    /// A Close frame's reason string was not valid UTF-8.
    InvalidUtf8CloseReason,
}

impl fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebSocketError::UnsupportedScheme => {
                f.write_str("the WebSocket URI scheme is not ws:// or wss://")
            }
            WebSocketError::MethodNotGet => {
                f.write_str("a WebSocket handshake request must use the GET method")
            }
            WebSocketError::Rng => f.write_str("the system random number generator failed"),
            WebSocketError::Upgrade(e) => write!(f, "the WebSocket upgrade request failed: {e}"),
            WebSocketError::UpgradeIncomplete => f.write_str(
                "the server accepted the upgrade but the connection handover did not complete",
            ),
            WebSocketError::UnexpectedStatus(status) => write!(
                f,
                "the WebSocket handshake response was {status}, not 101 Switching Protocols",
            ),
            WebSocketError::MissingUpgradeHeader => {
                f.write_str("the handshake response is missing the Upgrade header")
            }
            WebSocketError::BadUpgradeHeader => {
                f.write_str("the handshake response Upgrade header does not name \"websocket\"")
            }
            WebSocketError::MissingConnectionHeader => {
                f.write_str("the handshake response is missing the Connection header")
            }
            WebSocketError::BadConnectionHeader => {
                f.write_str("the handshake response Connection header does not include \"upgrade\"")
            }
            WebSocketError::MissingAcceptHeader => {
                f.write_str("the handshake response is missing the Sec-WebSocket-Accept header")
            }
            WebSocketError::AcceptMismatch => {
                f.write_str("the Sec-WebSocket-Accept value does not match the key that was sent")
            }
            WebSocketError::InvalidProtocolHeader => {
                f.write_str("the Sec-WebSocket-Protocol response header is not valid UTF-8")
            }
            WebSocketError::UnofferedSubprotocol => {
                f.write_str("the server selected a subprotocol that was not offered")
            }
            WebSocketError::Io(kind) => write!(f, "the WebSocket connection I/O failed: {kind}"),
            WebSocketError::UncleanClose => {
                f.write_str("the connection closed without a WebSocket Close frame")
            }
            WebSocketError::SendAfterClose => {
                f.write_str("cannot send: the WebSocket is closing or already closed")
            }
            WebSocketError::ReservedBitsSet => {
                f.write_str("a frame set a reserved bit, but no extension was negotiated")
            }
            WebSocketError::MaskedServerFrame => f.write_str("a server-to-client frame was masked"),
            WebSocketError::FrameTooLarge => {
                f.write_str("an inbound frame exceeded the maximum frame size")
            }
            WebSocketError::MessageTooLarge => {
                f.write_str("a fragmented message exceeded the maximum message size")
            }
            WebSocketError::UnexpectedDataFrame => {
                f.write_str("a new data frame arrived inside a fragmented message")
            }
            WebSocketError::UnexpectedContinuation => {
                f.write_str("a continuation frame arrived with no message in progress")
            }
            WebSocketError::FragmentedControlFrame => f.write_str("a control frame was fragmented"),
            WebSocketError::ControlFrameTooLarge => {
                f.write_str("a control frame payload exceeded 125 bytes")
            }
            WebSocketError::UnknownOpcode(opcode) => {
                write!(f, "a frame used an unknown WebSocket opcode {opcode:#x}")
            }
            WebSocketError::InvalidUtf8Text => {
                f.write_str("a text message contained invalid UTF-8")
            }
            WebSocketError::MalformedClosePayload => {
                f.write_str("a Close frame carried an invalid one-byte payload")
            }
            WebSocketError::InvalidUtf8CloseReason => {
                f.write_str("a Close frame reason contained invalid UTF-8")
            }
        }
    }
}

impl std::error::Error for WebSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WebSocketError::Upgrade(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HttpError> for WebSocketError {
    fn from(e: HttpError) -> Self {
        WebSocketError::Upgrade(e)
    }
}

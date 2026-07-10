//! Content-negotiated body codecs.
//!
//! Request and response bodies are generic: a value is encoded to bytes for
//! the wire, and response bytes are decoded back to a value, according to the
//! `Content-Type` header. Any `serde::Serialize` type can be a request body
//! and any `serde::de::DeserializeOwned` type a response body -- no wrapper:
//!
//! ```ignore
//! let resp: Response<User> = client.request(request_of::<User>()).await?;
//! ```
//!
//! Three marker types get special, serde-free handling (recognized by
//! [`TypeId`], so they need no wire format):
//!
//! - [`Empty`] -- no body. Encodes to zero bytes and needs no Content-Type;
//!   decoding ignores the response body. Use it for GETs and bodyless calls.
//! - [`Raw`] -- bytes as-is: encoding passes them straight through (the caller
//!   sets the Content-Type, typically `application/octet-stream`), and
//!   decoding captures the response body verbatim regardless of Content-Type.
//! - [`ByteStream`] -- a stream of byte chunks, unbuffered in both
//!   directions: encoding yields [`EncodedBody::Stream`] (the transport sends
//!   chunks as they arrive, without knowing the total length), and a response
//!   decoded into `ByteStream` hands over the body chunks as they are
//!   received instead of collecting them.
//!
//! Everything else dispatches on the Content-Type media type:
//! `application/json`, `application/xml`,
//! `application/x-www-form-urlencoded`, or `text/plain`.
//! `application/octet-stream` carries raw bytes, so it is served by [`Raw`]
//! or [`ByteStream`]; asking a serde value to encode as octet-stream is an
//! error.
//!
//! Because the marker types are matched by [`TypeId`], bodies must be
//! `'static` (an owned value, not a borrow).

use std::any::{Any, TypeId};
use std::fmt;
use std::pin::Pin;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use http::HeaderValue;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::errors::HttpError;

/// One of the supported body media types, parsed from a `Content-Type`
/// header (its media type only; parameters like `; charset=utf-8` are
/// ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `application/json`
    Json,
    /// `application/xml` (or `text/xml`)
    Xml,
    /// `application/x-www-form-urlencoded`
    Form,
    /// `text/plain`
    Text,
    /// `application/octet-stream`
    Octet,
}

impl ContentType {
    /// Parses the media type of a `Content-Type` header, or `None` if the
    /// header isn't valid text or names an unsupported media type.
    pub fn from_header(value: &HeaderValue) -> Option<Self> {
        let media = value.to_str().ok()?.split(';').next()?.trim();
        match media.to_ascii_lowercase().as_str() {
            "application/json" => Some(ContentType::Json),
            "application/xml" | "text/xml" => Some(ContentType::Xml),
            "application/x-www-form-urlencoded" => Some(ContentType::Form),
            "text/plain" => Some(ContentType::Text),
            "application/octet-stream" => Some(ContentType::Octet),
            _ => None,
        }
    }

    /// The canonical media-type string.
    pub fn as_str(self) -> &'static str {
        match self {
            ContentType::Json => "application/json",
            ContentType::Xml => "application/xml",
            ContentType::Form => "application/x-www-form-urlencoded",
            ContentType::Text => "text/plain",
            ContentType::Octet => "application/octet-stream",
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a body could not be encoded to, or decoded from, the wire. Descriptive
/// and non-allocating (the media type is a `Copy` [`ContentType`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// A body was supplied but no `Content-Type` header was set (request) or
    /// present (response), so there is no format to (de)serialize against.
    MissingContentType,
    /// The `Content-Type` is not one of the supported media types.
    UnsupportedContentType,
    /// Serializing the value to the given content type failed (e.g. the
    /// shape isn't representable in that format).
    Encode(ContentType),
    /// Deserializing the value from the given content type failed (malformed
    /// input, or it didn't match the target type).
    Decode(ContentType),
    /// `application/octet-stream` was requested for a serde value; raw bytes
    /// go through the [`Raw`] body type instead.
    OctetNotSerde,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::MissingContentType => {
                f.write_str("a body was supplied but no Content-Type header was set")
            }
            CodecError::UnsupportedContentType => f.write_str(
                "the Content-Type is not a supported media type (json, xml, \
                 x-www-form-urlencoded, text/plain, or octet-stream)",
            ),
            CodecError::Encode(ct) => write!(f, "could not encode the body as {ct}"),
            CodecError::Decode(ct) => write!(f, "could not decode the response body as {ct}"),
            CodecError::OctetNotSerde => f.write_str(
                "application/octet-stream carries raw bytes; use the Raw body type instead of a \
                 serde value",
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// An empty body (no bytes on the wire, no Content-Type required). Derives
/// `Serialize`/`Deserialize` only to satisfy the body bounds; the codec
/// special-cases it and never actually runs serde on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty;

/// A raw body: bytes passed through on encode, captured verbatim on decode.
/// The serde impls exist only to satisfy the body bounds and are never run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Raw(pub Bytes);

impl<T> From<T> for Raw
where
    T: AsRef<[u8]> + Send + 'static,
{
    fn from(value: T) -> Self {
        Raw(Bytes::from_owner(value))
    }
}

/// A streaming body: an unbuffered sequence of byte chunks with an error
/// channel (`Item = Result<Bytes, HttpError>`).
///
/// As a request body it is sent chunk-by-chunk as the stream yields (the
/// transport uses chunked framing, since the total length is unknown); a
/// producer yielding `Err` aborts the request -- use
/// [`HttpError::BodyProducer`] to carry the producer's reason. As a response
/// type it receives the body chunks as they arrive instead of collecting
/// them; a mid-body transport failure surfaces as one final `Err` before the
/// stream ends, so truncation is distinguishable from a clean EOF. Consume
/// it via [`into_inner`](Self::into_inner), which yields the [`Stream`] of
/// results.
///
/// Construct from an infallible `Stream<Item = Bytes>` via `From`/`.into()`
/// (chunks are wrapped in `Ok`), or from a fallible
/// `Stream<Item = Result<Bytes, HttpError>>` via [`new`](Self::new).
///
/// The serde implementations exist just to satisfy the body type bounds; the
/// codec recognizes `ByteStream` by [`TypeId`] first, so they never run.
pub struct ByteStream<'a>(Pin<Box<dyn Stream<Item = Result<Bytes, HttpError>> + Send + 'a>>);

/// Opaque: the chunks aren't knowable without consuming the stream.
impl fmt::Debug for ByteStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ByteStream")
    }
}

/// Infallible chunk streams wrap each chunk in `Ok`. (Coherence permits only
/// one blanket `From`; fallible streams use [`ByteStream::new`].)
impl<'a, T> From<T> for ByteStream<'a>
where
    T: Stream<Item = Bytes> + Send + 'a,
{
    fn from(value: T) -> Self {
        Self(Box::pin(value.map(Ok)))
    }
}

impl<'a> ByteStream<'a> {
    /// Wraps a fallible chunk stream. An `Err` from a request-body producer
    /// aborts the request.
    pub fn new<T>(stream: T) -> Self
    where
        T: Stream<Item = Result<Bytes, HttpError>> + Send + 'a,
    {
        Self(Box::pin(stream))
    }

    /// The inner chunk stream. (`ByteStream` can't implement [`Stream`]
    /// itself without breaking the blanket `From<impl Stream>` above, so
    /// consumers unwrap it; the returned `Pin<Box<dyn Stream>>` is a
    /// [`Stream`] directly.)
    pub fn into_inner(self) -> Pin<Box<dyn Stream<Item = Result<Bytes, HttpError>> + Send + 'a>> {
        self.0
    }
}

/// Never runs: `ByteStream` is matched by [`TypeId`] before serde is
/// consulted. Exists only to satisfy the `Serialize` body bound.
impl Serialize for ByteStream<'_> {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "ByteStream is a streaming body, not a serde value",
        ))
    }
}

/// Never runs: `ByteStream` is matched by [`TypeId`] before serde is
/// consulted. Exists only to satisfy the `DeserializeOwned` body bound.
impl<'de> Deserialize<'de> for ByteStream<'_> {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "ByteStream is a streaming body, not a serde value",
        ))
    }
}

/// An encoded request body, ready for the transport: either fully buffered
/// bytes (serde values, [`Empty`], [`Raw`]) or a [`ByteStream`] the transport
/// should send chunk-by-chunk.
#[derive(Debug)]
pub enum EncodedBody {
    Full(Bytes),
    Stream(ByteStream<'static>),
}

/// Encodes a request body for the request's `Content-Type`.
///
/// [`Empty`] and [`Raw`] bypass serde and yield [`EncodedBody::Full`];
/// [`ByteStream`] yields [`EncodedBody::Stream`] (the Content-Type is the
/// caller's to set and is not consulted). Every other `T: Serialize`
/// dispatches on the media type and yields `Full`.
pub fn encode<T: Serialize + 'static>(
    content_type: Option<&HeaderValue>,
    body: T,
) -> Result<EncodedBody, CodecError> {
    if TypeId::of::<T>() == TypeId::of::<Empty>() {
        return Ok(EncodedBody::Full(Bytes::new()));
    }
    if TypeId::of::<T>() == TypeId::of::<Raw>() {
        return Ok(EncodedBody::Full(coerce::<Raw>(body).0));
    }
    if TypeId::of::<T>() == TypeId::of::<ByteStream<'static>>() {
        return Ok(EncodedBody::Stream(coerce::<ByteStream<'static>>(body)));
    }

    let ct = resolve(content_type)?;
    let bytes = match ct {
        ContentType::Json => serde_json::to_vec(&body)
            .map(Bytes::from)
            .map_err(|_| CodecError::Encode(ct))?,
        ContentType::Xml => quick_xml::se::to_string(&body)
            .map(|s| Bytes::from(s.into_bytes()))
            .map_err(|_| CodecError::Encode(ct))?,
        ContentType::Form => serde_urlencoded::to_string(&body)
            .map(|s| Bytes::from(s.into_bytes()))
            .map_err(|_| CodecError::Encode(ct))?,
        ContentType::Text => serde_plain::to_string(&body)
            .map(|s| Bytes::from(s.into_bytes()))
            .map_err(|_| CodecError::Encode(ct))?,
        ContentType::Octet => return Err(CodecError::OctetNotSerde),
    };
    Ok(EncodedBody::Full(bytes))
}

/// Whether `T` is the streaming body type ([`ByteStream`]). Transports use
/// this to decide, before consuming the response body, whether to hand it
/// over as a stream ([`stream_response`]) or collect it for [`decode`].
pub fn is_stream<T: 'static>() -> bool {
    TypeId::of::<T>() == TypeId::of::<ByteStream<'static>>()
}

/// Wraps a response body chunk stream into `T`, when `T` is [`ByteStream`]
/// (`None` otherwise -- check with [`is_stream`] first). The transport
/// surfaces a mid-body failure as an `Err` item.
pub fn stream_response<T, S>(chunks: S) -> Option<T>
where
    T: 'static,
    S: Stream<Item = Result<Bytes, HttpError>> + Send + 'static,
{
    is_stream::<T>().then(|| coerce::<T>(ByteStream::new(chunks)))
}

/// Decodes a response body from bytes given the response's `Content-Type`.
///
/// [`Empty`] and [`Raw`] bypass serde; every other `T: DeserializeOwned`
/// dispatches on the media type. A [`ByteStream`] target is normally served
/// unbuffered by the transport (see [`stream_response`]); if one reaches
/// this buffered path anyway, the collected body is delivered as a
/// single-chunk stream.
pub fn decode<T: DeserializeOwned + 'static>(
    content_type: Option<&HeaderValue>,
    body: Bytes,
) -> Result<T, CodecError> {
    if TypeId::of::<T>() == TypeId::of::<Empty>() {
        return Ok(coerce::<T>(Empty));
    }
    if TypeId::of::<T>() == TypeId::of::<Raw>() {
        return Ok(coerce::<T>(Raw(body)));
    }
    if is_stream::<T>() {
        return Ok(coerce::<T>(ByteStream::from(futures::stream::iter([body]))));
    }

    let ct = resolve(content_type)?;
    let value = match ct {
        ContentType::Json => serde_json::from_slice(&body).map_err(|_| CodecError::Decode(ct))?,
        ContentType::Xml => {
            let text = std::str::from_utf8(&body).map_err(|_| CodecError::Decode(ct))?;
            quick_xml::de::from_str(text).map_err(|_| CodecError::Decode(ct))?
        }
        ContentType::Form => {
            serde_urlencoded::from_bytes(&body).map_err(|_| CodecError::Decode(ct))?
        }
        ContentType::Text => {
            let text = std::str::from_utf8(&body).map_err(|_| CodecError::Decode(ct))?;
            serde_plain::from_str(text).map_err(|_| CodecError::Decode(ct))?
        }
        ContentType::Octet => return Err(CodecError::OctetNotSerde),
    };
    Ok(value)
}

/// Resolves the supported [`ContentType`] from a header, distinguishing
/// "absent" from "present but unsupported".
fn resolve(content_type: Option<&HeaderValue>) -> Result<ContentType, CodecError> {
    let value = content_type.ok_or(CodecError::MissingContentType)?;
    ContentType::from_header(value).ok_or(CodecError::UnsupportedContentType)
}

/// Moves `value` into type `T` when the caller has already verified (via
/// [`TypeId`]) that its concrete type is `T` -- a safe `Any` downcast.
fn coerce<T: 'static>(value: impl Any) -> T {
    match (Box::new(value) as Box<dyn Any>).downcast::<T>() {
        Ok(boxed) => *boxed,
        Err(_) => unreachable!("caller verified TypeId equality"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Point {
        x: i32,
        y: i32,
    }

    fn ct(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    /// Unwraps the buffered arm (every non-`ByteStream` body encodes to it).
    fn full(encoded: EncodedBody) -> Bytes {
        match encoded {
            EncodedBody::Full(bytes) => bytes,
            EncodedBody::Stream(_) => panic!("expected a buffered body"),
        }
    }

    fn drain(stream: ByteStream<'_>) -> Vec<Result<Bytes, HttpError>> {
        futures::executor::block_on(stream.into_inner().collect())
    }

    #[test]
    fn json_round_trip() {
        let bytes = full(encode(Some(&ct("application/json")), Point { x: 1, y: 2 }).unwrap());
        assert_eq!(&bytes[..], br#"{"x":1,"y":2}"#);
        let back: Point = decode(Some(&ct("application/json; charset=utf-8")), bytes).unwrap();
        assert_eq!(back, Point { x: 1, y: 2 });
    }

    #[test]
    fn form_round_trip() {
        let bytes = full(
            encode(
                Some(&ct("application/x-www-form-urlencoded")),
                Point { x: 1, y: 2 },
            )
            .unwrap(),
        );
        assert_eq!(&bytes[..], b"x=1&y=2");
        let back: Point = decode(Some(&ct("application/x-www-form-urlencoded")), bytes).unwrap();
        assert_eq!(back, Point { x: 1, y: 2 });
    }

    #[test]
    fn text_round_trip() {
        let bytes = full(encode(Some(&ct("text/plain")), "hello".to_string()).unwrap());
        assert_eq!(&bytes[..], b"hello");
        let back: String = decode(Some(&ct("text/plain")), bytes).unwrap();
        assert_eq!(back, "hello");
    }

    #[test]
    fn empty_needs_no_content_type() {
        assert!(full(encode(None, Empty).unwrap()).is_empty());
        let back: Empty = decode(None, Bytes::from_static(b"ignored")).unwrap();
        assert_eq!(back, Empty);
    }

    #[test]
    fn raw_ignores_content_type() {
        let bytes = full(encode(None, Raw(Bytes::from_static(b"\x00\x01"))).unwrap());
        assert_eq!(&bytes[..], b"\x00\x01");
        // Even an unsupported response Content-Type is captured verbatim.
        let back: Raw = decode(Some(&ct("image/png")), Bytes::from_static(b"\x89PNG")).unwrap();
        assert_eq!(&back.0[..], b"\x89PNG");
    }

    #[test]
    fn byte_stream_encodes_to_stream_arm() {
        let chunks = [Bytes::from_static(b"ab"), Bytes::from_static(b"cd")];
        let body = ByteStream::from(futures::stream::iter(chunks));
        // No Content-Type required: the stream is passed through untouched.
        let EncodedBody::Stream(stream) = encode(None, body).unwrap() else {
            panic!("expected the streaming arm");
        };
        assert_eq!(
            drain(stream),
            vec![Ok(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cd"))]
        );
    }

    #[test]
    fn byte_stream_error_channel_passes_through() {
        let items = [
            Ok(Bytes::from_static(b"ab")),
            Err(HttpError::BodyProducer(std::io::ErrorKind::BrokenPipe)),
        ];
        let body = ByteStream::new(futures::stream::iter(items));
        let EncodedBody::Stream(stream) = encode(None, body).unwrap() else {
            panic!("expected the streaming arm");
        };
        assert_eq!(
            drain(stream),
            vec![
                Ok(Bytes::from_static(b"ab")),
                Err(HttpError::BodyProducer(std::io::ErrorKind::BrokenPipe)),
            ]
        );
    }

    #[test]
    fn stream_response_wraps_only_byte_stream() {
        let chunks = futures::stream::iter([Ok(Bytes::from_static(b"xy"))]);
        let body: ByteStream = stream_response(chunks).expect("ByteStream target");
        assert_eq!(drain(body), vec![Ok(Bytes::from_static(b"xy"))]);

        assert!(is_stream::<ByteStream>());
        assert!(!is_stream::<Raw>());
        let chunks = futures::stream::iter([Ok(Bytes::from_static(b"xy"))]);
        assert!(stream_response::<Raw, _>(chunks).is_none());
    }

    #[test]
    fn buffered_decode_into_stream_is_single_chunk() {
        let body: ByteStream =
            decode(Some(&ct("image/png")), Bytes::from_static(b"\x89PNG")).unwrap();
        assert_eq!(drain(body), vec![Ok(Bytes::from_static(b"\x89PNG"))]);
    }

    #[test]
    fn body_without_content_type_errors() {
        let err = encode(None, Point { x: 0, y: 0 }).unwrap_err();
        assert_eq!(err, CodecError::MissingContentType);
    }

    #[test]
    fn body_unsupported_content_type_errors() {
        let err = encode(Some(&ct("image/png")), Point { x: 0, y: 0 }).unwrap_err();
        assert_eq!(err, CodecError::UnsupportedContentType);
    }

    #[test]
    fn octet_on_serde_body_is_an_error() {
        let err = encode(Some(&ct("application/octet-stream")), "x".to_string()).unwrap_err();
        assert_eq!(err, CodecError::OctetNotSerde);
    }
}

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
//! Two marker types get special, serde-free handling (recognized by
//! [`TypeId`], so they need no wire format):
//!
//! - [`Empty`] -- no body. Encodes to zero bytes and needs no Content-Type;
//!   decoding ignores the response body. Use it for GETs and bodyless calls.
//! - [`Raw`] -- bytes as-is: encoding passes them straight through (the caller
//!   sets the Content-Type, typically `application/octet-stream`), and
//!   decoding captures the response body verbatim regardless of Content-Type.
//!
//! Everything else dispatches on the Content-Type media type:
//! `application/json`, `application/xml`,
//! `application/x-www-form-urlencoded`, or `text/plain`.
//! `application/octet-stream` carries raw bytes, so it is served by [`Raw`];
//! asking a serde value to encode as octet-stream is an error.
//!
//! Because the marker types are matched by [`TypeId`], bodies must be
//! `'static` (an owned value, not a borrow).

use std::any::{Any, TypeId};
use std::fmt;

use bytes::Bytes;
use http::HeaderValue;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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
    T: AsRef<[u8]> + Send + 'static
{
    fn from(value: T) -> Self {
        Raw(Bytes::from_owner(value))
    }
}

/// Encodes a request body to bytes for the request's `Content-Type`.
///
/// [`Empty`] and [`Raw`] bypass serde; every other `T: Serialize` dispatches
/// on the media type.
pub fn encode<T: Serialize + 'static>(
    content_type: Option<&HeaderValue>,
    body: T,
) -> Result<Bytes, CodecError> {
    if TypeId::of::<T>() == TypeId::of::<Empty>() {
        return Ok(Bytes::new());
    }
    if TypeId::of::<T>() == TypeId::of::<Raw>() {
        return Ok(coerce::<Raw>(body).0);
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
    Ok(bytes)
}

/// Decodes a response body from bytes given the response's `Content-Type`.
///
/// [`Empty`] and [`Raw`] bypass serde; every other `T: DeserializeOwned`
/// dispatches on the media type.
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

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Point {
        x: i32,
        y: i32,
    }

    fn ct(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn json_round_trip() {
        let bytes = encode(Some(&ct("application/json")), Point { x: 1, y: 2 }).unwrap();
        assert_eq!(&bytes[..], br#"{"x":1,"y":2}"#);
        let back: Point = decode(Some(&ct("application/json; charset=utf-8")), bytes).unwrap();
        assert_eq!(back, Point { x: 1, y: 2 });
    }

    #[test]
    fn form_round_trip() {
        let bytes = encode(
            Some(&ct("application/x-www-form-urlencoded")),
            Point { x: 1, y: 2 },
        )
        .unwrap();
        assert_eq!(&bytes[..], b"x=1&y=2");
        let back: Point = decode(Some(&ct("application/x-www-form-urlencoded")), bytes).unwrap();
        assert_eq!(back, Point { x: 1, y: 2 });
    }

    #[test]
    fn text_round_trip() {
        let bytes = encode(Some(&ct("text/plain")), "hello".to_string()).unwrap();
        assert_eq!(&bytes[..], b"hello");
        let back: String = decode(Some(&ct("text/plain")), bytes).unwrap();
        assert_eq!(back, "hello");
    }

    #[test]
    fn empty_needs_no_content_type() {
        assert!(encode(None, Empty).unwrap().is_empty());
        let back: Empty = decode(None, Bytes::from_static(b"ignored")).unwrap();
        assert_eq!(back, Empty);
    }

    #[test]
    fn raw_ignores_content_type() {
        let bytes = encode(None, Raw(Bytes::from_static(b"\x00\x01"))).unwrap();
        assert_eq!(&bytes[..], b"\x00\x01");
        // Even an unsupported response Content-Type is captured verbatim.
        let back: Raw = decode(Some(&ct("image/png")), Bytes::from_static(b"\x89PNG")).unwrap();
        assert_eq!(&back.0[..], b"\x89PNG");
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

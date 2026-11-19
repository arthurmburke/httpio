//! HPACK (RFC 7541), as much of it as a client needs.
//!
//! **Encoding requests** uses the static table and nothing else: a field is
//! an index into it, or a literal that is not added to the dynamic table,
//! with strings sent raw (no Huffman coding). That makes a request head a
//! handful of `memcpy`s with no per-connection encoder state, at the cost
//! of a few dozen more bytes on the wire than an indexing encoder would
//! send for a repeated request -- bytes that share the packet the request
//! needs anyway. Fields that carry credentials are marked never-indexed
//! (RFC 7541 §7.1.3) so intermediaries do not put them in a table either.
//!
//! **Decoding responses** is complete: the static and dynamic tables,
//! table size updates and Huffman-coded strings. The decoder's table is
//! connection state shared by every header block, so every block must be
//! decoded, in order, even one whose stream is gone; an error leaves the
//! table unusable and is fatal to the connection.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Uri};

use super::huffman;

/// The dynamic table size a decoder starts with, and the most the encoder
/// may raise it to since this client never advertises another
/// (`SETTINGS_HEADER_TABLE_SIZE`, RFC 9113 §6.5.2).
pub(super) const DEFAULT_TABLE_SIZE: usize = 4096;

/// What a table entry costs beyond its name and value (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// A header block could not be decoded. Always fatal to the connection
/// (`COMPRESSION_ERROR`): the dynamic table is no longer in step with the
/// peer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HpackError {
    /// The block ended inside an instruction.
    Truncated,
    /// An integer does not fit in 32 bits.
    IntegerOverflow,
    /// An index names no table entry.
    InvalidIndex,
    /// A string was not valid Huffman coding.
    InvalidHuffman,
    /// A table size update above the allowed size, or after a field.
    InvalidTableSize,
    /// A field name is not a valid lowercase HTTP field name.
    InvalidName,
    /// A field value holds bytes not allowed in one.
    InvalidValue,
    /// The decoded fields exceed the caller's limits (see
    /// [`Decoder::decode`]). Not a compression error as such, but decoding
    /// stops, which leaves the table just as unusable.
    TooLarge,
}

/// The name of a decoded field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Name {
    /// `:status`, the only pseudo-header field a response may carry.
    Status,
    /// Any other pseudo-header field: malformed in a response, but still
    /// decoded (and stored in the table) to stay in step with the peer.
    Pseudo(Bytes),
    Field(HeaderName),
}

impl Name {
    fn len(&self) -> usize {
        match self {
            Name::Status => 7,
            Name::Pseudo(name) => name.len(),
            Name::Field(name) => name.as_str().len(),
        }
    }

    fn from_bytes(name: &[u8]) -> Result<Self, HpackError> {
        if name.first() == Some(&b':') {
            return Ok(if name == b":status" {
                Name::Status
            } else {
                Name::Pseudo(Bytes::copy_from_slice(name))
            });
        }
        // Field names are lowercase in HTTP/2 (RFC 9113 §8.2.1); this
        // refuses uppercase along with everything that is not a token.
        HeaderName::from_lowercase(name)
            .map(Name::Field)
            .map_err(|_| HpackError::InvalidName)
    }
}

// ---------------------------------------------------------------------------
// The static table (RFC 7541 Appendix A)
// ---------------------------------------------------------------------------

enum StaticName {
    Authority,
    Method,
    Path,
    Scheme,
    Status,
    Field(HeaderName),
}

const fn field(name: HeaderName) -> (StaticName, &'static str) {
    (StaticName::Field(name), "")
}

/// Entry `i` is index `i + 1`.
static STATIC_TABLE: [(StaticName, &str); 61] = [
    (StaticName::Authority, ""),
    (StaticName::Method, "GET"),
    (StaticName::Method, "POST"),
    (StaticName::Path, "/"),
    (StaticName::Path, "/index.html"),
    (StaticName::Scheme, "http"),
    (StaticName::Scheme, "https"),
    (StaticName::Status, "200"),
    (StaticName::Status, "204"),
    (StaticName::Status, "206"),
    (StaticName::Status, "304"),
    (StaticName::Status, "400"),
    (StaticName::Status, "404"),
    (StaticName::Status, "500"),
    field(header::ACCEPT_CHARSET),
    (StaticName::Field(header::ACCEPT_ENCODING), "gzip, deflate"),
    field(header::ACCEPT_LANGUAGE),
    field(header::ACCEPT_RANGES),
    field(header::ACCEPT),
    field(header::ACCESS_CONTROL_ALLOW_ORIGIN),
    field(header::AGE),
    field(header::ALLOW),
    field(header::AUTHORIZATION),
    field(header::CACHE_CONTROL),
    field(header::CONTENT_DISPOSITION),
    field(header::CONTENT_ENCODING),
    field(header::CONTENT_LANGUAGE),
    field(header::CONTENT_LENGTH),
    field(header::CONTENT_LOCATION),
    field(header::CONTENT_RANGE),
    field(header::CONTENT_TYPE),
    field(header::COOKIE),
    field(header::DATE),
    field(header::ETAG),
    field(header::EXPECT),
    field(header::EXPIRES),
    field(header::FROM),
    field(header::HOST),
    field(header::IF_MATCH),
    field(header::IF_MODIFIED_SINCE),
    field(header::IF_NONE_MATCH),
    field(header::IF_RANGE),
    field(header::IF_UNMODIFIED_SINCE),
    field(header::LAST_MODIFIED),
    field(header::LINK),
    field(header::LOCATION),
    field(header::MAX_FORWARDS),
    field(header::PROXY_AUTHENTICATE),
    field(header::PROXY_AUTHORIZATION),
    field(header::RANGE),
    field(header::REFERER),
    field(header::REFRESH),
    field(header::RETRY_AFTER),
    field(header::SERVER),
    field(header::SET_COOKIE),
    field(header::STRICT_TRANSPORT_SECURITY),
    field(header::TRANSFER_ENCODING),
    field(header::USER_AGENT),
    field(header::VARY),
    field(header::VIA),
    field(header::WWW_AUTHENTICATE),
];

/// The static table index whose name is `name`, or 0.
fn static_name_index(name: &str) -> u8 {
    match name {
        "accept-charset" => 15,
        "accept-encoding" => 16,
        "accept-language" => 17,
        "accept-ranges" => 18,
        "accept" => 19,
        "access-control-allow-origin" => 20,
        "age" => 21,
        "allow" => 22,
        "authorization" => 23,
        "cache-control" => 24,
        "content-disposition" => 25,
        "content-encoding" => 26,
        "content-language" => 27,
        "content-length" => 28,
        "content-location" => 29,
        "content-range" => 30,
        "content-type" => 31,
        "cookie" => 32,
        "date" => 33,
        "etag" => 34,
        "expect" => 35,
        "expires" => 36,
        "from" => 37,
        "if-match" => 39,
        "if-modified-since" => 40,
        "if-none-match" => 41,
        "if-range" => 42,
        "if-unmodified-since" => 43,
        "last-modified" => 44,
        "link" => 45,
        "location" => 46,
        "max-forwards" => 47,
        "proxy-authenticate" => 48,
        "proxy-authorization" => 49,
        "range" => 50,
        "referer" => 51,
        "refresh" => 52,
        "retry-after" => 53,
        "server" => 54,
        "set-cookie" => 55,
        "strict-transport-security" => 56,
        "user-agent" => 58,
        "vary" => 59,
        "via" => 60,
        "www-authenticate" => 61,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Encoding requests
// ---------------------------------------------------------------------------

const INDEX_AUTHORITY: u8 = 1;
const INDEX_METHOD_GET: u8 = 2;
const INDEX_METHOD_POST: u8 = 3;
const INDEX_PATH_ROOT: u8 = 4;
const INDEX_SCHEME_HTTP: u8 = 6;
const INDEX_SCHEME_HTTPS: u8 = 7;
const INDEX_CONTENT_LENGTH: u8 = 28;

/// An integer with an `prefix_bits`-bit prefix (RFC 7541 §5.1); `flags`
/// are the bits of the first byte above the prefix.
fn put_int(dst: &mut BytesMut, flags: u8, prefix_bits: u32, mut value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        dst.put_u8(flags | value as u8);
        return;
    }
    dst.put_u8(flags | max as u8);
    value -= max;
    while value >= 0x80 {
        dst.put_u8(value as u8 | 0x80);
        value >>= 7;
    }
    dst.put_u8(value as u8);
}

/// A string literal, not Huffman coded (RFC 7541 §5.2).
fn put_string(dst: &mut BytesMut, bytes: &[u8]) {
    put_int(dst, 0, 7, bytes.len());
    dst.put_slice(bytes);
}

/// An indexed field (RFC 7541 §6.1).
fn put_indexed(dst: &mut BytesMut, index: u8) {
    dst.put_u8(0x80 | index);
}

/// A literal field whose name is static table entry `name_index`, or
/// `name` spelled out when that is 0; never added to a dynamic table.
/// `sensitive` marks it never-indexed (RFC 7541 §6.2.3) rather than
/// without indexing (§6.2.2).
fn put_literal(dst: &mut BytesMut, name_index: u8, name: &[u8], value: &[u8], sensitive: bool) {
    let flags = if sensitive { 0x10 } else { 0x00 };
    put_int(dst, flags, 4, usize::from(name_index));
    if name_index == 0 {
        put_string(dst, name);
    }
    put_string(dst, value);
}

/// Whether `name` is a field HTTP/2 forbids (connection-specific fields,
/// RFC 9113 §8.2.2) or one this encoder replaces (`host`, sent as
/// `:authority`). `te` is handled by the caller: only `trailers` may pass.
fn is_dropped(name: &HeaderName) -> bool {
    *name == header::CONNECTION
        || *name == header::HOST
        || *name == header::TRANSFER_ENCODING
        || *name == header::UPGRADE
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
}

/// The request's `:authority`: the URI's, else the `Host` field's.
pub(super) fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> Option<&'a [u8]> {
    match uri.authority() {
        Some(authority) => Some(authority.as_str().as_bytes()),
        None => headers.get(header::HOST).map(HeaderValue::as_bytes),
    }
}

/// Appends the header block of a request to `dst`: the pseudo-header
/// fields, then `headers` minus the fields HTTP/2 forbids, then
/// `content-length` when `content_length` is given (the caller passes it
/// only when `headers` has none).
///
/// `authority` is from [`authority`]. A URI without a scheme is sent as
/// `https`.
pub(super) fn encode_request(
    dst: &mut BytesMut,
    method: &Method,
    uri: &Uri,
    authority: &[u8],
    headers: &HeaderMap,
    content_length: Option<u64>,
) {
    match *method {
        Method::GET => put_indexed(dst, INDEX_METHOD_GET),
        Method::POST => put_indexed(dst, INDEX_METHOD_POST),
        _ => put_literal(
            dst,
            INDEX_METHOD_GET,
            b"",
            method.as_str().as_bytes(),
            false,
        ),
    }
    // CONNECT carries only `:method` and `:authority` (RFC 9113 §8.5).
    if *method != Method::CONNECT {
        match uri.scheme_str() {
            Some("http") => put_indexed(dst, INDEX_SCHEME_HTTP),
            Some("https") | None => put_indexed(dst, INDEX_SCHEME_HTTPS),
            Some(other) => put_literal(dst, INDEX_SCHEME_HTTP, b"", other.as_bytes(), false),
        }
        match uri.path_and_query().map_or("/", |pq| pq.as_str()) {
            "" | "/" => put_indexed(dst, INDEX_PATH_ROOT),
            path if path.starts_with('?') => {
                // An empty path with a query: the path is "/".
                put_int(dst, 0x00, 4, usize::from(INDEX_PATH_ROOT));
                put_int(dst, 0, 7, path.len() + 1);
                dst.put_u8(b'/');
                dst.put_slice(path.as_bytes());
            }
            path => put_literal(dst, INDEX_PATH_ROOT, b"", path.as_bytes(), false),
        }
    }
    put_literal(dst, INDEX_AUTHORITY, b"", authority, false);
    for (name, value) in headers {
        if is_dropped(name) {
            continue;
        }
        if *name == header::TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            continue;
        }
        let sensitive = value.is_sensitive()
            || *name == header::AUTHORIZATION
            || *name == header::PROXY_AUTHORIZATION
            || *name == header::COOKIE;
        let name = name.as_str();
        put_literal(
            dst,
            static_name_index(name),
            name.as_bytes(),
            value.as_bytes(),
            sensitive,
        );
    }
    if let Some(length) = content_length {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let mut n = length;
        loop {
            at -= 1;
            digits[at] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        put_literal(dst, INDEX_CONTENT_LENGTH, b"", &digits[at..], false);
    }
}

// ---------------------------------------------------------------------------
// Decoding responses
// ---------------------------------------------------------------------------

/// Limits on one decoded header block, so that a few bytes of indexes
/// cannot expand without bound.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Most fields.
    pub fields: usize,
    /// Largest total of name and value lengths plus 32 per field (the size
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` counts, RFC 9113 §6.5.2).
    pub size: usize,
}

struct Entry {
    name: Name,
    value: HeaderValue,
}

impl Entry {
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// The decoding side of one connection's HPACK state.
pub(super) struct Decoder {
    /// The dynamic table, newest entry first.
    table: VecDeque<Entry>,
    /// Sum of the entries' sizes.
    size: usize,
    /// The size the encoder last chose (at most [`DEFAULT_TABLE_SIZE`]).
    max_size: usize,
    /// Where literal values are written before they leave as `Bytes`:
    /// the values of a block share one allocation instead of each having
    /// its own.
    values: BytesMut,
    /// Scratch for a Huffman-coded name.
    name: BytesMut,
}

/// Reads a header block front to back.
struct Reader<'a> {
    block: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, HpackError> {
        let byte = *self.block.get(self.at).ok_or(HpackError::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    /// The rest of an integer whose first byte, masked to its prefix, is
    /// `first` (RFC 7541 §5.1).
    fn int(&mut self, first: u8, prefix_bits: u32) -> Result<usize, HpackError> {
        let max = (1u32 << prefix_bits) - 1;
        let mut value = u32::from(first) & max;
        if value < max {
            return Ok(value as usize);
        }
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            // 32 bits is far more than any length or index in a block
            // bounded by the frame size limits.
            if shift > 28 {
                return Err(HpackError::IntegerOverflow);
            }
            value = value
                .checked_add(u32::from(byte & 0x7f) << shift)
                .ok_or(HpackError::IntegerOverflow)?;
            if byte & 0x80 == 0 {
                return Ok(value as usize);
            }
            shift += 7;
        }
    }

    /// A string literal's coding flag and raw bytes (RFC 7541 §5.2).
    fn string(&mut self) -> Result<(bool, &'a [u8]), HpackError> {
        let first = self.byte()?;
        let len = self.int(first, 7)?;
        let end = self.at.checked_add(len).ok_or(HpackError::Truncated)?;
        let bytes = self.block.get(self.at..end).ok_or(HpackError::Truncated)?;
        self.at = end;
        Ok((first & 0x80 != 0, bytes))
    }
}

impl Decoder {
    pub(super) fn new() -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max_size: DEFAULT_TABLE_SIZE,
            values: BytesMut::new(),
            name: BytesMut::new(),
        }
    }

    /// Decodes one complete header block, handing each field to `emit` in
    /// order. On an error the connection must be closed.
    pub(super) fn decode(
        &mut self,
        block: &[u8],
        limits: Limits,
        mut emit: impl FnMut(Name, HeaderValue),
    ) -> Result<(), HpackError> {
        let mut reader = Reader { block, at: 0 };
        let mut fields = 0;
        let mut size = 0;
        while reader.at < block.len() {
            let first = reader.byte()?;
            let (name, value) = if first & 0x80 != 0 {
                // Indexed field.
                let index = reader.int(first, 7)?;
                self.entry(index)?
            } else if first & 0x40 != 0 {
                // Literal with incremental indexing.
                let (name, value) = self.literal(&mut reader, first, 6)?;
                self.insert(name.clone(), value.clone());
                (name, value)
            } else if first & 0x20 != 0 {
                // Dynamic table size update: only before the first field
                // of a block (RFC 7541 §4.2).
                let max_size = reader.int(first, 5)?;
                if fields != 0 || max_size > DEFAULT_TABLE_SIZE {
                    return Err(HpackError::InvalidTableSize);
                }
                self.max_size = max_size;
                self.evict(0);
                continue;
            } else {
                // Literal without indexing (0000) or never indexed (0001):
                // the same to a decoder that does not re-encode.
                self.literal(&mut reader, first, 4)?
            };
            fields += 1;
            size += name.len() + value.len() + ENTRY_OVERHEAD;
            if fields > limits.fields || size > limits.size {
                return Err(HpackError::TooLarge);
            }
            emit(name, value);
        }
        Ok(())
    }

    /// The field at `index` in the combined static and dynamic tables.
    fn entry(&self, index: usize) -> Result<(Name, HeaderValue), HpackError> {
        if let Some(index) = index.checked_sub(STATIC_TABLE.len() + 1) {
            let entry = self.table.get(index).ok_or(HpackError::InvalidIndex)?;
            return Ok((entry.name.clone(), entry.value.clone()));
        }
        let index = index.checked_sub(1).ok_or(HpackError::InvalidIndex)?;
        let (_, value) = &STATIC_TABLE[index];
        Ok((static_name(index), HeaderValue::from_static(value)))
    }

    /// The name at `index` alone.
    fn name(&self, index: usize) -> Result<Name, HpackError> {
        if let Some(index) = index.checked_sub(STATIC_TABLE.len() + 1) {
            let entry = self.table.get(index).ok_or(HpackError::InvalidIndex)?;
            return Ok(entry.name.clone());
        }
        let index = index.checked_sub(1).ok_or(HpackError::InvalidIndex)?;
        Ok(static_name(index))
    }

    /// A literal field whose first byte is `first`, with the name index in
    /// its low `prefix_bits` bits.
    fn literal(
        &mut self,
        reader: &mut Reader<'_>,
        first: u8,
        prefix_bits: u32,
    ) -> Result<(Name, HeaderValue), HpackError> {
        let index = reader.int(first, prefix_bits)?;
        let name = if index != 0 {
            self.name(index)?
        } else {
            let (coded, bytes) = reader.string()?;
            if coded {
                self.name.clear();
                huffman::decode(bytes, &mut self.name).map_err(|_| HpackError::InvalidHuffman)?;
                Name::from_bytes(&self.name)?
            } else {
                Name::from_bytes(bytes)?
            }
        };
        let (coded, bytes) = reader.string()?;
        if coded {
            huffman::decode(bytes, &mut self.values).map_err(|_| HpackError::InvalidHuffman)?;
        } else {
            self.values.extend_from_slice(bytes);
        }
        // `split` leaves the buffer's spare capacity for the next value.
        let value = HeaderValue::from_maybe_shared(self.values.split().freeze())
            .map_err(|_| HpackError::InvalidValue)?;
        Ok((name, value))
    }

    /// Adds an entry at the front of the dynamic table, evicting from the
    /// back to make room. An entry larger than the whole table empties it
    /// and is not added (RFC 7541 §4.4).
    fn insert(&mut self, name: Name, value: HeaderValue) {
        let entry = Entry { name, value };
        let size = entry.size();
        self.evict(size);
        if size <= self.max_size {
            self.size += size;
            self.table.push_front(entry);
        }
    }

    /// Evicts the oldest entries until `incoming` more bytes fit.
    fn evict(&mut self, incoming: usize) {
        while self.size + incoming > self.max_size {
            let Some(entry) = self.table.pop_back() else {
                break;
            };
            self.size -= entry.size();
        }
    }
}

fn static_name(index: usize) -> Name {
    match &STATIC_TABLE[index].0 {
        StaticName::Status => Name::Status,
        StaticName::Authority => Name::Pseudo(Bytes::from_static(b":authority")),
        StaticName::Method => Name::Pseudo(Bytes::from_static(b":method")),
        StaticName::Path => Name::Pseudo(Bytes::from_static(b":path")),
        StaticName::Scheme => Name::Pseudo(Bytes::from_static(b":scheme")),
        StaticName::Field(name) => Name::Field(name.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        fields: 100,
        size: 64 * 1024,
    };

    fn decode(decoder: &mut Decoder, block: &[u8]) -> Result<Vec<(String, String)>, HpackError> {
        let mut out = Vec::new();
        decoder.decode(block, LIMITS, |name, value| {
            let name = match name {
                Name::Status => ":status".to_owned(),
                Name::Pseudo(name) => String::from_utf8(name.to_vec()).unwrap(),
                Name::Field(name) => name.as_str().to_owned(),
            };
            out.push((name, value.to_str().unwrap().to_owned()));
        })?;
        Ok(out)
    }

    fn pairs(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits.chunks(2).map(|d| d[0] << 4 | d[1]).collect()
    }

    fn table(decoder: &Decoder) -> Vec<(String, String)> {
        decoder
            .table
            .iter()
            .map(|entry| {
                let name = match &entry.name {
                    Name::Status => ":status".to_owned(),
                    Name::Pseudo(name) => String::from_utf8(name.to_vec()).unwrap(),
                    Name::Field(name) => name.as_str().to_owned(),
                };
                (name, entry.value.to_str().unwrap().to_owned())
            })
            .collect()
    }

    #[test]
    fn static_table_matches_the_name_lookup() {
        for (i, (name, _)) in STATIC_TABLE.iter().enumerate() {
            if let StaticName::Field(name) = name {
                let expected = if *name == header::HOST || *name == header::TRANSFER_ENCODING {
                    // Never encoded: dropped from requests.
                    0
                } else {
                    i + 1
                };
                assert_eq!(usize::from(static_name_index(name.as_str())), expected);
            }
        }
        assert_eq!(STATIC_TABLE[INDEX_CONTENT_LENGTH as usize - 1].1, "");
        assert_eq!(static_name_index("x-custom"), 0);
    }

    /// RFC 7541 Appendix C.5: responses without Huffman coding, with a
    /// 256-byte table so that entries are evicted.
    #[test]
    fn rfc_response_examples_without_huffman() {
        let mut decoder = Decoder::new();
        decoder.max_size = 256;
        let first = hex(
            "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
             2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
             6c65 2e63 6f6d",
        );
        assert_eq!(
            decode(&mut decoder, &first).unwrap(),
            pairs(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(decoder.size, 222);
        // The second response evicts `:status: 302` to add `:status: 307`.
        assert_eq!(
            decode(&mut decoder, &hex("4803 3330 37c1 c0bf")).unwrap(),
            pairs(&[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(decoder.size, 222);
        assert_eq!(
            table(&decoder),
            pairs(&[
                (":status", "307"),
                ("location", "https://www.example.com"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("cache-control", "private"),
            ])
        );
    }

    /// RFC 7541 Appendix C.6: the same responses, Huffman coded.
    #[test]
    fn rfc_response_examples_with_huffman() {
        let mut decoder = Decoder::new();
        decoder.max_size = 256;
        let first = hex(
            "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
             2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        );
        assert_eq!(
            decode(&mut decoder, &first).unwrap(),
            pairs(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(
            decode(&mut decoder, &hex("4883 640e ffc1 c0bf")).unwrap()[0],
            (":status".to_owned(), "307".to_owned())
        );
        let third = hex(
            "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
             77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
             9587 3160 65c0 03ed 4ee5 b106 3d50 07",
        );
        assert_eq!(
            decode(&mut decoder, &third).unwrap(),
            pairs(&[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                ),
            ])
        );
        assert_eq!(decoder.size, 215);
    }

    #[test]
    fn integers_at_every_prefix_boundary() {
        for prefix_bits in 1..=8u32 {
            for value in [
                0usize, 1, 30, 31, 126, 127, 128, 254, 255, 256, 1337, 70_000,
            ] {
                let mut out = BytesMut::new();
                put_int(&mut out, 0, prefix_bits, value);
                let mut reader = Reader { block: &out, at: 0 };
                let first = reader.byte().unwrap();
                assert_eq!(reader.int(first, prefix_bits), Ok(value));
                assert_eq!(reader.at, out.len());
            }
        }
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix.
        let mut out = BytesMut::new();
        put_int(&mut out, 0, 5, 1337);
        assert_eq!(&out[..], [0x1f, 0x9a, 0x0a]);
        // Too large, and unterminated.
        let mut reader = Reader {
            block: &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            at: 1,
        };
        assert_eq!(reader.int(0x7f, 7), Err(HpackError::IntegerOverflow));
        let mut reader = Reader {
            block: &[0xff, 0x80],
            at: 1,
        };
        assert_eq!(reader.int(0x7f, 7), Err(HpackError::Truncated));
    }

    #[test]
    fn malformed_blocks_are_errors() {
        let cases: [(&[u8], HpackError); 9] = [
            // Index 0, and indexes past both tables.
            (&[0x80], HpackError::InvalidIndex),
            (&[0xbe], HpackError::InvalidIndex),
            (&[0x7e, 0x01, b'x'], HpackError::InvalidIndex),
            // A string longer than the block.
            (&[0x40, 0x05, b'a'], HpackError::Truncated),
            // An uppercase name, and a control character in a value.
            (&[0x40, 0x01, b'A', 0x01, b'x'], HpackError::InvalidName),
            (&[0x40, 0x01, b'a', 0x01, 0x00], HpackError::InvalidValue),
            // Invalid Huffman padding.
            (&[0x40, 0x01, b'a', 0x81, 0x06], HpackError::InvalidHuffman),
            // A table size above the setting, and an update after a field.
            (&[0x3f, 0xe2, 0x1f], HpackError::InvalidTableSize),
            (&[0x88, 0x20], HpackError::InvalidTableSize),
        ];
        for (block, error) in cases {
            assert_eq!(decode(&mut Decoder::new(), block), Err(error), "{block:x?}");
        }
    }

    #[test]
    fn limits_stop_index_expansion() {
        let mut decoder = Decoder::new();
        // One 1000-byte value in the table, then referenced over and over.
        let mut block = vec![0x40, 0x01, b'a', 0x7f];
        block.extend_from_slice(&[0xe9, 0x06]);
        block.extend(std::iter::repeat_n(b'v', 1000));
        assert_eq!(decode(&mut decoder, &block).unwrap().len(), 1);
        // 1033 bytes a field: 63 fit in 64 KiB, 64 do not.
        let bomb = vec![0xbe; 63];
        assert_eq!(decode(&mut decoder, &bomb).unwrap().len(), 63);
        let bomb = vec![0xbe; 64];
        assert_eq!(decode(&mut decoder, &bomb), Err(HpackError::TooLarge));
        let many = vec![0x88; 101];
        assert_eq!(
            decode(&mut Decoder::new(), &many),
            Err(HpackError::TooLarge)
        );
    }

    #[test]
    fn table_size_updates_evict() {
        let mut decoder = Decoder::new();
        let add = [0x40, 0x01, b'a', 0x01, b'1', 0x40, 0x01, b'b', 0x01, b'2'];
        decode(&mut decoder, &add).unwrap();
        assert_eq!(table(&decoder), pairs(&[("b", "2"), ("a", "1")]));
        assert_eq!(decoder.size, 68);
        // Room for one entry only, then none.
        decode(&mut decoder, &[0x3f, 0x03]).unwrap();
        assert_eq!(table(&decoder), pairs(&[("b", "2")]));
        decode(&mut decoder, &[0x20]).unwrap();
        assert!(decoder.table.is_empty());
        assert_eq!(decoder.size, 0);
        // With no room an indexed literal is decoded but not stored.
        assert_eq!(
            decode(&mut decoder, &add).unwrap(),
            pairs(&[("a", "1"), ("b", "2")])
        );
        assert!(decoder.table.is_empty());
    }

    /// What this encoder writes, a full decoder reads back.
    #[test]
    fn requests_round_trip() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-request-id", HeaderValue::from_static("abc123"));
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("host", HeaderValue::from_static("ignored.example"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("te", HeaderValue::from_static("gzip"));
        headers.insert(
            "accept",
            HeaderValue::from_static(&"a".repeat(300).leak()[..]),
        );
        let uri: Uri = "https://example.com:8443/a/b?c=d".parse().unwrap();
        let mut block = BytesMut::new();
        let host = authority(&uri, &headers).unwrap();
        encode_request(&mut block, &Method::POST, &uri, host, &headers, Some(1234));
        let mut decoder = Decoder::new();
        assert_eq!(
            decode(&mut decoder, &block).unwrap(),
            pairs(&[
                (":method", "POST"),
                (":scheme", "https"),
                (":path", "/a/b?c=d"),
                (":authority", "example.com:8443"),
                ("content-type", "application/json"),
                ("x-request-id", "abc123"),
                ("authorization", "Bearer secret"),
                ("accept", &"a".repeat(300)),
                ("content-length", "1234"),
            ])
        );
        // Nothing the encoder writes enters a table.
        assert!(decoder.table.is_empty());
        // The credential is marked never-indexed.
        let at = block
            .windows(13)
            .position(|w| w == b"Bearer secret")
            .unwrap();
        assert_eq!(
            block[at - 3..at],
            [0x1f, 0x08, 13],
            "never-indexed, name index 23"
        );

        // Other methods and targets.
        let mut block = BytesMut::new();
        let uri: Uri = "http://h?q=1".parse().unwrap();
        encode_request(
            &mut block,
            &Method::DELETE,
            &uri,
            b"h",
            &HeaderMap::new(),
            None,
        );
        assert_eq!(
            decode(&mut decoder, &block).unwrap(),
            pairs(&[
                (":method", "DELETE"),
                (":scheme", "http"),
                (":path", "/?q=1"),
                (":authority", "h"),
            ])
        );
        let mut block = BytesMut::new();
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("from-host"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        let host = authority(&uri, &headers).unwrap();
        encode_request(&mut block, &Method::GET, &uri, host, &headers, None);
        assert_eq!(
            decode(&mut decoder, &block).unwrap(),
            pairs(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "from-host"),
                ("te", "trailers"),
            ])
        );
        assert_eq!(&block[..3], [0x82, 0x87, 0x84]);
    }
}

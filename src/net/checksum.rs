//! RFC 1071 Internet checksum, plus the IPv4 pseudo-header sum TCP/UDP
//! checksums are computed over.

/// One's-complement sum of `data` as big-endian 16-bit words (odd trailing
/// byte, if any, is treated as a byte in the high position of a final
/// word). Accumulates in 32 bits and folds carries at the end, so callers
/// can chain multiple regions (e.g. pseudo-header + TCP header + payload)
/// by feeding the running sum into the next call via `with_seed`.
pub fn sum16(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    sum
}

/// Folds a 32-bit accumulated sum down to a 16-bit one's-complement
/// checksum ready to place in the wire header.
pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Internet checksum over a single contiguous buffer (e.g. an IPv4 header
/// with checksum field zeroed).
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(data, 0))
}

/// TCP/UDP-over-IPv4 pseudo-header sum (RFC 793 §3.1 / RFC 9293 §3.1):
/// src IP + dst IP + zero byte + protocol + segment length (header +
/// payload, not including the pseudo-header itself).
pub fn ipv4_pseudo_header_sum(src: [u8; 4], dst: [u8; 4], protocol: u8, segment_len: u16) -> u32 {
    let mut sum = 0u32;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += protocol as u32;
    sum += segment_len as u32;
    sum
}

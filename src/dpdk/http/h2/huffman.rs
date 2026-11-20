//! The HPACK Huffman code (RFC 7541 §5.2, Appendix B): decoding, which a
//! client needs for response headers. Requests are sent without Huffman
//! coding (see [`super::hpack`]), so encoding exists only for the tests
//! and the fuzzers.
//!
//! Decoding reads the input through a 64-bit window. Codes of up to
//! [`PRIMARY_BITS`] bits -- every printable ASCII character the common
//! headers use -- resolve with one lookup in a 1024-entry table; longer
//! codes (up to 30 bits) fall back to a binary search over all codes
//! sorted by their left-aligned value. Both tables are computed at compile
//! time from the code list below, the only hand-maintained data.

use bytes::{BufMut, BytesMut};

/// A string was not a valid Huffman encoding: it held the EOS symbol, or
/// ended in padding that is not a strict prefix of EOS shorter than a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvalidHuffman;

/// The EOS symbol's index in [`CODES`].
const EOS: u16 = 256;

/// `(code, length in bits)` for each byte value, then EOS: RFC 7541
/// Appendix B.
const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x007fffd8, 23),
    (0x0fffffe2, 28),
    (0x0fffffe3, 28),
    (0x0fffffe4, 28),
    (0x0fffffe5, 28),
    (0x0fffffe6, 28),
    (0x0fffffe7, 28),
    (0x0fffffe8, 28),
    (0x00ffffea, 24),
    (0x3ffffffc, 30),
    (0x0fffffe9, 28),
    (0x0fffffea, 28),
    (0x3ffffffd, 30),
    (0x0fffffeb, 28),
    (0x0fffffec, 28),
    (0x0fffffed, 28),
    (0x0fffffee, 28),
    (0x0fffffef, 28),
    (0x0ffffff0, 28),
    (0x0ffffff1, 28),
    (0x0ffffff2, 28),
    (0x3ffffffe, 30),
    (0x0ffffff3, 28),
    (0x0ffffff4, 28),
    (0x0ffffff5, 28),
    (0x0ffffff6, 28),
    (0x0ffffff7, 28),
    (0x0ffffff8, 28),
    (0x0ffffff9, 28),
    (0x0ffffffa, 28),
    (0x0ffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0x0ffffffc, 28),
    (0xfffe6, 20),
    (0x003fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x003fffd3, 22),
    (0x003fffd4, 22),
    (0x003fffd5, 22),
    (0x007fffd9, 23),
    (0x003fffd6, 22),
    (0x007fffda, 23),
    (0x007fffdb, 23),
    (0x007fffdc, 23),
    (0x007fffdd, 23),
    (0x007fffde, 23),
    (0x00ffffeb, 24),
    (0x007fffdf, 23),
    (0x00ffffec, 24),
    (0x00ffffed, 24),
    (0x003fffd7, 22),
    (0x007fffe0, 23),
    (0x00ffffee, 24),
    (0x007fffe1, 23),
    (0x007fffe2, 23),
    (0x007fffe3, 23),
    (0x007fffe4, 23),
    (0x001fffdc, 21),
    (0x003fffd8, 22),
    (0x007fffe5, 23),
    (0x003fffd9, 22),
    (0x007fffe6, 23),
    (0x007fffe7, 23),
    (0x00ffffef, 24),
    (0x003fffda, 22),
    (0x001fffdd, 21),
    (0xfffe9, 20),
    (0x003fffdb, 22),
    (0x003fffdc, 22),
    (0x007fffe8, 23),
    (0x007fffe9, 23),
    (0x001fffde, 21),
    (0x007fffea, 23),
    (0x003fffdd, 22),
    (0x003fffde, 22),
    (0x00fffff0, 24),
    (0x001fffdf, 21),
    (0x003fffdf, 22),
    (0x007fffeb, 23),
    (0x007fffec, 23),
    (0x001fffe0, 21),
    (0x001fffe1, 21),
    (0x003fffe0, 22),
    (0x001fffe2, 21),
    (0x007fffed, 23),
    (0x003fffe1, 22),
    (0x007fffee, 23),
    (0x007fffef, 23),
    (0xfffea, 20),
    (0x003fffe2, 22),
    (0x003fffe3, 22),
    (0x003fffe4, 22),
    (0x007ffff0, 23),
    (0x003fffe5, 22),
    (0x003fffe6, 22),
    (0x007ffff1, 23),
    (0x03ffffe0, 26),
    (0x03ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x003fffe7, 22),
    (0x007ffff2, 23),
    (0x003fffe8, 22),
    (0x01ffffec, 25),
    (0x03ffffe2, 26),
    (0x03ffffe3, 26),
    (0x03ffffe4, 26),
    (0x07ffffde, 27),
    (0x07ffffdf, 27),
    (0x03ffffe5, 26),
    (0x00fffff1, 24),
    (0x01ffffed, 25),
    (0x7fff2, 19),
    (0x001fffe3, 21),
    (0x03ffffe6, 26),
    (0x07ffffe0, 27),
    (0x07ffffe1, 27),
    (0x03ffffe7, 26),
    (0x07ffffe2, 27),
    (0x00fffff2, 24),
    (0x001fffe4, 21),
    (0x001fffe5, 21),
    (0x03ffffe8, 26),
    (0x03ffffe9, 26),
    (0x0ffffffd, 28),
    (0x07ffffe3, 27),
    (0x07ffffe4, 27),
    (0x07ffffe5, 27),
    (0xfffec, 20),
    (0x00fffff3, 24),
    (0xfffed, 20),
    (0x001fffe6, 21),
    (0x003fffe9, 22),
    (0x001fffe7, 21),
    (0x001fffe8, 21),
    (0x007ffff3, 23),
    (0x003fffea, 22),
    (0x003fffeb, 22),
    (0x01ffffee, 25),
    (0x01ffffef, 25),
    (0x00fffff4, 24),
    (0x00fffff5, 24),
    (0x03ffffea, 26),
    (0x007ffff4, 23),
    (0x03ffffeb, 26),
    (0x07ffffe6, 27),
    (0x03ffffec, 26),
    (0x03ffffed, 26),
    (0x07ffffe7, 27),
    (0x07ffffe8, 27),
    (0x07ffffe9, 27),
    (0x07ffffea, 27),
    (0x07ffffeb, 27),
    (0x0ffffffe, 28),
    (0x07ffffec, 27),
    (0x07ffffed, 27),
    (0x07ffffee, 27),
    (0x07ffffef, 27),
    (0x07fffff0, 27),
    (0x03ffffee, 26),
    (0x3fffffff, 30),
];

/// Codes this short resolve with one table lookup.
const PRIMARY_BITS: u32 = 10;

/// Indexed by the next [`PRIMARY_BITS`] bits of input: `symbol << 4 | length`
/// for a code no longer than that, `0` for the prefix of a longer one.
static PRIMARY: [u16; 1 << PRIMARY_BITS] = primary_table();

/// Every code as `(code left-aligned in 32 bits, length, symbol)`, sorted.
/// The code is prefix-free and complete, so the entry matching a 32-bit
/// window of input is the last one not greater than it.
static SORTED: [(u32, u8, u16); 257] = sorted_table();

const fn primary_table() -> [u16; 1 << PRIMARY_BITS] {
    let mut table = [0u16; 1 << PRIMARY_BITS];
    let mut symbol = 0;
    while symbol < 256 {
        let (code, len) = CODES[symbol];
        if len as u32 <= PRIMARY_BITS {
            let spare = PRIMARY_BITS - len as u32;
            let first = (code << spare) as usize;
            let mut i = 0;
            while i < 1 << spare {
                table[first + i] = (symbol as u16) << 4 | len as u16;
                i += 1;
            }
        }
        symbol += 1;
    }
    table
}

const fn sorted_table() -> [(u32, u8, u16); 257] {
    let mut table = [(0u32, 0u8, 0u16); 257];
    let mut symbol = 0;
    while symbol < 257 {
        let (code, len) = CODES[symbol];
        let entry = (code << (32 - len as u32), len, symbol as u16);
        // Insertion sort: shift larger entries up.
        let mut at = symbol;
        while at > 0 && table[at - 1].0 > entry.0 {
            table[at] = table[at - 1];
            at -= 1;
        }
        table[at] = entry;
        symbol += 1;
    }
    table
}

/// Appends the decoding of `src` to `dst`.
pub(super) fn decode(src: &[u8], dst: &mut BytesMut) -> Result<(), InvalidHuffman> {
    // The shortest code is 5 bits.
    dst.reserve(src.len() * 8 / 5);
    let mut input = src.iter();
    // The low `bits` bits of `window` are input not yet decoded.
    let mut window = 0u64;
    let mut bits = 0u32;
    loop {
        while bits <= 56 {
            let Some(&byte) = input.next() else { break };
            window = window << 8 | u64::from(byte);
            bits += 8;
        }
        if bits == 0 {
            return Ok(());
        }
        // The undecoded bits at the top, followed by ones: the padding a
        // valid encoding ends with, so a code cut off by the end of input
        // shows up as a match longer than the bits that remain.
        let top = window << (64 - bits) | u64::MAX.checked_shr(bits).unwrap_or(0);
        let entry = PRIMARY[(top >> (64 - PRIMARY_BITS)) as usize];
        let (symbol, len) = if entry != 0 {
            (entry >> 4, u32::from(entry & 0xf))
        } else {
            let top = (top >> 32) as u32;
            let at = SORTED.partition_point(|&(code, _, _)| code <= top);
            let (_, len, symbol) = SORTED[at - 1];
            (symbol, u32::from(len))
        };
        if len > bits {
            // Only padding is left: fewer than 8 bits, all ones.
            let padding = window & (u64::MAX >> (64 - bits));
            return if bits < 8 && padding == (1 << bits) - 1 {
                Ok(())
            } else {
                Err(InvalidHuffman)
            };
        }
        if symbol == EOS {
            return Err(InvalidHuffman);
        }
        dst.put_u8(symbol as u8);
        bits -= len;
    }
}

/// Appends the encoding of `src` to `dst`.
#[cfg(any(test, fuzzing))]
pub(super) fn encode(src: &[u8], dst: &mut Vec<u8>) {
    let mut window = 0u64;
    let mut bits = 0u32;
    for &byte in src {
        let (code, len) = CODES[usize::from(byte)];
        window = window << len | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            dst.push((window >> bits) as u8);
        }
    }
    if bits > 0 {
        let pad = 8 - bits;
        dst.push(((window << pad) as u8) | ((1u16 << pad) - 1) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(src: &[u8]) -> Result<Vec<u8>, InvalidHuffman> {
        let mut out = BytesMut::new();
        decode(src, &mut out)?;
        Ok(out.to_vec())
    }

    #[test]
    fn the_code_is_complete_and_prefix_free() {
        // Kraft equality: the code lengths exactly fill the code space.
        let total: u64 = CODES.iter().map(|&(_, len)| 1u64 << (32 - len)).sum();
        assert_eq!(total, 1 << 32);
        // Sorted by left-aligned value, each code ends where the next starts.
        for pair in SORTED.windows(2) {
            let (code, len, _) = pair[0];
            assert_eq!(u64::from(code) + (1u64 << (32 - len)), u64::from(pair[1].0));
        }
        let (code, len, symbol) = SORTED[256];
        assert_eq!(u64::from(code) + (1u64 << (32 - len)), 1 << 32);
        assert_eq!((symbol, len), (EOS, 30));
    }

    /// RFC 7541 Appendix C.4 and C.6.
    #[test]
    fn rfc_examples() {
        let cases: [(&[u8], &[u8]); 6] = [
            (
                b"www.example.com",
                &[
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
            ),
            (b"no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
            (
                b"custom-key",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
            ),
            (
                b"custom-value",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            ),
            (b"302", &[0x64, 0x02]),
            (b"private", &[0xae, 0xc3, 0x77, 0x1a, 0x4b]),
        ];
        for (plain, coded) in cases {
            assert_eq!(decoded(coded).unwrap(), plain);
            let mut out = Vec::new();
            encode(plain, &mut out);
            assert_eq!(out, coded);
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        for chunk in [1, 2, 3, 7, 64, 256] {
            for piece in all.chunks(chunk) {
                let mut coded = Vec::new();
                encode(piece, &mut coded);
                assert_eq!(decoded(&coded).unwrap(), piece);
            }
        }
        assert_eq!(decoded(&[]).unwrap(), b"");
    }

    #[test]
    fn invalid_padding_and_eos_are_rejected() {
        // "0" is 00000 (5 bits): padding must be ones.
        assert_eq!(decoded(&[0b0000_0111]).unwrap(), b"0");
        assert_eq!(decoded(&[0b0000_0110]), Err(InvalidHuffman));
        // A whole byte of padding is too much.
        assert_eq!(decoded(&[0b0000_0111, 0xff]), Err(InvalidHuffman));
        // EOS itself (30 ones), with or without padding.
        assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xff]), Err(InvalidHuffman));
        assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xfc]), Err(InvalidHuffman));
    }
}

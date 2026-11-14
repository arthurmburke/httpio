//! TCP segment header parsing/serialization (RFC 9293 §3.1), including
//! the MSS, window scale and selective acknowledgment (RFC 2018) options.
//! Timestamps are intentionally out of scope: they would add 12 bytes to
//! every segment.

use std::net::Ipv4Addr;

use super::checksum;

pub const TCP_HDR_LEN: usize = 20;

pub mod flags {
    pub const FIN: u8 = 0b0000_0001;
    pub const SYN: u8 = 0b0000_0010;
    pub const RST: u8 = 0b0000_0100;
    pub const PSH: u8 = 0b0000_1000;
    pub const ACK: u8 = 0b0001_0000;
    pub const URG: u8 = 0b0010_0000;
    pub const ECE: u8 = 0b0100_0000;
    pub const CWR: u8 = 0b1000_0000;
}

pub const OPT_KIND_END: u8 = 0;
pub const OPT_KIND_NOP: u8 = 1;
pub const OPT_KIND_MSS: u8 = 2;
pub const OPT_KIND_SACK_PERMITTED: u8 = 4;
pub const OPT_KIND_SACK: u8 = 5;

/// Most SACK blocks one segment can carry: 4 fit the 40 bytes of option
/// space when no other option is present (RFC 2018 §3).
pub const MAX_SACK_BLOCKS: usize = 4;

/// The `[left, right)` sequence ranges of a SACK option, in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SackBlocks {
    blocks: [(u32, u32); MAX_SACK_BLOCKS],
    count: u8,
}

impl SackBlocks {
    /// Appends a block; ignored once the option is full.
    pub fn push(&mut self, left: u32, right: u32) {
        if let Some(slot) = self.blocks.get_mut(usize::from(self.count)) {
            *slot = (left, right);
            self.count += 1;
        }
    }

    pub fn as_slice(&self) -> &[(u32, u32)] {
        &self.blocks[..usize::from(self.count)]
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Bytes this option occupies on the wire, padded to a multiple of 4.
    fn wire_len(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            4 + 8 * usize::from(self.count)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    /// SACK-permitted (SYN segments only).
    pub sack_permitted: bool,
    /// Selective acknowledgments. This stack sends them only on segments
    /// without payload, so data segments never lose room to them.
    pub sack: SackBlocks,
}

impl TcpOptions {
    fn parse(mut buf: &[u8]) -> Self {
        let mut opts = TcpOptions::default();
        while !buf.is_empty() {
            match buf[0] {
                OPT_KIND_END => break,
                OPT_KIND_NOP => buf = &buf[1..],
                OPT_KIND_MSS if buf.len() >= 4 && buf[1] == 4 => {
                    opts.mss = Some(u16::from_be_bytes([buf[2], buf[3]]));
                    buf = &buf[4..];
                }
                3 if buf.len() >= 3 && buf[1] == 3 => {
                    opts.window_scale = Some(buf[2].min(14));
                    buf = &buf[3..];
                }
                OPT_KIND_SACK_PERMITTED if buf.len() >= 2 && buf[1] == 2 => {
                    opts.sack_permitted = true;
                    buf = &buf[2..];
                }
                OPT_KIND_SACK
                    if buf.len() >= 2
                        && buf[1] >= 10
                        && (buf[1] - 2).is_multiple_of(8)
                        && usize::from(buf[1]) <= buf.len() =>
                {
                    let len = usize::from(buf[1]);
                    for block in buf[2..len].chunks_exact(8) {
                        opts.sack.push(
                            u32::from_be_bytes(block[..4].try_into().unwrap()),
                            u32::from_be_bytes(block[4..].try_into().unwrap()),
                        );
                    }
                    buf = &buf[len..];
                }
                _kind => {
                    // Unknown/other option: length-prefixed per RFC 9293
                    // §3.1 (kind, length, ...); skip it. Malformed
                    // (length 0 or truncated) options stop parsing rather
                    // than risk an infinite loop or out-of-bounds read.
                    if buf.len() < 2 || buf[1] < 2 || (buf[1] as usize) > buf.len() {
                        break;
                    }
                    buf = &buf[buf[1] as usize..];
                }
            }
        }
        opts
    }

    /// Serializes just the MSS option (padded to a 4-byte boundary with
    /// NOPs), the only option this stack ever sends.
    fn write_mss(mss: u16, out: &mut [u8]) -> usize {
        out[0] = OPT_KIND_MSS;
        out[1] = 4;
        out[2..4].copy_from_slice(&mss.to_be_bytes());
        4
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: TcpOptions,
}

impl TcpHeader {
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Parses the TCP header (including options) out of `buf`, which must
    /// contain at least the header; returns the header and the byte
    /// offset where the payload begins. `verify` computes and checks the
    /// checksum (over the IPv4 pseudo-header + segment) in software;
    /// callers pass `false` when the NIC already validated it (RX L4
    /// checksum offload reported GOOD).
    pub fn parse(
        buf: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        verify: bool,
    ) -> Option<(Self, usize)> {
        if buf.len() < TCP_HDR_LEN {
            return None;
        }
        let data_offset_words = (buf[12] >> 4) as usize;
        let hdr_len = data_offset_words * 4;
        if hdr_len < TCP_HDR_LEN || hdr_len > buf.len() {
            return None;
        }

        if verify {
            let pseudo = checksum::ipv4_pseudo_header_sum(
                src_ip,
                dst_ip,
                super::ipv4::PROTO_TCP,
                buf.len() as u16,
            );
            if checksum::fold(checksum::sum16(buf, pseudo)) != 0 {
                return None;
            }
        }

        let options = TcpOptions::parse(&buf[TCP_HDR_LEN..hdr_len]);
        let header = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            seq: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            ack: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            flags: buf[13],
            window: u16::from_be_bytes([buf[14], buf[15]]),
            urgent_pointer: u16::from_be_bytes([buf[18], buf[19]]),
            options,
        };
        Some((header, hdr_len))
    }

    /// Total serialized header length in bytes (20 + options, padded to a
    /// 4-byte boundary).
    pub fn wire_len(&self) -> usize {
        TCP_HDR_LEN
            + if self.options.mss.is_some() { 4 } else { 0 }
            + if self.options.window_scale.is_some() {
                4
            } else {
                0
            }
            + if self.options.sack_permitted { 4 } else { 0 }
            + self.options.sack.wire_len()
    }

    /// Writes the header (and options) into `out` and fills in the
    /// checksum. `out` must be exactly `wire_len()` bytes.
    ///
    /// With `offload_cksum`, only the IPv4 pseudo-header checksum is
    /// written (TX TCP checksum offload): the NIC completes it over the
    /// header + payload. Otherwise the full checksum is computed in
    /// software.
    pub fn write(
        &self,
        out: &mut [u8],
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        offload_cksum: bool,
    ) {
        let hdr_len = self.wire_len();
        debug_assert_eq!(out.len(), hdr_len);

        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..12].copy_from_slice(&self.ack.to_be_bytes());
        out[12] = ((hdr_len / 4) as u8) << 4;
        out[13] = self.flags;
        out[14..16].copy_from_slice(&self.window.to_be_bytes());
        out[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
        out[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());

        if let Some(mss) = self.options.mss {
            TcpOptions::write_mss(mss, &mut out[TCP_HDR_LEN..hdr_len]);
        }

        if let Some(scale) = self.options.window_scale {
            let start = TCP_HDR_LEN + if self.options.mss.is_some() { 4 } else { 0 };
            out[start..start + 4].copy_from_slice(&[1, 3, 3, scale.min(14)]);
        }
        // Whatever precedes these is a multiple of 4 bytes; two NOPs keep
        // each of them one too.
        let mut at = TCP_HDR_LEN
            + if self.options.mss.is_some() { 4 } else { 0 }
            + if self.options.window_scale.is_some() {
                4
            } else {
                0
            };
        if self.options.sack_permitted {
            out[at..at + 4].copy_from_slice(&[1, 1, OPT_KIND_SACK_PERMITTED, 2]);
            at += 4;
        }
        let sack = self.options.sack.as_slice();
        if !sack.is_empty() {
            out[at..at + 4].copy_from_slice(&[1, 1, OPT_KIND_SACK, 2 + 8 * sack.len() as u8]);
            at += 4;
            for &(left, right) in sack {
                out[at..at + 4].copy_from_slice(&left.to_be_bytes());
                out[at + 4..at + 8].copy_from_slice(&right.to_be_bytes());
                at += 8;
            }
        }
        let pseudo = checksum::ipv4_pseudo_header_sum(
            src_ip,
            dst_ip,
            super::ipv4::PROTO_TCP,
            (hdr_len + payload.len()) as u16,
        );
        let csum = if offload_cksum {
            // DPDK TX L4 offload contract (`rte_ipv4_phdr_cksum`): the field
            // carries the folded, NOT complemented, pseudo-header sum; the
            // NIC sums the segment on top of it and complements.
            checksum::fold_raw(pseudo)
        } else {
            checksum::fold(checksum::sum16(payload, checksum::sum16(out, pseudo)))
        };
        out[16..18].copy_from_slice(&csum.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn header(mss: Option<u16>) -> TcpHeader {
        TcpHeader {
            src_port: 12345,
            dst_port: 80,
            seq: 0xdead_beef,
            ack: 0x0102_0304,
            flags: 0x18,
            window: 0xffff,
            urgent_pointer: 0,
            options: TcpOptions {
                mss,
                ..Default::default()
            },
        }
    }

    fn build(h: &TcpHeader, payload: &[u8], offload: bool) -> Vec<u8> {
        let mut hdr = vec![0u8; h.wire_len()];
        h.write(&mut hdr, payload, SRC, DST, offload);
        let mut seg = hdr;
        seg.extend_from_slice(payload);
        seg
    }

    fn payloads() -> Vec<Vec<u8>> {
        vec![
            vec![],
            (0..64u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(200))
                .collect(),
            (0..65u8)
                .map(|i| i.wrapping_mul(91).wrapping_add(255))
                .collect(),
            vec![0xff; 1461],
        ]
    }

    #[test]
    fn window_scale_options_round_trip_with_and_without_mss() {
        for mss in [None, Some(1460)] {
            for scale in [0, 4, 14, 255] {
                let mut h = header(mss);
                h.options.window_scale = Some(scale);
                let wire = build(&h, b"payload", false);
                let (decoded, len) = TcpHeader::parse(&wire, SRC, DST, true).unwrap();
                assert_eq!(len, h.wire_len());
                assert_eq!(decoded.options.window_scale, Some(scale.min(14)));
                assert_eq!(decoded.options.mss, mss);
            }
        }
    }

    #[test]
    fn sack_options_round_trip_alongside_the_others() {
        for mss in [None, Some(1460)] {
            for scale in [None, Some(4)] {
                // SYN: SACK-permitted.
                let mut h = header(mss);
                h.options.window_scale = scale;
                h.options.sack_permitted = true;
                let wire = build(&h, &[], false);
                let (decoded, len) = TcpHeader::parse(&wire, SRC, DST, true).unwrap();
                assert_eq!(len, h.wire_len());
                assert_eq!(decoded.options, h.options);
            }
        }
        // Pure ACK: one to four blocks, including across sequence wrap.
        for count in 1..=MAX_SACK_BLOCKS as u32 {
            let mut h = header(None);
            for i in 0..count {
                h.options.sack.push(
                    (u32::MAX - 500).wrapping_add(i * 1000),
                    u32::MAX.wrapping_add(i * 1000),
                );
            }
            assert_eq!(h.wire_len(), 20 + 4 + 8 * count as usize);
            let wire = build(&h, &[], false);
            let (decoded, len) = TcpHeader::parse(&wire, SRC, DST, true).unwrap();
            assert_eq!(len, h.wire_len());
            assert_eq!(decoded.options.sack, h.options.sack);
            assert_eq!(decoded.options.sack.as_slice().len(), count as usize);
        }
        // A fifth block does not fit and is dropped rather than overflowing.
        let mut blocks = SackBlocks::default();
        for i in 0..5 {
            blocks.push(i, i + 1);
        }
        assert_eq!(blocks.as_slice().len(), MAX_SACK_BLOCKS);
        // A malformed SACK length is skipped, not misread.
        let mut h = header(None);
        h.options.sack.push(1, 2);
        let mut wire = build(&h, &[], false);
        wire[23] = 9;
        let (decoded, _) = TcpHeader::parse(&wire, SRC, DST, false).unwrap();
        assert!(decoded.options.sack.is_empty());
    }

    #[test]
    fn software_checksum_verifies() {
        for mss in [None, Some(1460)] {
            for p in payloads() {
                let seg = build(&header(mss), &p, false);
                assert!(TcpHeader::parse(&seg, SRC, DST, true).is_some());
            }
        }
    }

    #[test]
    fn offload_checksum_completed_by_nic_verifies() {
        for mss in [None, Some(1460)] {
            for p in payloads() {
                let h = header(mss);
                let mut seg = build(&h, &p, true);
                // Not valid before the NIC completes it (unless degenerate).
                let seed = u16::from_be_bytes([seg[16], seg[17]]) as u32;
                // Simulate NIC: zero field, sum segment on top of seed, complement.
                seg[16] = 0;
                seg[17] = 0;
                let csum = checksum::fold(checksum::sum16(&seg, seed));
                seg[16..18].copy_from_slice(&csum.to_be_bytes());
                assert!(
                    TcpHeader::parse(&seg, SRC, DST, true).is_some(),
                    "mss={:?} payload_len={}",
                    mss,
                    p.len()
                );
            }
        }
    }

    #[test]
    fn offload_field_is_uncomplemented_pseudo_sum() {
        let h = header(None);
        let p = [1u8, 2, 3];
        let seg = build(&h, &p, true);
        let pseudo = checksum::ipv4_pseudo_header_sum(SRC, DST, super::super::ipv4::PROTO_TCP, 23);
        assert_eq!(
            u16::from_be_bytes([seg[16], seg[17]]),
            checksum::fold_raw(pseudo)
        );
    }
}

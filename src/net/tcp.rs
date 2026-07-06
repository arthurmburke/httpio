//! TCP segment header parsing/serialization (RFC 9293 §3.1), including the
//! MSS option. Window scale / SACK / timestamps are intentionally out of
//! scope -- see the top-level README for what this stack does and doesn't
//! implement.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
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
    /// offset where the payload begins. Verifies the checksum using the
    /// IPv4 pseudo-header of the enclosing packet.
    pub fn parse(buf: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Option<(Self, usize)> {
        if buf.len() < TCP_HDR_LEN {
            return None;
        }
        let data_offset_words = (buf[12] >> 4) as usize;
        let hdr_len = data_offset_words * 4;
        if hdr_len < TCP_HDR_LEN || hdr_len > buf.len() {
            return None;
        }

        let pseudo = checksum::ipv4_pseudo_header_sum(
            src_ip,
            dst_ip,
            super::ipv4::PROTO_TCP,
            buf.len() as u16,
        );
        if checksum::fold(checksum::sum16(buf, pseudo)) != 0 {
            return None;
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
        TCP_HDR_LEN + if self.options.mss.is_some() { 4 } else { 0 }
    }

    /// Writes the header (and options) into `out`, then fills in the
    /// checksum computed over header + `payload` using the IPv4
    /// pseudo-header. `out` must be exactly `wire_len()` bytes.
    pub fn write(&self, out: &mut [u8], payload: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
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

        let pseudo = checksum::ipv4_pseudo_header_sum(
            src_ip,
            dst_ip,
            super::ipv4::PROTO_TCP,
            (hdr_len + payload.len()) as u16,
        );
        let sum = checksum::sum16(payload, checksum::sum16(out, pseudo));
        let csum = checksum::fold(sum);
        out[16..18].copy_from_slice(&csum.to_be_bytes());
    }
}

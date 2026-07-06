//! IPv4 header parsing/serialization (no options: fixed 20-byte header).

use super::checksum;

pub const IPV4_HDR_LEN: usize = 20;
pub const PROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    /// Parses a header with no options (IHL must be 5). Returns the
    /// header and, since callers need it to slice the payload, its byte
    /// length (always `IPV4_HDR_LEN` for this parser).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < IPV4_HDR_LEN {
            return None;
        }
        let version_ihl = buf[0];
        if version_ihl >> 4 != 4 {
            return None; // not IPv4
        }
        if version_ihl & 0x0F != 5 {
            return None; // options present; unsupported by this parser
        }
        // Verify checksum: summing the whole header (with its own
        // checksum field included) folds to 0 iff it's valid.
        if checksum::checksum(&buf[..IPV4_HDR_LEN]) != 0 {
            return None;
        }
        Some(Self {
            dscp_ecn: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags_fragment_offset: u16::from_be_bytes([buf[6], buf[7]]),
            ttl: buf[8],
            protocol: buf[9],
            src: buf[12..16].try_into().unwrap(),
            dst: buf[16..20].try_into().unwrap(),
        })
    }

    /// Writes the 20-byte header into `out` (which must be at least
    /// `IPV4_HDR_LEN` bytes) and fills in the header checksum.
    pub fn write(&self, out: &mut [u8]) {
        out[0] = (4 << 4) | 5;
        out[1] = self.dscp_ecn;
        out[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        out[6..8].copy_from_slice(&self.flags_fragment_offset.to_be_bytes());
        out[8] = self.ttl;
        out[9] = self.protocol;
        out[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
        out[12..16].copy_from_slice(&self.src);
        out[16..20].copy_from_slice(&self.dst);
        let csum = checksum::checksum(&out[..IPV4_HDR_LEN]);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
    }
}

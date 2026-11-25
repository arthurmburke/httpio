//! UDP datagram header parsing/serialization (RFC 768) over IPv4.
//!
//! The header is fixed at 8 bytes: source port, destination port, length
//! (header + payload) and checksum. Over IPv4 the checksum is optional: a
//! sender that does not compute one transmits 0, so a checksum that
//! genuinely computes to 0 is sent as `0xFFFF` instead (the two are the
//! same value in one's complement arithmetic).

use std::net::Ipv4Addr;

use super::checksum;

pub const UDP_HDR_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    /// Header + payload, in bytes.
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parses the header at the start of `buf`, the IPv4 payload. Returns
    /// the header and the length of the datagram's payload, which is what
    /// the UDP length field says, not what is left of `buf`: an Ethernet
    /// frame may be padded past the end of the datagram.
    ///
    /// Rejects a length shorter than the header or longer than `buf`.
    /// `verify` checks the checksum in software over the IPv4
    /// pseudo-header and the datagram; callers pass `false` when the NIC
    /// already validated it (RX UDP checksum offload reported GOOD). A
    /// checksum field of 0 means the sender computed none, and is accepted
    /// without verification.
    pub fn parse(
        buf: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        verify: bool,
    ) -> Option<(Self, usize)> {
        if buf.len() < UDP_HDR_LEN {
            return None;
        }
        let header = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length: u16::from_be_bytes([buf[4], buf[5]]),
            checksum: u16::from_be_bytes([buf[6], buf[7]]),
        };
        let length = usize::from(header.length);
        if length < UDP_HDR_LEN || length > buf.len() {
            return None;
        }
        if verify && !checksum_ok(&buf[..length], src_ip, dst_ip) {
            return None;
        }
        Some((header, length - UDP_HDR_LEN))
    }

    /// Writes the 8-byte header for a datagram carrying `payload` into
    /// `out` (exactly [`UDP_HDR_LEN`] bytes), setting `length` from the
    /// payload and ignoring `self.length` and `self.checksum`.
    ///
    /// With `offload_cksum`, only the IPv4 pseudo-header sum is written
    /// (TX UDP checksum offload): the NIC completes it over the header and
    /// payload. Otherwise the full checksum is computed in software, a
    /// computed 0 going out as `0xFFFF` (RFC 768), since a 0 on the wire
    /// would mean "no checksum".
    ///
    /// `payload` is only read for the software checksum, so the caller may
    /// keep it elsewhere than right after `out` (a separate, chained mbuf).
    pub fn write(
        &self,
        out: &mut [u8],
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        offload_cksum: bool,
    ) {
        debug_assert_eq!(out.len(), UDP_HDR_LEN);
        let length = (UDP_HDR_LEN + payload.len()) as u16;
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&length.to_be_bytes());
        out[6..8].copy_from_slice(&[0, 0]);
        let pseudo =
            checksum::ipv4_pseudo_header_sum(src_ip, dst_ip, super::ipv4::PROTO_UDP, length);
        let csum = if offload_cksum {
            // DPDK TX L4 offload contract (`rte_ipv4_phdr_cksum`): the
            // folded, NOT complemented, pseudo-header sum; the NIC sums the
            // datagram on top of it, complements, and itself maps a 0 to
            // 0xFFFF for UDP.
            checksum::fold_raw(pseudo)
        } else {
            software_checksum(checksum::sum16(payload, checksum::sum16(out, pseudo)))
        };
        out[6..8].copy_from_slice(&csum.to_be_bytes());
    }
}

/// Whether `datagram` (exactly the header and payload, as the UDP length
/// field delimits them) carries a valid checksum, or none (a 0 field).
pub fn checksum_ok(datagram: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
    if datagram.len() < UDP_HDR_LEN || datagram[6..8] == [0, 0] {
        return datagram.len() >= UDP_HDR_LEN;
    }
    let pseudo = checksum::ipv4_pseudo_header_sum(
        src_ip,
        dst_ip,
        super::ipv4::PROTO_UDP,
        datagram.len() as u16,
    );
    // Summing the datagram with its own checksum included folds to 0 iff
    // it is valid; a transmitted 0xFFFF (a computed 0) sums the same as 0
    // would have.
    checksum::fold(checksum::sum16(datagram, pseudo)) == 0
}

/// The wire checksum for a datagram whose pseudo-header, header (checksum
/// field zero) and payload sum to `sum`: RFC 768 sends a computed 0 as
/// all ones, since 0 means "not computed".
pub fn software_checksum(sum: u32) -> u16 {
    match checksum::fold(sum) {
        0 => 0xFFFF,
        csum => csum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn header(src_port: u16, dst_port: u16) -> UdpHeader {
        UdpHeader {
            src_port,
            dst_port,
            length: 0,
            checksum: 0,
        }
    }

    fn build(
        h: &UdpHeader,
        payload: &[u8],
        src: Ipv4Addr,
        dst: Ipv4Addr,
        offload: bool,
    ) -> Vec<u8> {
        let mut out = vec![0u8; UDP_HDR_LEN];
        h.write(&mut out, payload, src, dst, offload);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn known_answer_checksum() {
        // 192.168.0.31:20 -> 192.168.0.30:10, payload "Hi": computed
        // independently (one's complement sum over pseudo-header, header
        // and payload) as 0x35c5.
        let (src, dst) = (
            Ipv4Addr::new(192, 168, 0, 31),
            Ipv4Addr::new(192, 168, 0, 30),
        );
        let wire = build(&header(20, 10), b"Hi", src, dst, false);
        assert_eq!(wire, [0, 20, 0, 10, 0, 10, 0x35, 0xc5, b'H', b'i']);
        let (parsed, len) = UdpHeader::parse(&wire, src, dst, true).unwrap();
        assert_eq!(len, 2);
        assert_eq!(
            parsed,
            UdpHeader {
                src_port: 20,
                dst_port: 10,
                length: 10,
                checksum: 0x35c5
            }
        );
    }

    #[test]
    fn a_computed_zero_checksum_is_sent_as_all_ones_and_verifies() {
        // This payload makes the sum come out to exactly 0xFFFF, so the
        // complement is 0.
        let payload = [0xe0, 0x1f];
        let wire = build(&header(1000, 2000), &payload, SRC, DST, false);
        assert_eq!(&wire[6..8], &[0xff, 0xff]);
        assert!(UdpHeader::parse(&wire, SRC, DST, true).is_some());
        assert_eq!(software_checksum(0xffff), 0xffff);
    }

    #[test]
    fn checksum_zero_means_none_and_is_accepted() {
        let mut wire = build(&header(1, 2), b"payload", SRC, DST, false);
        wire[6] = 0;
        wire[7] = 0;
        // Even with a payload the checksum would not match.
        wire[8] ^= 0xff;
        assert_eq!(UdpHeader::parse(&wire, SRC, DST, true).unwrap().1, 7);
    }

    #[test]
    fn corruption_is_detected_unless_verification_is_skipped() {
        for len in [0usize, 1, 64, 65, 1472] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let mut wire = build(&header(5353, 53), &payload, SRC, DST, false);
            assert!(
                UdpHeader::parse(&wire, SRC, DST, true).is_some(),
                "len {len}"
            );
            // A different pseudo-header (wrong destination) fails too.
            assert!(UdpHeader::parse(&wire, SRC, Ipv4Addr::new(10, 0, 0, 3), true).is_none());
            let last = wire.len() - 1;
            wire[last] ^= 0x01;
            assert!(
                UdpHeader::parse(&wire, SRC, DST, true).is_none(),
                "len {len}"
            );
            assert!(UdpHeader::parse(&wire, SRC, DST, false).is_some());
        }
    }

    #[test]
    fn length_bounds_and_padding() {
        let mut wire = build(&header(1, 2), b"abc", SRC, DST, false);
        // Ethernet padding after the datagram is not payload.
        wire.extend_from_slice(&[0; 20]);
        assert_eq!(UdpHeader::parse(&wire, SRC, DST, true).unwrap().1, 3);
        // Shorter than a header, or longer than the buffer, is malformed.
        assert!(UdpHeader::parse(&wire[..7], SRC, DST, false).is_none());
        let mut short = wire.clone();
        short[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(UdpHeader::parse(&short, SRC, DST, false).is_none());
        let mut long = wire[..11].to_vec();
        long[4..6].copy_from_slice(&12u16.to_be_bytes());
        assert!(UdpHeader::parse(&long, SRC, DST, false).is_none());
        // An empty datagram is fine.
        let empty = build(&header(1, 2), &[], SRC, DST, false);
        assert_eq!(UdpHeader::parse(&empty, SRC, DST, true).unwrap().1, 0);
    }

    #[test]
    fn offload_checksum_completed_by_nic_verifies() {
        for len in [0usize, 3, 64, 1472] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 91 + 255) as u8).collect();
            let mut wire = build(&header(4000, 4001), &payload, SRC, DST, true);
            let pseudo = checksum::ipv4_pseudo_header_sum(
                SRC,
                DST,
                super::super::ipv4::PROTO_UDP,
                (UDP_HDR_LEN + len) as u16,
            );
            assert_eq!(
                u16::from_be_bytes([wire[6], wire[7]]),
                checksum::fold_raw(pseudo)
            );
            // What the NIC does: sum over the datagram on top of the seed
            // it finds in the field, complement, 0 -> 0xFFFF.
            let seed = u32::from(u16::from_be_bytes([wire[6], wire[7]]));
            wire[6..8].fill(0);
            let csum = software_checksum(checksum::sum16(&wire, seed));
            wire[6..8].copy_from_slice(&csum.to_be_bytes());
            assert!(
                UdpHeader::parse(&wire, SRC, DST, true).is_some(),
                "len {len}"
            );
        }
    }
}

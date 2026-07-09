//! Minimal ARP (RFC 826) for IPv4-over-Ethernet: just enough to resolve a
//! next-hop MAC address and answer requests for our own IP, since without
//! it there is no way to actually address an Ethernet frame to a real
//! peer/gateway.

pub const ARP_HDR_LEN: usize = 28;
pub const ETHERTYPE_ARP: u16 = 0x0806;

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const HLEN_ETHERNET: u8 = 6;
const PLEN_IPV4: u8 = 4;

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < ARP_HDR_LEN {
            return None;
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        if htype != HTYPE_ETHERNET
            || ptype != PTYPE_IPV4
            || buf[4] != HLEN_ETHERNET
            || buf[5] != PLEN_IPV4
        {
            return None;
        }
        Some(Self {
            operation: u16::from_be_bytes([buf[6], buf[7]]),
            sender_mac: buf[8..14].try_into().unwrap(),
            sender_ip: buf[14..18].try_into().unwrap(),
            target_mac: buf[18..24].try_into().unwrap(),
            target_ip: buf[24..28].try_into().unwrap(),
        })
    }

    pub fn write(&self, out: &mut [u8]) {
        out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        out[4] = HLEN_ETHERNET;
        out[5] = PLEN_IPV4;
        out[6..8].copy_from_slice(&self.operation.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip);
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip);
    }
}

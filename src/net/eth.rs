//! Ethernet II header parsing/serialization.

pub const ETH_HDR_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < ETH_HDR_LEN {
            return None;
        }
        Some(Self {
            dst: buf[0..6].try_into().unwrap(),
            src: buf[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes([buf[12], buf[13]]),
        })
    }

    pub fn write(&self, out: &mut [u8]) {
        out[0..6].copy_from_slice(&self.dst);
        out[6..12].copy_from_slice(&self.src);
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    }
}

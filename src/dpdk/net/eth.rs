//! Ethernet II header parsing/serialization.

pub const ETH_HDR_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// A 48-bit Ethernet (MAC) address, in wire (network) byte order.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct EthAddr([u8; 6]);

impl EthAddr {
    /// `ff:ff:ff:ff:ff:ff`: every station on the segment.
    pub const BROADCAST: EthAddr = EthAddr([0xff; 6]);
    /// `00:00:00:00:00:00`: "unknown", e.g. an ARP request's target.
    pub const ZERO: EthAddr = EthAddr([0; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl std::fmt::Display for EthAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl From<EthAddr> for [u8; 6] {
    fn from(addr: EthAddr) -> Self {
        addr.0
    }
}

impl AsRef<[u8]> for EthAddr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EthAddr {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<[u8; 6]> for EthAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for EthAddr {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 6 {
            return Err("Ethernet address buffer too short");
        }
        let mut arr = [0u8; 6];
        arr.copy_from_slice(&value[0..6]);
        Ok(Self(arr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: EthAddr,
    pub src: EthAddr,
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
        out[0..6].copy_from_slice(self.dst.as_ref());
        out[6..12].copy_from_slice(self.src.as_ref());
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    }
}

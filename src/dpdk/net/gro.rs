//! Burst-local TCP/IPv4 GRO. Validate each original packet before DPDK
//! merges it: merged checksums are intentionally not recomputed by GRO.
use super::{eth, ipv4, tcp};
use crate::dpdk::{Mbuf, ffi};

pub(crate) fn prepare(packet: &mut Mbuf) -> bool {
    if packet.rx_ip_cksum_bad() || packet.rx_l4_cksum_bad() {
        return false;
    }
    let frame = packet.data();
    if frame.len() != packet.pkt_len() as usize {
        return false;
    }
    let Some(ether) = eth::EthHeader::parse(frame) else {
        return false;
    };
    if ether.ethertype != eth::ETHERTYPE_IPV4 {
        return false;
    }
    let Some(ip) = ipv4::Ipv4Header::parse(&frame[14..], !packet.rx_ip_cksum_good()) else {
        return false;
    };
    if ip.protocol != ipv4::PROTO_TCP || ip.flags_fragment_offset & 0x3fff != 0 {
        return false;
    }
    let end = 14 + ip.total_length as usize;
    if end > frame.len() || end < 54 {
        return false;
    }
    if end <= 54 || end != frame.len() || frame[46] != 0x50 || frame[47] != tcp::flags::ACK {
        return false;
    }
    let Some((header, len)) =
        tcp::TcpHeader::parse(&frame[34..end], ip.src, ip.dst, !packet.rx_l4_cksum_good())
    else {
        return false;
    };
    // Keep control packets and TCP options out of aggregation. GRO requires ACK-only packets.
    if header.flags != tcp::flags::ACK || len != 20 || end <= 54 || end != frame.len() {
        return false;
    }
    unsafe {
        let raw = packet.as_raw();
        (*raw).__bindgen_anon_1.packet_type =
            ffi::RTE_PTYPE_L2_ETHER | ffi::RTE_PTYPE_L3_IPV4 | ffi::RTE_PTYPE_L4_TCP;
        (*raw).__bindgen_anon_3.tx_offload = 14 | (20 << 7) | (20 << 16);
        (*raw).ol_flags = ((*raw).ol_flags
            & !((ffi::RTE_MBUF_F_RX_IP_CKSUM_MASK | ffi::RTE_MBUF_F_RX_L4_CKSUM_MASK) as u64))
            | ffi::RTE_MBUF_F_RX_IP_CKSUM_GOOD as u64
            | ffi::RTE_MBUF_F_RX_L4_CKSUM_GOOD as u64;
    }
    true
}

/// Takes ownership of the input pointers and returns the compacted count.
/// Callers own exactly the first returned-count pointers afterward.
pub(crate) unsafe fn merge(packets: &mut [*mut ffi::rte_mbuf], count: usize) -> usize {
    let params = ffi::rte_gro_param {
        gro_types: ffi::RTE_GRO_TCP_IPV4 as u64,
        max_flow_num: 64,
        max_item_per_flow: 64,
        socket_id: 0,
    };
    unsafe { ffi::rte_gro_reassemble_burst(packets.as_mut_ptr(), count as u16, &params) as usize }
}

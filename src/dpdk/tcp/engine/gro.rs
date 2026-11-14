//! Burst-local TCP/IPv4 GRO. Validate each original packet before DPDK
//! merges it: merged checksums are intentionally not recomputed by GRO.
use crate::dpdk::net::{eth, ipv4, tcp};
use crate::dpdk::{Mbuf, ffi};

pub fn prepare(packet: &mut Mbuf) -> bool {
    if packet.rx_ip_cksum_bad() || packet.rx_l4_cksum_bad() {
        return false;
    }
    let frame = packet.data();
    if frame.len() != packet.pkt_len() as usize {
        return false;
    }
    // Cheap eligibility checks precede parsing/checksumming. Pure ACKs,
    // control packets and packets with options are handled by the normal
    // RX path, which still validates their headers and checksums.
    if !candidate(frame) {
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
    if end != frame.len() {
        return false;
    }
    // Eligibility is established, but the TCP checksum must still validate.
    if tcp::TcpHeader::parse(&frame[34..end], ip.src, ip.dst, !packet.rx_l4_cksum_good()).is_none()
    {
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

fn candidate(frame: &[u8]) -> bool {
    frame.len() > 54 && frame[14] == 0x45 && frame[46] == 0x50 && frame[47] == tcp::flags::ACK
}

/// Takes ownership of the input pointers and returns the compacted count.
/// Callers own exactly the first returned-count pointers afterward.
pub unsafe fn merge(packets: &mut [*mut ffi::rte_mbuf], count: usize) -> usize {
    let params = ffi::rte_gro_param {
        gro_types: ffi::RTE_GRO_TCP_IPV4 as u64,
        max_flow_num: 64,
        max_item_per_flow: 64,
        socket_id: 0,
    };
    unsafe { ffi::rte_gro_reassemble_burst(packets.as_mut_ptr(), count as u16, &params) as usize }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_controls_options_and_truncation_before_validation() {
        let mut frame = [0; 55];
        frame[14] = 0x45;
        frame[46] = 0x50;
        frame[47] = tcp::flags::ACK;
        assert!(candidate(&frame));
        for length in 0..=54 {
            assert!(!candidate(&frame[..length]));
        }
        for flags in [
            tcp::flags::SYN,
            tcp::flags::ACK | tcp::flags::PSH,
            tcp::flags::ACK | tcp::flags::FIN,
            tcp::flags::RST,
        ] {
            frame[47] = flags;
            assert!(!candidate(&frame));
        }
        frame[47] = tcp::flags::ACK;
        frame[14] = 0x46;
        assert!(!candidate(&frame));
        frame[14] = 0x45;
        frame[46] = 0x60;
        assert!(!candidate(&frame));
    }
}

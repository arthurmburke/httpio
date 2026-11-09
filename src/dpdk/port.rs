//! Safe wrapper around a single ethdev port: configure, start, rx/tx burst.

use std::ptr;

use super::ffi;
use super::mbuf::Mbuf;
use super::mempool::Mempool;

#[derive(Debug)]
pub struct PortError {
    pub what: &'static str,
    pub rc: i32,
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed with rc={}", self.what, self.rc)
    }
}
impl std::error::Error for PortError {}

fn check(what: &'static str, rc: i32) -> Result<(), PortError> {
    if rc < 0 {
        Err(PortError { what, rc })
    } else {
        Ok(())
    }
}

pub struct EthPort {
    port_id: u16,
    mtu: u32,
    /// The NIC will compute IPv4 + TCP checksums on TX (both offloads were
    /// available and enabled), so the stack writes only the TCP
    /// pseudo-header checksum and leaves the IP checksum zero.
    tx_cksum_offload: bool,
    /// The NIC validates IPv4 + TCP checksums on RX and reports the result
    /// via mbuf flags, so the stack can skip software verification when the
    /// flag says GOOD.
    rx_cksum_offload: bool,
}

impl EthPort {
    pub fn count_avail() -> u16 {
        unsafe { ffi::rte_eth_dev_count_avail() }
    }

    /// Configures, sets up a single RX/TX queue pair, and starts the given
    /// port. `mtu` bounds the largest frame the device will accept
    /// (payload, not including the Ethernet header/CRC).
    pub fn init(
        port_id: u16,
        rx_pool: &Mempool,
        nb_rx_desc: u16,
        nb_tx_desc: u16,
        mtu: u32,
        socket_id: i32,
    ) -> Result<Self, PortError> {
        let mut info: ffi::rte_eth_dev_info = unsafe { core::mem::zeroed() };
        check("rte_eth_dev_info_get", unsafe {
            ffi::rte_eth_dev_info_get(port_id, &mut info)
        })?;

        // Enable IPv4 + TCP checksum offload where the device supports it,
        // masking the desired bits against the reported capabilities so
        // `rte_eth_dev_configure` never rejects an unsupported offload.
        // Port-level offloads apply to all queues in DPDK, so setting them
        // in `[rt]xmode.offloads` here (with a NULL per-queue conf below)
        // is sufficient.
        let tx_want =
            (ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | ffi::RTE_ETH_TX_OFFLOAD_TCP_CKSUM) as u64;
        let rx_want =
            (ffi::RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | ffi::RTE_ETH_RX_OFFLOAD_TCP_CKSUM) as u64;
        let tx_en = tx_want & info.tx_offload_capa;
        let rx_en = rx_want & info.rx_offload_capa;
        // Take the fast path only when BOTH IPv4 and TCP checksums can be
        // offloaded together (our frames always carry both); otherwise fall
        // back to full software checksums to avoid a mixed hardware/software
        // state per packet.
        let tx_cksum_offload = tx_en == tx_want;
        let rx_cksum_offload = rx_en == rx_want;

        // Single rx queue (0), single tx queue (0). A zeroed `rte_eth_conf`
        // is the DPDK-conventional starting point (like the sample apps'
        // memset); the MTU and offloads are then set.
        // SAFETY: `rte_eth_conf` is plain C config data; all-zero is valid.
        let mut conf: ffi::rte_eth_conf = unsafe { core::mem::zeroed() };
        conf.rxmode.mtu = mtu;
        conf.txmode.offloads = tx_en;
        conf.rxmode.offloads = rx_en;

        check("rte_eth_dev_configure", unsafe {
            ffi::rte_eth_dev_configure(port_id, 1, 1, &conf)
        })?;

        check("rte_eth_rx_queue_setup", unsafe {
            ffi::rte_eth_rx_queue_setup(
                port_id,
                0,
                nb_rx_desc,
                socket_id as u32,
                ptr::null(),
                rx_pool.as_raw(),
            )
        })?;

        check("rte_eth_tx_queue_setup", unsafe {
            ffi::rte_eth_tx_queue_setup(port_id, 0, nb_tx_desc, socket_id as u32, ptr::null())
        })?;

        check("rte_eth_dev_start", unsafe {
            ffi::rte_eth_dev_start(port_id)
        })?;

        // Promiscuous mode: this stack terminates TCP at the DPDK port
        // itself rather than relying on the kernel/ARP for delivery, so it
        // needs to see frames addressed to the port's own MAC without
        // depending on switch/NIC filtering being set up in advance.
        check("rte_eth_promiscuous_enable", unsafe {
            ffi::rte_eth_promiscuous_enable(port_id)
        })?;

        Ok(Self {
            port_id,
            mtu,
            tx_cksum_offload,
            rx_cksum_offload,
        })
    }

    /// Whether IPv4 + TCP TX checksum offload is active on this port. When
    /// true, outgoing frames should carry only the TCP pseudo-header
    /// checksum (IP checksum zero) with the mbuf offload flags set.
    pub fn tx_cksum_offload(&self) -> bool {
        self.tx_cksum_offload
    }

    /// Whether IPv4 + TCP RX checksum offload is active on this port.
    pub fn rx_cksum_offload(&self) -> bool {
        self.rx_cksum_offload
    }

    pub fn mac_addr(&self) -> Result<ffi::rte_ether_addr, PortError> {
        // SAFETY: `rte_ether_addr` is a plain 6-byte struct; zeroed is a
        // valid placeholder that `rte_eth_macaddr_get` overwrites.
        let mut addr: ffi::rte_ether_addr = unsafe { core::mem::zeroed() };
        check("rte_eth_macaddr_get", unsafe {
            ffi::rte_eth_macaddr_get(self.port_id, &mut addr)
        })?;
        Ok(addr)
    }

    /// Collects up to `max` packets (at most 64) into an owned vector.
    /// Use `rx_packets` to avoid the collection allocation on hot paths.
    pub fn rx_burst(&self, max: usize) -> Vec<Mbuf> {
        self.rx_packets(max).collect()
    }

    /// Allocation-free RX batch. Unconsumed packets are freed on drop.
    pub fn rx_packets(&self, max: usize) -> impl ExactSizeIterator<Item = Mbuf> {
        let mut packets: [Option<Mbuf>; 64] = std::array::from_fn(|_| None);
        let mut raw = [ptr::null_mut(); 64];
        let received =
            unsafe { ffi::rte_eth_rx_burst(self.port_id, 0, raw.as_mut_ptr(), max.min(64) as u16) }
                as usize;
        for i in 0..received {
            packets[i] = Some(unsafe { Mbuf::from_raw(raw[i]) });
        }
        packets.into_iter().take(received).map(Option::unwrap)
    }

    /// Transmits a batch, returning packets the driver did not accept.
    pub fn tx_burst(&self, mut mbufs: Vec<Mbuf>) -> Vec<Mbuf> {
        self.tx_burst_in_place(&mut mbufs);
        mbufs
    }

    /// Keeps the caller's allocation; removes only packets owned by the NIC.
    pub fn tx_burst_in_place(&self, mbufs: &mut Vec<Mbuf>) {
        let mut accepted = 0;
        while accepted < mbufs.len() {
            let n = (mbufs.len() - accepted).min(64);
            let mut raw = [ptr::null_mut(); 64];
            for (dst, packet) in raw.iter_mut().zip(&mbufs[accepted..accepted + n]) {
                *dst = packet.as_raw();
            }
            let sent = unsafe { ffi::rte_eth_tx_burst(self.port_id, 0, raw.as_mut_ptr(), n as u16) }
                as usize;
            accepted += sent;
            if sent < n {
                break;
            }
        }
        for packet in mbufs.drain(..accepted) {
            // The NIC owns these packets now; do not run Mbuf::drop.
            std::mem::forget(packet);
        }
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }
}

impl Drop for EthPort {
    fn drop(&mut self) {
        // Stop *and* close: `rte_eth_dev_stop` alone leaves the device
        // configured and, for the tap PMD, keeps the kernel tap attached
        // with its multi-queue ownership held -- so a subsequent process
        // re-attaching to the same persistent tap can't move packets
        // ("Exclusivity flag on, cannot modify"). `rte_eth_dev_close`
        // fully releases it.
        unsafe {
            ffi::rte_eth_dev_stop(self.port_id);
            ffi::rte_eth_dev_close(self.port_id);
        }
    }
}

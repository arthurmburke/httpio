//! Safe wrapper around a single ethdev port: configure, start, rx/tx burst.

use std::ptr;

use super::ffi;
use super::mbuf::Mbuf;
use super::mempool::PktMbufPool;

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
        rx_pool: &PktMbufPool,
        nb_rx_desc: u16,
        nb_tx_desc: u16,
        mtu: u32,
        socket_id: i32,
    ) -> Result<Self, PortError> {
        // SAFETY: single rx queue (0), single tx queue (0); eth_conf is
        // built to a zeroed default inside the shim against the real
        // struct rte_eth_conf layout (see csrc/shim.c).
        check("rte_eth_dev_configure", unsafe {
            ffi::dpdk_shim_eth_dev_configure_default(port_id, 1, 1, mtu)
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

        Ok(Self { port_id })
    }

    pub fn mac_addr(&self) -> Result<ffi::rte_ether_addr, PortError> {
        let mut addr = ffi::rte_ether_addr::default();
        check("rte_eth_macaddr_get", unsafe {
            ffi::rte_eth_macaddr_get(self.port_id, &mut addr)
        })?;
        Ok(addr)
    }

    /// Polls up to `rx_pkts.len()` received packets into the given buffer,
    /// returning the mbufs actually received (never blocks).
    pub fn rx_burst(&self, max: usize) -> Vec<Mbuf> {
        const MAX_BURST: usize = 64;
        let n = max.min(MAX_BURST);
        let mut raw: [*mut ffi::rte_mbuf; MAX_BURST] = [ptr::null_mut(); MAX_BURST];
        let received =
            unsafe { ffi::dpdk_shim_eth_rx_burst(self.port_id, 0, raw.as_mut_ptr(), n as u16) };
        raw[..received as usize]
            .iter()
            .map(|&p| unsafe { Mbuf::from_raw(p) })
            .collect()
    }

    /// Hands a batch of mbufs to the NIC for transmission. Ownership of
    /// each mbuf transfers to the driver, which frees it once sent; any
    /// mbufs the NIC couldn't queue this call are returned to the caller.
    pub fn tx_burst(&self, mbufs: Vec<Mbuf>) -> Vec<Mbuf> {
        let raw_ptrs: Vec<*mut ffi::rte_mbuf> = mbufs.into_iter().map(Mbuf::into_raw).collect();
        let mut raw_ptrs = raw_ptrs;
        let sent = unsafe {
            ffi::dpdk_shim_eth_tx_burst(
                self.port_id,
                0,
                raw_ptrs.as_mut_ptr(),
                raw_ptrs.len() as u16,
            )
        };
        // Anything beyond `sent` was not accepted by the driver and is
        // still owned by us; reclaim those as Mbufs so they get freed (or
        // can be retried) instead of leaking.
        raw_ptrs
            .split_off(sent as usize)
            .into_iter()
            .map(|p| unsafe { Mbuf::from_raw(p) })
            .collect()
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }
}

impl Drop for EthPort {
    fn drop(&mut self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.port_id);
        }
    }
}

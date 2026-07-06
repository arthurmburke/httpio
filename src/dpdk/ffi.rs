//! DPDK FFI layer. Two binding modes, selected by `cfg(dpdk_bound)`
//! (set by build.rs when it found libdpdk via pkg-config on Linux):
//!
//! - **Real bindings** (`dpdk_bound`): generated at build time by bindgen
//!   from the installed DPDK headers (`csrc/wrapper.h`), so struct
//!   layouts and function signatures are ABI-exact for that exact DPDK
//!   version. This is the only mode that links and runs.
//! - **Stub declarations** (no `dpdk_bound`): a minimal hand-written
//!   mirror of the same names so the crate still type-checks on machines
//!   without DPDK (e.g. macOS -- DPDK is Linux-only). Never linkable;
//!   `cargo build` will fail at the link step in this mode by design.
//!
//! In both modes the `dpdk_shim_*` functions are provided by
//! `csrc/shim.c`: DPDK's hottest datapath calls (`rte_eth_rx_burst`,
//! `rte_pktmbuf_alloc`, `rte_pktmbuf_mtod`, ...) are `static inline` in
//! the C headers and thus have no linkable symbol for either bindgen or
//! an `extern "C"` block to bind -- the shim wraps each in a real
//! exported symbol, compiled against the same installed headers.
//!
//! Safe-wrapper code (mbuf.rs, mempool.rs, port.rs) treats `rte_mbuf`
//! and `rte_mempool` as opaque pointers and reads mbuf fields through
//! shim accessors, so it never depends on which mode produced the types.

use std::os::raw::{c_int, c_uint, c_void};

#[cfg(dpdk_bound)]
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/dpdk_bindings.rs"));
}

#[cfg(dpdk_bound)]
pub use bindings::{
    rte_eal_init, rte_eal_remote_launch, rte_eal_wait_lcore, rte_eth_dev_count_avail,
    rte_eth_dev_start, rte_eth_dev_stop, rte_eth_macaddr_get, rte_eth_promiscuous_enable,
    rte_eth_rx_queue_setup, rte_eth_tx_queue_setup, rte_ether_addr, rte_get_next_lcore,
    rte_lcore_count, rte_mbuf, rte_mempool, rte_pktmbuf_pool_create,
};

/// `typedef int (*lcore_function_t)(void *)` -- the entry point
/// `rte_eal_remote_launch` runs on a worker lcore. bindgen emits the
/// callback as an `Option`-wrapped fn pointer, so mirror that here for a
/// signature that matches under both the bindgen and stub paths.
pub type LcoreFunction = Option<unsafe extern "C" fn(arg: *mut c_void) -> c_int>;

#[cfg(not(dpdk_bound))]
mod stub {
    //! Type-check-only mirror of the bindgen output. Signatures match
    //! the DPDK 22.11+ C API; pointer-target structs are opaque.

    use std::os::raw::{c_char, c_int, c_uint, c_void};

    /// Opaque stand-in for `struct rte_mempool`.
    #[repr(C)]
    pub struct rte_mempool {
        _private: [u8; 0],
    }

    /// Opaque stand-in for `struct rte_mbuf`.
    #[repr(C)]
    pub struct rte_mbuf {
        _private: [u8; 0],
    }

    /// Mirrors `struct rte_ether_addr` (`uint8_t addr_bytes[6]`).
    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct rte_ether_addr {
        pub addr_bytes: [u8; 6],
    }

    unsafe extern "C" {
        pub fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;

        pub fn rte_pktmbuf_pool_create(
            name: *const c_char,
            n: c_uint,
            cache_size: c_uint,
            priv_size: u16,
            data_room_size: u16,
            socket_id: c_int,
        ) -> *mut rte_mempool;

        pub fn rte_eth_dev_count_avail() -> u16;
        pub fn rte_eth_rx_queue_setup(
            port_id: u16,
            rx_queue_id: u16,
            nb_rx_desc: u16,
            socket_id: c_uint,
            rx_conf: *const c_void,
            mb_pool: *mut rte_mempool,
        ) -> c_int;
        pub fn rte_eth_tx_queue_setup(
            port_id: u16,
            tx_queue_id: u16,
            nb_tx_desc: u16,
            socket_id: c_uint,
            tx_conf: *const c_void,
        ) -> c_int;
        pub fn rte_eth_dev_start(port_id: u16) -> c_int;
        pub fn rte_eth_dev_stop(port_id: u16) -> c_int;
        pub fn rte_eth_promiscuous_enable(port_id: u16) -> c_int;
        pub fn rte_eth_macaddr_get(port_id: u16, mac_addr: *mut rte_ether_addr) -> c_int;

        pub fn rte_eal_remote_launch(
            f: super::LcoreFunction,
            arg: *mut c_void,
            worker_id: c_uint,
        ) -> c_int;
        pub fn rte_eal_wait_lcore(worker_id: c_uint) -> c_int;
        pub fn rte_get_next_lcore(i: c_uint, skip_main: c_int, wrap: c_int) -> c_uint;
        pub fn rte_lcore_count() -> c_uint;
    }
}

#[cfg(not(dpdk_bound))]
pub use stub::*;

// ---- shim-backed functions (csrc/shim.c) -------------------------------
// Inline-only in the real DPDK headers, or (for eth_dev_configure) built
// in C to avoid replicating the version-sensitive `struct rte_eth_conf`.
unsafe extern "C" {
    pub fn dpdk_shim_socket_id() -> u16;
    /// `rte_lcore_id()` is inline (reads a per-lcore variable), so it has
    /// no linkable symbol -- wrapped by the shim.
    pub fn dpdk_shim_lcore_id() -> c_uint;
    /// `RTE_MAX_LCORE` compile-time constant (the "no next lcore"
    /// sentinel returned by `rte_get_next_lcore`).
    pub fn dpdk_shim_max_lcore() -> c_uint;
    pub fn dpdk_shim_eth_dev_configure_default(
        port_id: u16,
        nb_rx_q: u16,
        nb_tx_q: u16,
        mtu: u32,
    ) -> c_int;

    pub fn dpdk_shim_eth_rx_burst(
        port_id: u16,
        queue_id: u16,
        rx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;
    pub fn dpdk_shim_eth_tx_burst(
        port_id: u16,
        queue_id: u16,
        tx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;

    pub fn dpdk_shim_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf;
    pub fn dpdk_shim_pktmbuf_alloc_bulk(
        mp: *mut rte_mempool,
        mbufs: *mut *mut rte_mbuf,
        count: u16,
    ) -> u16;
    pub fn dpdk_shim_pktmbuf_free(m: *mut rte_mbuf);

    pub fn dpdk_shim_pktmbuf_data(m: *mut rte_mbuf) -> *mut u8;
    pub fn dpdk_shim_pktmbuf_headroom(m: *const rte_mbuf) -> u16;
    pub fn dpdk_shim_pktmbuf_tailroom(m: *const rte_mbuf) -> u16;
    pub fn dpdk_shim_pktmbuf_pkt_len(m: *const rte_mbuf) -> u32;
    pub fn dpdk_shim_pktmbuf_data_len(m: *const rte_mbuf) -> u16;
    pub fn dpdk_shim_pktmbuf_port(m: *const rte_mbuf) -> u16;
    pub fn dpdk_shim_pktmbuf_reset(m: *mut rte_mbuf);
    pub fn dpdk_shim_pktmbuf_append(m: *mut rte_mbuf, len: u16) -> *mut u8;
    pub fn dpdk_shim_pktmbuf_prepend(m: *mut rte_mbuf, len: u16) -> *mut u8;
    pub fn dpdk_shim_pktmbuf_adj(m: *mut rte_mbuf, len: u16) -> c_int;
    pub fn dpdk_shim_pktmbuf_trim(m: *mut rte_mbuf, len: u16) -> c_int;
}

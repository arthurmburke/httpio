/*
 * bindgen entry point: the DPDK headers whose types and exported
 * functions get real Rust bindings generated at build time (see build.rs;
 * the allowlist there controls what actually lands in the bindings).
 */
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

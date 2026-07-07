#ifndef BYPIO_DPDK_WRAPPER_H
#define BYPIO_DPDK_WRAPPER_H

/* Umbrella header bindgen parses to generate the DPDK FFI. Broadly
 * includes the DPDK subsystems this stack uses; the allowlist in build.rs
 * keeps the generated bindings to the `rte_*` surface. */
#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_version.h>

#endif

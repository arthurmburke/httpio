/*
 * Minimal exported wrappers around DPDK functions/macros that are
 * `static inline` in the public headers and therefore have no linkable
 * symbol of their own. Every wrapper here is a one-line pass-through to
 * the real DPDK inline implementation, compiled against whatever DPDK
 * version is actually installed on this machine (via pkg-config libdpdk)
 * so the ABI is always correct for that install -- nothing in this file
 * hard-codes struct layouts or offsets.
 *
 * Anything that is a genuinely exported DPDK symbol (rte_eal_init,
 * rte_eth_dev_configure, rte_eth_dev_start, rte_pktmbuf_pool_create, ...)
 * is declared directly as `extern "C"` on the Rust side and does NOT go
 * through this file.
 */

#include <stdint.h>
#include <string.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

uint16_t
dpdk_shim_socket_id(void)
{
	return (uint16_t)rte_socket_id();
}

unsigned int
dpdk_shim_lcore_id(void)
{
	return rte_lcore_id();
}

/* RTE_MAX_LCORE is the sentinel rte_get_next_lcore() returns when there
 * is no next lcore; expose the compile-time constant rather than
 * hard-coding its value (it varies with the DPDK build config). */
unsigned int
dpdk_shim_max_lcore(void)
{
	return RTE_MAX_LCORE;
}

/*
 * rte_eth_dev_configure() needs a fully-formed `struct rte_eth_conf`.
 * That struct has grown ABI-stability padding (reserved_64s/reserved_ptrs)
 * and nested union/bitfield members that differ across DPDK versions, so
 * rather than hand-replicate its layout in Rust (guesswork we can't check
 * here), build a zeroed default config against the real, locally-installed
 * header and only expose the couple of knobs the stack actually needs.
 */
int
dpdk_shim_eth_dev_configure_default(uint16_t port_id, uint16_t nb_rx_q,
    uint16_t nb_tx_q, uint32_t mtu)
{
	struct rte_eth_conf conf;

	memset(&conf, 0, sizeof(conf));
	conf.rxmode.mtu = mtu;
	return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &conf);
}

uint16_t
dpdk_shim_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t
dpdk_shim_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

struct rte_mbuf *
dpdk_shim_pktmbuf_alloc(struct rte_mempool *mp)
{
	return rte_pktmbuf_alloc(mp);
}

uint16_t
dpdk_shim_pktmbuf_alloc_bulk(struct rte_mempool *mp, struct rte_mbuf **mbufs,
    uint16_t count)
{
	return rte_pktmbuf_alloc_bulk(mp, mbufs, count) == 0 ? count : 0;
}

void
dpdk_shim_pktmbuf_free(struct rte_mbuf *m)
{
	rte_pktmbuf_free(m);
}

uint8_t *
dpdk_shim_pktmbuf_data(struct rte_mbuf *m)
{
	return rte_pktmbuf_mtod(m, uint8_t *);
}

uint16_t
dpdk_shim_pktmbuf_headroom(const struct rte_mbuf *m)
{
	return rte_pktmbuf_headroom(m);
}

uint16_t
dpdk_shim_pktmbuf_tailroom(const struct rte_mbuf *m)
{
	return rte_pktmbuf_tailroom(m);
}

uint32_t
dpdk_shim_pktmbuf_pkt_len(const struct rte_mbuf *m)
{
	return m->pkt_len;
}

uint16_t
dpdk_shim_pktmbuf_data_len(const struct rte_mbuf *m)
{
	return m->data_len;
}

uint16_t
dpdk_shim_pktmbuf_port(const struct rte_mbuf *m)
{
	return m->port;
}

void
dpdk_shim_pktmbuf_reset(struct rte_mbuf *m)
{
	rte_pktmbuf_reset(m);
}

uint8_t *
dpdk_shim_pktmbuf_append(struct rte_mbuf *m, uint16_t len)
{
	return (uint8_t *)rte_pktmbuf_append(m, len);
}

uint8_t *
dpdk_shim_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len)
{
	return (uint8_t *)rte_pktmbuf_prepend(m, len);
}

int
dpdk_shim_pktmbuf_adj(struct rte_mbuf *m, uint16_t len)
{
	return rte_pktmbuf_adj(m, len) != NULL ? 0 : -1;
}

int
dpdk_shim_pktmbuf_trim(struct rte_mbuf *m, uint16_t len)
{
	return rte_pktmbuf_trim(m, len);
}

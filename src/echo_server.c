// echo_server.c - DPDK 18.11 Echo Server
// Receives packets and sends them back to sender
// Uses port 1, leaving port 0 for Linux

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

// Use port 1 (second port) on the Mellanox card
#define PORT_ID 1

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = 1518,
    },
};

// Function to initialize port
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    rte_eth_dev_info_get(port, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet device. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    /* Display port MAC address */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
        port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
        addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    return 0;
}

// Main function for echo server
static void lcore_main(void) {
    struct rte_mbuf *bufs[BURST_SIZE];
    struct ether_hdr *eth_hdr;
    uint16_t port = PORT_ID;  // Use port 1

    printf("\nEcho server running on port %u. [Ctrl+C to quit]\n", port);

    while (1) {
        /* Get burst of RX packets. */
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        
        if (nb_rx == 0)
            continue;

        /* Echo back received packets */
        for (int i = 0; i < nb_rx; i++) {
            eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
            
            /* Swap source and destination MAC addresses */
            struct ether_addr temp_addr;
            ether_addr_copy(&eth_hdr->d_addr, &temp_addr);
            ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
            ether_addr_copy(&temp_addr, &eth_hdr->s_addr);
        }

        /* Send back packets */
        const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
        
        /* Free any unsent packets */
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
                rte_pktmbuf_free(bufs[buf]);
        }
    }
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check that port 1 is available */
    if (!rte_eth_dev_is_valid_port(PORT_ID))
        rte_exit(EXIT_FAILURE, "Port %u is not available. Check that DPDK sees the Mellanox card properly.\n", PORT_ID);

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize port 1. */
    if (port_init(PORT_ID, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot initialize port %"PRIu16 "\n", PORT_ID);

    /* Call lcore_main on the main core only. */
    lcore_main();

    return 0;
}

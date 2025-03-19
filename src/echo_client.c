// echo_client.c - DPDK 18.11 Client for RTT measurement
// Sends packets and measures RTT when they return
// Uses port 1, leaving port 0 for Linux

#include "rte_ether.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/queue.h>
#include <math.h>
#include <time.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

#define NUM_PACKETS 1000
#define PACKET_SIZE 64  // Payload size
#define TIMEOUT_SEC 2   // Timeout in seconds

// Use port 1 (second port) on the Mellanox card
#define PORT_ID 1

// Structure to store packet metadata
struct packet_metadata {
    uint32_t sequence;
    uint64_t timestamp;
    uint8_t received;
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = 1518,
    },
};

// Array to store RTT values
static double rtt_values[NUM_PACKETS];
// Array to track sent packets
static struct packet_metadata packet_records[NUM_PACKETS];

static int double_compare(const double *a, const double *b);

// Initialize port
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

// Create a test packet
static struct rte_mbuf* create_packet(struct rte_mempool *mbuf_pool, uint16_t port, uint32_t seq_num) {
    struct rte_mbuf *pkt;
    struct ether_hdr *eth_hdr;
    struct ether_addr my_addr;
    struct ether_addr dst_addr = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}; // Broadcast for simplicity
    uint16_t pkt_data_len = sizeof(struct ether_hdr) + sizeof(uint32_t) + PACKET_SIZE;
    
    // Get MAC address
    rte_eth_macaddr_get(port, &my_addr);
    
    // Allocate the packet
    pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (pkt == NULL) {
        printf("Failed to allocate packet\n");
        return NULL;
    }
    
    // Set packet length
    if (rte_pktmbuf_append(pkt, pkt_data_len) == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to add data segmet to the pktmbuf\n");
    };
    
    // Initialize Ethernet header
    eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    ether_addr_copy(&dst_addr, &eth_hdr->d_addr);
    ether_addr_copy(&my_addr, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(0x1234); // Custom type for our test
    
    // Add sequence number after the header
    uint32_t *seq = rte_pktmbuf_mtod_offset(pkt, uint32_t*, sizeof(struct ether_hdr));
    *seq = seq_num;
    
    // Fill the rest with some pattern
    uint8_t *payload = rte_pktmbuf_mtod_offset(pkt, uint8_t*, sizeof(struct ether_hdr) + sizeof(uint32_t));
    for (int i = 0; i < PACKET_SIZE; i++) {
        payload[i] = (uint8_t)i;
    }
    
    return pkt;
}

// Calculate statistics
static void calculate_statistics(double *mean, double *stddev, int received_count) {
    double sum = 0.0;
    
    // Calculate mean
    for (int i = 0; i < received_count; i++) {
        sum += rtt_values[i];
    }
    *mean = sum / received_count;
    
    // Calculate standard deviation
    sum = 0.0;
    for (int i = 0; i < received_count; i++) {
        sum += (rtt_values[i] - *mean) * (rtt_values[i] - *mean);
    }
    *stddev = sqrt(sum / received_count);
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    uint16_t port = PORT_ID;  // Use port 1
    int ret, i;
    struct rte_mbuf *pkts[NUM_PACKETS];
    struct rte_mbuf *rx_pkts[32];
    uint32_t *rx_seq;
    struct ether_hdr *eth_hdr;
    uint64_t start_tsc, end_tsc, current_tsc;
    uint64_t tsc_hz;
    double mean_rtt = 0.0, stddev_rtt = 0.0;
    int packets_received = 0;
    int retry_count = 0;
    int max_retries = 3;
    
    /* Initialize the Environment Abstraction Layer (EAL). */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    
    argc -= ret;
    argv += ret;
    
    /* Check that port 1 is available */
    if (!rte_eth_dev_is_valid_port(PORT_ID))
        rte_exit(EXIT_FAILURE, "Port %u is not available. Check that DPDK sees the Mellanox card properly.\n", PORT_ID);
    
    /* Get the frequency of the TSC counter */
    tsc_hz = rte_get_tsc_hz();
    
    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    
    /* Initialize port */
    if (port_init(port, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port);
    
    printf("Sending %d packets on port %u to measure RTT...\n", NUM_PACKETS, port);
    
    // Initialize packet tracking
    for (i = 0; i < NUM_PACKETS; i++) {
        packet_records[i].sequence = i;
        packet_records[i].received = 0;
    }
    
    // Create and send all packets
    for (i = 0; i < NUM_PACKETS; i++) {
        // Create packet
        pkts[i] = create_packet(mbuf_pool, port, i);
        if (pkts[i] == NULL)
            rte_exit(EXIT_FAILURE, "Failed to create packet %d\n", i);
        
        // Send packet and record timestamp
        start_tsc = rte_rdtsc();
        packet_records[i].timestamp = start_tsc;
        
        if (rte_eth_tx_burst(port, 0, &pkts[i], 1) != 1) {
            printf("Failed to send packet %d\n", i);
            rte_pktmbuf_free(pkts[i]);
            continue;
        }
    }
    
    // Receive loop with timeout
    start_tsc = rte_rdtsc();
    while (packets_received < NUM_PACKETS) {
        // Check timeout
        current_tsc = rte_rdtsc();
        if ((current_tsc - start_tsc) > (tsc_hz * TIMEOUT_SEC)) {
            if (retry_count >= max_retries)
                break;
            
            printf("Timeout occurred. Resending unacknowledged packets. Attempt %d/%d\n", 
                   retry_count + 1, max_retries);
            
            // Resend unacknowledged packets
            for (i = 0; i < NUM_PACKETS; i++) {
                if (!packet_records[i].received) {
                    struct rte_mbuf *new_pkt = create_packet(mbuf_pool, port, i);
                    if (new_pkt == NULL) continue;
                    
                    packet_records[i].timestamp = rte_rdtsc();
                    if (rte_eth_tx_burst(port, 0, &new_pkt, 1) != 1) {
                        rte_pktmbuf_free(new_pkt);
                    }
                }
            }
            
            start_tsc = rte_rdtsc();
            retry_count++;
            continue;
        }
        
        // Try to receive packets
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, rx_pkts, 32);
        
        // Process received packets
        for (i = 0; i < nb_rx; i++) {
            end_tsc = rte_rdtsc();
            
            // Extract sequence number
            eth_hdr = rte_pktmbuf_mtod(rx_pkts[i], struct ether_hdr *);
            rx_seq = rte_pktmbuf_mtod_offset(rx_pkts[i], uint32_t *, sizeof(struct ether_hdr));
            
            // Make sure sequence number is valid
            if (*rx_seq < NUM_PACKETS && !packet_records[*rx_seq].received) {
                // Calculate RTT
                double rtt_us = (double)(end_tsc - packet_records[*rx_seq].timestamp) * 1000000 / tsc_hz;
                rtt_values[packets_received] = rtt_us;
                packet_records[*rx_seq].received = 1;
                packets_received++;
                
                // Print progress
                if (packets_received % 100 == 0 || packets_received == NUM_PACKETS)
                    printf("Received %d packets\n", packets_received);
            }
            
            rte_pktmbuf_free(rx_pkts[i]);
        }
    }
    
    // Calculate and print statistics
    if (packets_received > 0) {
        calculate_statistics(&mean_rtt, &stddev_rtt, packets_received);
        printf("\nRTT Measurement Results:\n");
        printf("Packets sent: %d\n", NUM_PACKETS);
        printf("Packets received: %d\n", packets_received);
        printf("Mean RTT: %.2f microseconds\n", mean_rtt);
        printf("Standard Deviation: %.2f microseconds\n", stddev_rtt);
        
        // Print detailed percentile information
        if (packets_received >= 10) {
            // Sort RTT values for percentile calculation
            qsort(rtt_values, packets_received, sizeof(double), 
                 (int (*)(const void *, const void *))double_compare);
                 
            printf("Min RTT: %.2f microseconds\n", rtt_values[0]);
            printf("50th percentile (median): %.2f microseconds\n", 
                   rtt_values[packets_received/2]);
            printf("90th percentile: %.2f microseconds\n", 
                   rtt_values[(int)(packets_received * 0.9)]);
            printf("99th percentile: %.2f microseconds\n", 
                   rtt_values[(int)(packets_received * 0.99)]);
            printf("Max RTT: %.2f microseconds\n", 
                   rtt_values[packets_received-1]);
        }
    } else {
        printf("No packets received. Check if the echo server is running.\n");
    }
    
    // Clean up
    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    rte_eal_cleanup();
    
    return 0;
}

// Helper function for qsort
static int double_compare(const double *a, const double *b) {
    if (*a < *b) return -1;
    if (*a > *b) return 1;
    return 0;
}

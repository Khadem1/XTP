#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <signal.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define XTP_PROTO_ID 253
#define TX_PORT 0

volatile int keep_running = 1;

struct xtp_hdr {
    uint8_t ver_flags;
    uint8_t msg_type;
    uint16_t msg_id;
} __attribute__((__packed__));

static void signal_handler(int signum) {
    keep_running = 0;
}

static struct rte_mbuf *build_xtp_packet(struct rte_mempool *mbuf_pool) {
    const unsigned total_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct xtp_hdr) + 8;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) return NULL;

    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(eth + 1);
    struct xtp_hdr *xtp = (struct xtp_hdr *)(ip + 1);
    uint8_t *payload = (uint8_t *)(xtp + 1);

    // Fill Ethernet header
    memset(eth->d_addr.addr_bytes, 0xff, 6); // Broadcast
    memset(eth->s_addr.addr_bytes, 0x11, 6); // Dummy MAC
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    // Fill IPv4 header
    memset(ip, 0, sizeof(struct ipv4_hdr));
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct xtp_hdr) + 8);
    ip->next_proto_id = XTP_PROTO_ID;
    ip->src_addr = rte_cpu_to_be_32(IPv4(192, 168, 0, 1));
    ip->dst_addr = rte_cpu_to_be_32(IPv4(192, 168, 0, 2));
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // XTP Header
    xtp->ver_flags = 0x01;
    xtp->msg_type = 0x10;
    xtp->msg_id = rte_cpu_to_be_16(rand() & 0xffff);

    // Payload
    memset(payload, 0xab, 8);

    return mbuf;
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    struct rte_eth_conf port_conf = { .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN } };

    signal(SIGINT, signal_handler);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL init\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (rte_eth_dev_configure(TX_PORT, 0, 1, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device\n");

    if (rte_eth_tx_queue_setup(TX_PORT, 0, 512, rte_eth_dev_socket_id(TX_PORT), NULL) < 0)
        rte_exit(EXIT_FAILURE, "TX queue setup failed\n");

    if (rte_eth_dev_start(TX_PORT) < 0)
        rte_exit(EXIT_FAILURE, "Device start failed\n");

    printf("Sending XTP packets in loop... Press Ctrl+C to stop\n");

    uint64_t t0 = rte_get_timer_cycles();
    uint64_t hz = rte_get_timer_hz();
    uint64_t packets = 0;

    while (keep_running) {
        struct rte_mbuf *tx_bufs[BURST_SIZE];

        for (int i = 0; i < BURST_SIZE; ++i) {
            tx_bufs[i] = build_xtp_packet(mbuf_pool);
            if (!tx_bufs[i]) break;
        }

        uint16_t sent = rte_eth_tx_burst(TX_PORT, 0, tx_bufs, BURST_SIZE);
        packets += sent;

        // Free unsent mbufs
        for (int i = sent; i < BURST_SIZE; i++) {
            if (tx_bufs[i]) rte_pktmbuf_free(tx_bufs[i]);
        }

        uint64_t t1 = rte_get_timer_cycles();
        if (t1 - t0 >= hz) {
            printf("PPS: %lu packets/sec\n", packets);
            packets = 0;
            t0 = t1;
        }
    }

    rte_eth_dev_stop(TX_PORT);
    rte_eth_dev_close(TX_PORT);
    printf("Stopped.\n");

    return 0;
}

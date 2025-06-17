#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <signal.h>
#include <time.h>

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IPv4(a, b, c, d) ((uint32_t)(((a)&0xff)<<24 | ((b)&0xff)<<16 | ((c)&0xff)<<8 | ((d)&0xff)))

volatile int keep_running = 1;

struct xtp_hdr {
    uint8_t flags;
    uint8_t priority;
    uint16_t length;
    uint32_t session_id;
} __attribute__((__packed__));

static void handle_signal(int sig) {
    keep_running = 0;
}

static struct rte_mbuf *build_packet(struct rte_mempool *mbuf_pool, const char *mode) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) return NULL;

    const uint16_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        (strcmp(mode, "xtp") == 0 ? sizeof(struct xtp_hdr) :
         strcmp(mode, "udp") == 0 ? sizeof(struct rte_udp_hdr) : sizeof(struct rte_tcp_hdr)) + 8;

    mbuf->data_len = pkt_size;
    mbuf->pkt_len = pkt_size;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

    memset(eth->dst_addr.addr_bytes, 0xff, 6);
    memset(eth->src_addr.addr_bytes, 0x11, 6);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip, 0, sizeof(struct rte_ipv4_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(pkt_size - sizeof(struct rte_ether_hdr));
    ip->packet_id = rte_cpu_to_be_16(0);
    ip->time_to_live = 64;
    ip->next_proto_id = (strcmp(mode, "xtp") == 0 ? 253 :
                         strcmp(mode, "udp") == 0 ? IPPROTO_UDP : IPPROTO_TCP);
    ip->src_addr = rte_cpu_to_be_32(IPv4(10, 0, 0, 1));
    ip->dst_addr = rte_cpu_to_be_32(IPv4(10, 0, 0, 2));
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    char *l4 = (char *)(ip + 1);
    if (strcmp(mode, "xtp") == 0) {
        struct xtp_hdr *xtp = (struct xtp_hdr *)l4;
        xtp->flags = 0x1;
        xtp->priority = 0x5;
        xtp->length = rte_cpu_to_be_16(8);
        xtp->session_id = rte_cpu_to_be_32(1234);
    } else if (strcmp(mode, "udp") == 0) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        udp->src_port = rte_cpu_to_be_16(1000);
        udp->dst_port = rte_cpu_to_be_16(2000);
        udp->dgram_len = rte_cpu_to_be_16(pkt_size - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
        udp->dgram_cksum = 0;
    } else {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        tcp->src_port = rte_cpu_to_be_16(1000);
        tcp->dst_port = rte_cpu_to_be_16(2000);
        tcp->sent_seq = rte_cpu_to_be_32(1);
        tcp->recv_ack = 0;
        tcp->data_off = (5 << 4);
        tcp->tcp_flags = RTE_TCP_SYN_FLAG;
        tcp->rx_win = rte_cpu_to_be_16(65535);
        tcp->cksum = 0;
        tcp->tcp_urp = 0;
    }

    return mbuf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <xtp|udp|tcp>\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL init\n");

    uint16_t port_id = 0;
    if (!rte_eth_dev_is_valid_port(port_id))
        rte_exit(EXIT_FAILURE, "Invalid port\n");

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    struct rte_eth_conf port_conf = { .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE } };
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Cannot configure device\n");

    ret = rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (ret < 0) rte_exit(EXIT_FAILURE, "RX queue setup failed\n");

    ret = rte_eth_tx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL);
    if (ret < 0) rte_exit(EXIT_FAILURE, "TX queue setup failed\n");

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Device start failed\n");

    printf("Benchmarking %s packets... Press Ctrl+C to stop\n", mode);

    uint64_t pkt_count = 0;
    time_t last_time = time(NULL);

    while (keep_running) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        for (int i = 0; i < BURST_SIZE; i++) {
            mbufs[i] = build_packet(mbuf_pool, mode);
            if (!mbufs[i]) continue;
        }

        uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, BURST_SIZE);
        pkt_count += nb_tx;

        time_t now = time(NULL);
        if (now > last_time) {
            printf("PPS: %lu packets/sec\n", pkt_count);
            pkt_count = 0;
            last_time = now;
        }
    }

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    return 0;
}

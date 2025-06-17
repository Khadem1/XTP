/*
 * Benchmark DPDK TX performance for XTP, UDP, and TCP
 */

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <unistd.h>
#include <time.h>

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

enum proto_type { XTP_PROTO, UDP_PROTO, TCP_PROTO };

struct xtp_hdr {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t session_id;
} __attribute__((__packed__));

struct rte_mbuf *build_packet(struct rte_mempool *mbuf_pool, enum proto_type proto) {
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        ((proto == XTP_PROTO) ? sizeof(struct xtp_hdr) :
        (proto == UDP_PROTO) ? sizeof(struct rte_udp_hdr) :
                               sizeof(struct rte_tcp_hdr)) + 8;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) return NULL;

    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

    memset(eth->d_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
    memset(eth->s_addr.addr_bytes, 0x11, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip, 0, sizeof(struct rte_ipv4_hdr));
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(total_len - sizeof(struct rte_ether_hdr));
    ip->time_to_live = 64;
    ip->src_addr = rte_cpu_to_be_32((192 << 24) | (168 << 16) | (0 << 8) | 1);
    ip->dst_addr = rte_cpu_to_be_32((192 << 24) | (168 << 16) | (0 << 8) | 2);

    if (proto == XTP_PROTO) {
        ip->next_proto_id = 253;
        struct xtp_hdr *xtp = (struct xtp_hdr *)(ip + 1);
        xtp->type = 1;
        xtp->flags = 0;
        xtp->length = rte_cpu_to_be_16(8);
        xtp->session_id = rte_cpu_to_be_32(42);
        memset(xtp + 1, 0xaa, 8);
    } else if (proto == UDP_PROTO) {
        ip->next_proto_id = IPPROTO_UDP;
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
        udp->src_port = rte_cpu_to_be_16(1234);
        udp->dst_port = rte_cpu_to_be_16(5678);
        udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + 8);
        udp->dgram_cksum = 0;
        memset(udp + 1, 0xbb, 8);
    } else {
        ip->next_proto_id = IPPROTO_TCP;
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
        tcp->src_port = rte_cpu_to_be_16(10000);
        tcp->dst_port = rte_cpu_to_be_16(20000);
        tcp->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
        tcp->tcp_flags = RTE_TCP_SYN_FLAG;
        memset(tcp + 1, 0xcc, 8);
    }

    ip->hdr_checksum = rte_ipv4_cksum(ip);
    return mbuf;
}

int main(int argc, char *argv[]) {
    enum proto_type proto = XTP_PROTO;
    if (argc > 1) {
        if (strcmp(argv[1], "udp") == 0) proto = UDP_PROTO;
        else if (strcmp(argv[1], "tcp") == 0) proto = TCP_PROTO;
    }

    rte_eal_init(argc, argv);

    uint16_t port_id = 0;
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    struct rte_eth_conf port_conf = { .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN } };
    rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    rte_eth_rx_queue_setup(port_id, 0, 128, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    rte_eth_tx_queue_setup(port_id, 0, 128, rte_eth_dev_socket_id(port_id), NULL);
    rte_eth_dev_start(port_id);

    uint64_t total_sent = 0;
    time_t start = time(NULL);
    for (;;) {
        struct rte_mbuf *bufs[BURST_SIZE];
        for (int i = 0; i < BURST_SIZE; ++i)
            bufs[i] = build_packet(mbuf_pool, proto);
        const uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, bufs, BURST_SIZE);
        total_sent += nb_tx;
        for (int i = nb_tx; i < BURST_SIZE; ++i)
            rte_pktmbuf_free(bufs[i]);
        if (time(NULL) - start >= 1) {
            printf("PPS: %lu packets/sec\n", total_sent);
            total_sent = 0;
            start = time(NULL);
        }
    }
    return 0;
}

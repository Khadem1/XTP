#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <unistd.h>
#include <string.h>

#pragma pack(push, 1)
struct xtp_hdr {
    uint8_t  ver_flags;
    uint8_t  type_qos;
    uint16_t length;
    uint32_t msg_id;
};
#pragma pack(pop)

#define MBUF_CACHE_SIZE 250
#define NUM_MBUFS 8191
#define BURST_SIZE 32

static struct rte_mempool *mbuf_pool;

static void
build_xtp_packet(struct rte_mbuf *mbuf,
                 struct rte_ether_addr *src_mac,
                 struct rte_ether_addr *dst_mac,
                 uint32_t src_ip,
                 uint32_t dst_ip,
                 uint32_t msg_id,
                 uint8_t *payload,
                 uint16_t payload_len)
{
    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)pkt_data;
    rte_ether_addr_copy(dst_mac, &eth_hdr->dst_addr);
    rte_ether_addr_copy(src_mac, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct xtp_hdr) + payload_len);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = 253;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->src_addr = rte_cpu_to_be_32(src_ip);
    ip_hdr->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    struct xtp_hdr *xtp = (struct xtp_hdr *)(ip_hdr + 1);
    xtp->ver_flags = 0x10;
    xtp->type_qos = 0x21;
    xtp->length = rte_cpu_to_be_16(payload_len);
    xtp->msg_id = rte_cpu_to_be_32(msg_id);

    uint8_t *payload_start = (uint8_t *)(xtp + 1);
    rte_memcpy(payload_start, payload, payload_len);

    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
                   + sizeof(struct xtp_hdr) + payload_len;
    mbuf->pkt_len = mbuf->data_len;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t port_id = 0;
    if (!rte_eth_dev_is_valid_port(port_id))
        rte_exit(EXIT_FAILURE, "Invalid port\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * 2,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    struct rte_eth_conf port_conf = {0};
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device\n");

    ret = rte_eth_rx_queue_setup(port_id, 0, 128, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    ret |= rte_eth_tx_queue_setup(port_id, 0, 128, rte_eth_dev_socket_id(port_id), NULL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Queue setup failed\n");

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Device start failed\n");

    printf("Sending XTP packet...\n");

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    struct rte_ether_addr src_mac, dst_mac;
    rte_eth_macaddr_get(port_id, &src_mac);
    memset(&dst_mac, 0xff, sizeof(dst_mac)); // broadcast for demo

    uint32_t src_ip = RTE_IPV4(192, 168, 0, 1);
    uint32_t dst_ip = RTE_IPV4(192, 168, 0, 2);
    uint8_t data[] = "Hello XTP!";
    build_xtp_packet(mbuf, &src_mac, &dst_mac, src_ip, dst_ip, 42, data, sizeof(data));

    const uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (nb_tx == 0) rte_pktmbuf_free(mbuf);

    printf("Packet sent.\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    return 0;
}

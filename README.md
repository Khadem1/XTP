# XTP / NeuNIC Transport Protocol
XTP — eXtreme Transport Protocol
Creating a **new custom protocol header using DPDK's flexible items** (flex item in flow API or within custom packet parsing) can be a powerful way to offload parsing or filtering on a SmartNIC or high-performance NIC. Your goal is to define a **custom transport-layer-like header** that is **more efficient** than TCP/UDP/QUIC, possibly for specific use cases like ultra-low-latency, real-time telemetry, or internal data center traffic.

###  Step 1: Define the Design Goals

To be *more efficient* than UDP/TCP/QUIC, the custom header aim for:

| Feature                | Value/Strategy                                      |
| ---------------------- | --------------------------------------------------- |
| **Low Overhead**       | Smaller header (e.g., 8 bytes max)                  |
| **Stateless**          | Avoid connection states (like UDP)                  |
| **Optional Integrity** | CRC or checksum only if needed                      |
| **Alignment-friendly** | Align to 4- or 8-byte boundaries                    |
| **NIC Parsable**       | Easily matched via DPDK flow rules and flex parsing |
| **Application-aware**  | Support for app-level QoS, message ID, etc.         |


### Step 2: Define the Custom Header (call it`XTP` — eXtreme Transport Protocol/ NeuNIC Transport Protocol)

```c
struct xtp_hdr {
    uint8_t  ver_flags;     // [4 bits version | 4 bits flags]
    uint8_t  type_qos;      // [4 bits type | 4 bits QoS/class]
    uint16_t length;        // Payload length in bytes
    uint32_t msg_id;        // Message or sequence ID
};
```

#### Description:

* **ver\_flags (1 byte)**:

  * Version: bits \[7:4] (e.g., 0001 for version 1)
  * Flags: bits \[3:0] — e.g., ACK, RELIABLE, ENCRYPTED, FRAGMENTED
* **type\_qos (1 byte)**:

  * Type: message type (e.g., control/data/audio/video)
  * QoS: low latency / best effort / lossless
* **length (2 bytes)**:

  * Length of the payload (like UDP)
* **msg\_id (4 bytes)**:

  * Application-level sequence or message identifier

 **Total size: 8 bytes**

### Comparison With UDP/TCP/QUIC

| Protocol | Header Size   | Connection | Reliability | Parsing Cost | Use Case                     |
| -------- | ------------- | ---------- | ----------- | ------------ | ---------------------------- |
| TCP      | 20 bytes      | Stateful   | Yes         | High         | General-purpose, reliable    |
| UDP      | 8 bytes       | Stateless  | No          | Low          | Streaming, VoIP              |
| QUIC     | \~20–50 bytes | Stateful   | Yes         | High         | Modern, encrypted transport  |
| **XTP**  | 8 bytes       | Stateless  | Optional    | Very low     | HPC, AI inference, telemetry |


### Step 3: Integrate with DPDK

1. **Packet Construction**

```c
struct rte_mbuf *mbuf = ...;
struct xtp_hdr *xtp = (struct xtp_hdr *)rte_pktmbuf_mtod_offset(mbuf, void *, offset);
xtp->ver_flags = 0x10;  // Version 1, flags 0
xtp->type_qos = 0x21;   // Type 2 (e.g., video), QoS 1 (low latency)
xtp->length = rte_cpu_to_be_16(payload_len);
xtp->msg_id = rte_cpu_to_be_32(msg_id);
```

2. **Using Flow Rules with Flex Parser**

```c
struct rte_flow_item_flex {
    uint16_t pattern_offset; // offset from custom L4
    uint16_t length;
    uint8_t  pattern[8];
};
```

Create a flow rule matching your `xtp_hdr` using flex item starting at the offset from L3.


### Benefits of XTP

* Ideal for high-performance networks (like RDMA-lite)
* Simple to parse in DPDK and SmartNICs
* Tailorable per use-case (e.g., AI pipelines, NVMe over UDP, sensor data)
* NIC offload possible with `rte_flow` and `rte_flow_item_flex`

### Summary of Your Benchmarks

####  Run:

```bash
sudo ./benchmark           # For XTP
sudo ./benchmark udp       # For UDP
sudo ./benchmark tcp       # For TCP
```

| Protocol | Initial PPS (warm-up) | Peak PPS      | Consistency             |
| -------- | --------------------- | ------------- | ----------------------- |
| **XTP**  | 1.29M                 | \~6.59M       | Stable, tight variance  |
| **UDP**  | 0.33M                 | \~6.44M       | Slightly lower than XTP |
| **TCP**  | 2.09M                 | \~6.59–6.59M+ | Slightly higher ceiling |

1. **XTP matches TCP in performance**: Despite being a minimal custom protocol with no OS-level stack support, XTP achieves TCP-level throughput — this validates that:

   * XTP packet header is lightweight enough.
   * The NIC offloads or path in DPDK isn't a bottleneck.
   * The DPDK TX path is fully saturated.

2. **UDP is slightly lower (\~100–200k PPS)**:

   * Possibly due to the fixed header length in `rte_udp_hdr` plus alignment and checksum quirks.
   * Could also relate to NIC offloads not being fully optimized.


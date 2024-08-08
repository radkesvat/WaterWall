
#include "hsocket.h"
#include <stdint.h>
#include <stdlib.h>

struct ipv4header
{
#if __BIG_ENDIAN__
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
    unsigned int ihl : 4;
    unsigned int version : 4;
#endif
    uint8_t  tos;      // Type of Service
    uint16_t tot_len;  // Total Length
    uint16_t id;       // Identification
    uint16_t frag_off; // Fragment Offset
    uint8_t  ttl;      // Time to Live
    uint8_t  protocol; // Protocol
    uint16_t check;    // Header Checksum
    uint32_t saddr;    // Source Address
    uint32_t daddr;    // Destination Address
} __attribute__((packed));

struct ipv6header
{
#if __BIG_ENDIAN__
    uint32_t version : 4, traffic_class : 8, flow_label : 20;
#else
    uint32_t flow_label : 20, traffic_class : 8, version : 4;
#endif
    uint16_t        payload_len; // Payload Length
    uint8_t         nexthdr;     // Next Header
    uint8_t         hop_limit;   // Hop Limit
    struct in6_addr saddr;       // Source Address
    struct in6_addr daddr;       // Destination Address
} __attribute__((packed));

typedef union {
    struct ipv4header ip4_header;
    struct ipv6header ip6_header;

} packet_mask;

struct tcpheader
{
    uint16_t source;   // Source port
    uint16_t dest;     // Destination port
    uint32_t seq;      // Sequence number
    uint32_t ack_seq;  // Acknowledgment number
    uint16_t res1 : 4; // Reserved (4 bits)
    uint16_t doff : 4; // Data offset (4 bits)
    uint16_t fin : 1;  // FIN flag
    uint16_t syn : 1;  // SYN flag
    uint16_t rst : 1;  // RST flag
    uint16_t psh : 1;  // PSH flag
    uint16_t ack : 1;  // ACK flag
    uint16_t urg : 1;  // URG flag
    uint16_t res2 : 2; // Reserved (2 bits)
    uint16_t window;   // Window size
    uint16_t check;    // Checksum
    uint16_t urg_ptr;  // Urgent pointer
} __attribute__((packed));

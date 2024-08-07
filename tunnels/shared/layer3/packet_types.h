
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
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

struct ipv6header
{
#if __BIG_ENDIAN__
    uint8_t version : 4, priority : 4;
#else
    uint8_t priority : 4, version : 4;
#endif
    uint8_t flow_lbl[3];

    uint16_t payload_len;
    uint8_t  nexthdr;
    uint8_t  hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
};

typedef union {
    struct ipv4header ip4_header;
    struct ipv6header ip6_header;

} packet_mask;


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
    // uint32_t flow_label : 20;
    // uint32_t traffic_class : 8;
    uint32_t useless : 4;
    uint32_t version : 4;
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
#if __BIG_ENDIAN__
    uint16_t doff : 4;  // Data offset (4 bits)
    uint16_t res1 : 4;  // Reserved (4 bits)
    uint16_t res2 : 2;  // Reserved (2 bits)
    uint16_t urg : 1;   // URG flag
    uint16_t ack : 1;   // ACK flag
    uint16_t psh : 1;   // PSH flag
    uint16_t rst : 1;   // RST flag
    uint16_t syn : 1;   // SYN flag
    uint16_t fin : 1;   // FIN flag
#else
    uint16_t res1 : 4;  // Reserved (4 bits)
    uint16_t doff : 4;  // Data offset (4 bits)
    uint16_t fin : 1;   // FIN flag
    uint16_t syn : 1;   // SYN flag
    uint16_t rst : 1;   // RST flag
    uint16_t psh : 1;   // PSH flag
    uint16_t ack : 1;   // ACK flag
    uint16_t urg : 1;   // URG flag
    uint16_t res2 : 2;  // Reserved (2 bits)
#endif
    uint16_t window;   // Window size
    uint16_t check;    // Checksum
    uint16_t urg_ptr;  // Urgent pointer
} __attribute__((packed));


static inline uint16_t standardCheckSum(uint8_t* buf, int len) {
    unsigned int sum = 0;
    uint16_t* ptr = (uint16_t*)buf;
    while(len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if(len) {
        sum += *(uint8_t*)ptr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}


/** Swap the bytes in an u16_t: much like lwip_htons() for little-endian */
#ifndef SWAP_BYTES_IN_WORD
#define SWAP_BYTES_IN_WORD(w) ((((w) & 0xff) << 8) | (((w) & 0xff00) >> 8))
#endif /* SWAP_BYTES_IN_WORD */

#ifndef FOLD_U32T
#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u) & 0x0000ffffUL)))
#endif

// this is algorithim 2 of lwip
static uint16_t lwipStandardCheckSum(const void *dataptr, int len)
{
    const uint8_t *pb = (const uint8_t *)dataptr;
    const uint16_t *ps;
    uint16_t t = 0;
    uint32_t sum = 0;
    int odd = (int)((uintptr_t)pb & 1);

    /* Get aligned to uint16_t */
    if (odd && len > 0) {
        ((uint8_t *)&t)[1] = *pb++;
        len--;
    }

    /* Add the bulk of the data */
    ps = (const uint16_t *)(const void *)pb;
    while (len > 1) {
        sum += *ps++;
        len -= 2;
    }

    /* Consume left-over byte, if any */
    if (len > 0) {
        ((uint8_t *)&t)[0] = *(const uint8_t *)ps;
    }

    /* Add end bytes */
    sum += t;

    /* Fold 32-bit sum to 16 bits
       calling this twice is probably faster than if statements... */
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);

    /* Swap if alignment was odd */
    if (odd) {
        sum = SWAP_BYTES_IN_WORD(sum);
    }

    return (uint16_t)sum;
}

static unsigned short tcpCheckSum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

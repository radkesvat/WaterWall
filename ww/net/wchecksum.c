#include "wchecksum.h"

#include "wlibc.h"

void calcFullPacketChecksum(uint8_t *buf);

extern uint16_t checksumAVX2(const uint8_t *data, uint16_t len, uint32_t initial);
extern uint16_t checksumSSE3(const uint8_t *data, uint16_t len, uint32_t initial);
// extern uint16_t checksumAMD64(const uint8_t *data, size_t len, uint16_t initial);
extern uint16_t checksumDefault(const uint8_t *data, uint16_t len, uint32_t initial);

typedef uint16_t (*cksum_fn)(const uint8_t *, uint16_t, uint32_t);
static cksum_fn checksum = NULL;

/** Sum the pseudo‑header (src, dst, proto, length) in host order */
static inline uint32_t checksumPseudoHeader(const struct ip4_addr_packed *src, const struct ip4_addr_packed *dst,
                                            u8_t proto, u16_t length)
{
    uint32_t sum   = 0;
    uint32_t src_h = lwip_ntohl(src->addr);
    uint32_t dst_h = lwip_ntohl(dst->addr);

    /* high and low 16 bits of source address */
    sum += (src_h >> 16) & 0xFFFF;
    sum += src_h & 0xFFFF;
    /* high and low 16 bits of destination address */
    sum += (dst_h >> 16) & 0xFFFF;
    sum += dst_h & 0xFFFF;
    /* protocol (zero‑padded high byte + proto in low byte) */
    sum += proto;
    /* TCP/UDP length */
    sum += length;

    return sum;
}
/** Fold carries and return the one's‑complement result */
static inline uint16_t finalizeChecksum(uint32_t sum)
{
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t) ~sum;
}

void calcFullPacketChecksum(uint8_t *buf)
{
    struct ip_hdr *ipheader = (struct ip_hdr *) buf;

    if (IPH_V(ipheader) != 4)
    {
        return;
    }

    /* 1) Recalculate IP header checksum */
    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));

    /* 2) Get transport header & length */
    u16_t ip_hdr_len = IPH_HL(ipheader) * 4;
    u16_t ip_tot_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_tot_len < ip_hdr_len)
    {
        return; /* malformed */
    }

    uint8_t *transport_hdr = buf + ip_hdr_len;
    u16_t    transport_len = ip_tot_len - ip_hdr_len;
    u8_t     protocol      = IPH_PROTO(ipheader);

    /* 3) Recalculate TCP/UDP/ICMP checksums */
    switch (protocol)
    {
    case IP_PROTO_TCP: {
        struct tcp_hdr *tcph = (struct tcp_hdr *) transport_hdr;
        tcph->chksum         = 0;
        {
            // seed with folded pseudo-header checksum
            uint16_t init = checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_TCP, transport_len);

            // uint16_t d_sum = checksumDefault(transport_hdr, transport_len, 0);
            // uint16_t a_sum = checksum(transport_hdr, transport_len, 0);
            // assert(d_sum == a_sum);
            // discard d_sum;
            // discard a_sum;
            tcph->chksum = checksum(transport_hdr, (transport_len), init);
        }
        break;
    }
    case IP_PROTO_UDP: {
        struct udp_hdr *udph = (struct udp_hdr *) transport_hdr;
        udph->chksum         = 0;
        {
            uint16_t init =
                finalizeChecksum(checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_UDP, transport_len));
            udph->chksum = checksum(transport_hdr, transport_len, init);
        }
        /* RFC 768: checksum of zero is transmitted as all‑ones */
        if (udph->chksum == 0)
        {
            udph->chksum = 0xFFFF;
        }
        break;
    }
    case IP_PROTO_ICMP: {
        struct icmp_hdr *icmph = (struct icmp_hdr *) transport_hdr;
        icmph->chksum          = 0;
        // ICMP: no pseudo-header, just header+payload
        icmph->chksum = (checksum(transport_hdr, transport_len, 0));
        break;
    }
    default:
        /* other protocols: leave as is */
        break;
    }
}

uint16_t calcGenericChecksum(const uint8_t *data, size_t len, uint32_t initial)
{
    return checksum(data, len, initial);
}

void checkSumInit(void)
{
#if CHECKSUM_AVX2
    if (checkcpu_avx() && checkcpu_avx2_bmi2())
    {
        checksum = checksumAVX2;
        return;
    }
#endif
#if CHECKSUM_SSE3
    if (checkcpu_sse3())
    {
        checksum = checksumSSE3;
        return;
    }
#endif

    // else
    // {
    //     checksum = checksumAMD64;
    // }

    checksum = checksumDefault;
}

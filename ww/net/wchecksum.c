#include "wchecksum.h"

/*
 * Selects checksum backend and recomputes IPv4/L4 checksums for packets.
 */

#include "wlibc.h"

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


bool calcFullPacketChecksum(uint8_t *buf, size_t available_len)
{
    if (UNLIKELY(buf == NULL || available_len < IP_HLEN))
    {
        return false;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) buf;

    if (UNLIKELY(IPH_V(ipheader) != 4))
    {
        return false;
    }

    u16_t ip_hdr_len = IPH_HL_BYTES(ipheader);
    u16_t ip_tot_len = lwip_ntohs(IPH_LEN(ipheader));
    if (UNLIKELY(ip_hdr_len < IP_HLEN || ip_hdr_len > IP_HLEN_MAX || ip_hdr_len > available_len ||
                 ip_tot_len < ip_hdr_len || ip_tot_len > available_len))
    {
        return false;
    }

    uint8_t *transport_hdr = buf + ip_hdr_len;
    u16_t    transport_len = ip_tot_len - ip_hdr_len;
    u8_t     protocol      = IPH_PROTO(ipheader);
    u16_t     frag_field    = lwip_ntohs(IPH_OFFSET(ipheader));
    bool      fragmented    = (frag_field & (IP_MF | IP_OFFMASK)) != 0;

    /* Validate every field that will be accessed before modifying either checksum. */
    if (LIKELY(! fragmented))
    {
        switch (protocol)
        {
        case IP_PROTO_TCP: {
            if (UNLIKELY(transport_len < TCP_HLEN))
            {
                return false;
            }
            const struct tcp_hdr *tcph        = (const struct tcp_hdr *) transport_hdr;
            u16_t                 tcp_hdr_len = TCPH_HDRLEN_BYTES(tcph);
            if (UNLIKELY(tcp_hdr_len < TCP_HLEN || tcp_hdr_len > transport_len))
            {
                return false;
            }
            break;
        }
        case IP_PROTO_UDP: {
            if (UNLIKELY(transport_len < UDP_HLEN))
            {
                return false;
            }
            const struct udp_hdr *udph    = (const struct udp_hdr *) transport_hdr;
            u16_t                 udp_len = lwip_ntohs(udph->len);
            if (UNLIKELY(udp_len < UDP_HLEN || udp_len > transport_len))
            {
                return false;
            }
            break;
        }
        case IP_PROTO_ICMP:
            if (UNLIKELY(transport_len < sizeof(struct icmp_hdr)))
            {
                return false;
            }
            break;
        default:
            break;
        }
    }

    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, ip_hdr_len));

    /* Fragmented IPv4 packets cannot have transport checksum recalculated per-fragment. */
    if (UNLIKELY(fragmented))
    {
        return true;
    }

    switch (protocol)
    {
    case IP_PROTO_TCP: {
        struct tcp_hdr *tcph = (struct tcp_hdr *) transport_hdr;
        tcph->chksum         = 0;
        {
            // seed with pseudo-header checksum (not finalized)
            uint32_t init = checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_TCP, transport_len);

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
        u16_t           udp_len = lwip_ntohs(udph->len);
        udph->chksum         = 0;
        {
            uint32_t init = checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_UDP, udp_len);
            udph->chksum = checksum(transport_hdr, udp_len, init);
        }
        /* RFC 768: checksum of zero is transmitted as all‑ones */
        if (UNLIKELY(udph->chksum == 0))
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

    return true;
}

uint16_t calcGenericChecksum(const uint8_t *data, uint16_t len, uint32_t initial)
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

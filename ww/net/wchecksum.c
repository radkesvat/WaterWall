#include "wchecksum.h"

/*
 * Selects checksum backend and recomputes IPv4/L4 checksums for packets.
 */

#include "ipv4_packet_view.h"
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
    ipv4_packet_view_t packet = {0};
    if (! ipv4packetviewParse(buf, available_len, &packet))
    {
        return false;
    }

    struct ip_hdr *ipheader      = (struct ip_hdr *) buf;
    uint8_t       *transport_hdr = buf + packet.transport_offset;

    /* Validate every field that will be accessed before modifying either checksum. */
    if (LIKELY(! packet.fragmented))
    {
        ipv4_packet_view_t transport = {0};
        switch (packet.protocol)
        {
        case IP_PROTO_TCP:
            if (! ipv4packetviewParseTcp(buf, available_len, &transport))
            {
                return false;
            }
            break;
        case IP_PROTO_UDP:
            if (! ipv4packetviewParseUdp(buf, available_len, &transport))
            {
                return false;
            }
            break;
        case IP_PROTO_ICMP:
            if (UNLIKELY(packet.transport_length < sizeof(struct icmp_hdr)))
            {
                return false;
            }
            break;
        default:
            break;
        }
    }

    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, packet.ip_header_length));

    /* Fragmented IPv4 packets cannot have transport checksum recalculated per-fragment. */
    if (UNLIKELY(packet.fragmented))
    {
        return true;
    }

    switch (packet.protocol)
    {
    case IP_PROTO_TCP: {
        struct tcp_hdr *tcph = (struct tcp_hdr *) transport_hdr;
        tcph->chksum         = 0;
        {
            // seed with pseudo-header checksum (not finalized)
            uint32_t init =
                checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_TCP, packet.transport_length);

            // uint16_t d_sum = checksumDefault(transport_hdr, transport_len, 0);
            // uint16_t a_sum = checksum(transport_hdr, transport_len, 0);
            // assert(d_sum == a_sum);
            // discard d_sum;
            // discard a_sum;
            tcph->chksum = checksum(transport_hdr, packet.transport_length, init);
        }
        break;
    }
    case IP_PROTO_UDP: {
        struct udp_hdr *udph    = (struct udp_hdr *) transport_hdr;
        u16_t           udp_len = lwip_ntohs(udph->len);
        udph->chksum            = 0;
        {
            uint32_t init = checksumPseudoHeader(&ipheader->src, &ipheader->dest, IP_PROTO_UDP, udp_len);
            udph->chksum  = checksum(transport_hdr, udp_len, init);
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
        icmph->chksum = (checksum(transport_hdr, packet.transport_length, 0));
        break;
    }
    default:
        /* other protocols: leave as is */
        break;
    }

    return true;
}

static inline uint16_t checksumUpdateWord16(uint16_t checksum_network, uint16_t old_word_network,
                                            uint16_t new_word_network)
{
    if (old_word_network == new_word_network)
    {
        return checksum_network;
    }

    uint16_t hc      = lwip_ntohs(checksum_network);
    uint16_t m       = lwip_ntohs(old_word_network);
    uint16_t m_prime = lwip_ntohs(new_word_network);

    uint32_t sum = (uint32_t) ((~hc) & 0xFFFFU) + (uint32_t) ((~m) & 0xFFFFU) + (uint32_t) m_prime;
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    uint16_t hc_prime = (uint16_t) (~sum);
    return lwip_htons(hc_prime);
}

static inline uint16_t checksumUpdateWord32(uint16_t checksum_network, uint32_t old_value_network,
                                            uint32_t new_value_network)
{
    if (old_value_network == new_value_network)
    {
        return checksum_network;
    }

    uint32_t old32_h = lwip_ntohl(old_value_network);
    uint32_t new32_h = lwip_ntohl(new_value_network);

    uint16_t old_high = lwip_htons((uint16_t) (old32_h >> 16));
    uint16_t old_low  = lwip_htons((uint16_t) (old32_h & 0xFFFFU));
    uint16_t new_high = lwip_htons((uint16_t) (new32_h >> 16));
    uint16_t new_low  = lwip_htons((uint16_t) (new32_h & 0xFFFFU));

    uint16_t step1 = checksumUpdateWord16(checksum_network, old_high, new_high);
    return checksumUpdateWord16(step1, old_low, new_low);
}

bool updateIpv4TransportChecksumAddresses(uint8_t *buf, size_t available_len, uint8_t effective_protocol,
                                          uint32_t old_source_network, uint32_t old_destination_network,
                                          uint32_t new_source_network, uint32_t new_destination_network)
{
    ipv4_packet_view_t packet = {0};
    if ((effective_protocol != IPPROTO_TCP && effective_protocol != IPPROTO_UDP) ||
        ! ipv4packetviewParse(buf, available_len, &packet))
    {
        return false;
    }

    const uint32_t start           = (uint32_t) packet.fragment_offset * 8U;
    const uint32_t end             = start + packet.transport_length;
    const uint32_t checksum_offset = effective_protocol == IPPROTO_TCP ? 16U : 6U;
    const uint8_t *payload         = buf + packet.transport_offset;
    if (packet.fragmented &&
        (packet.transport_length == 0 || (packet.more_fragments && packet.transport_length % 8U != 0) ||
         end > UINT16_MAX - IP_HLEN || (packet.fragment_state & IP_DF) != 0))
    {
        return false;
    }

    /* Validate whichever structural fields are locally present, even under a mapped protocol. */
    if (effective_protocol == IPPROTO_TCP)
    {
        if (! packet.more_fragments && end < TCP_HLEN)
        {
            return false;
        }
        if (start <= 12U && end > 12U)
        {
            uint32_t header_length = (uint32_t) (payload[12U - start] >> 4) * 4U;
            if (header_length < TCP_HLEN || (! packet.more_fragments && header_length > end))
            {
                return false;
            }
        }
    }
    else
    {
        if (! packet.more_fragments && end < UDP_HLEN)
        {
            return false;
        }
        if (start == 0 && end >= 6U)
        {
            uint16_t udp_length = (uint16_t) (((uint16_t) payload[4] << 8) | payload[5]);
            if (udp_length < UDP_HLEN || (! packet.fragmented && udp_length > end))
            {
                return false;
            }
        }
    }

    if (end <= checksum_offset || start >= checksum_offset + 2U)
    {
        return packet.fragmented;
    }
    if (start > checksum_offset || end < checksum_offset + 2U)
    {
        return false;
    }

    uint8_t *field = buf + packet.transport_offset + checksum_offset - start;
    uint16_t value;
    memcpy(&value, field, sizeof(value));
    if (effective_protocol == IPPROTO_UDP && value == 0)
    {
        return true;
    }
    value = checksumUpdateWord32(value, old_source_network, new_source_network);
    value = checksumUpdateWord32(value, old_destination_network, new_destination_network);
    if (effective_protocol == IPPROTO_UDP && value == 0)
    {
        value = 0xffff;
    }
    memcpy(field, &value, sizeof(value));
    return true;
}

bool calcIpv4HeaderChecksum(uint8_t *buf, size_t available_len)
{
    ipv4_packet_view_t packet = {0};
    if (! ipv4packetviewParse(buf, available_len, &packet))
    {
        return false;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) buf;
    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, packet.ip_header_length));
    return true;
}

bool setIpv4AddressWithChecksumUpdate(uint8_t *buf, size_t available_len, ipv4_checksum_address_field_e field,
                                      uint32_t new_address_network)
{
    if (UNLIKELY(field != kIpv4ChecksumAddressSource && field != kIpv4ChecksumAddressDestination))
    {
        return false;
    }

    ipv4_packet_view_t packet = {0};
    if (! ipv4packetviewParse(buf, available_len, &packet))
    {
        return false;
    }

    struct ip_hdr *ipheader      = (struct ip_hdr *) buf;
    uint32_t old_address_network = (field == kIpv4ChecksumAddressSource) ? ipheader->src.addr : ipheader->dest.addr;

    if (old_address_network == new_address_network)
    {
        return true;
    }

    struct tcp_hdr *tcph                    = NULL;
    struct udp_hdr *udph                    = NULL;
    bool            update_transport_chksum = false;

    if (packet.fragment_offset == 0)
    {
        ipv4_packet_view_t transport = {0};
        if (packet.protocol == IP_PROTO_TCP)
        {
            if (! ipv4packetviewParseTcp(buf, available_len, &transport))
            {
                return false;
            }
            tcph                    = (struct tcp_hdr *) (buf + transport.transport_offset);
            update_transport_chksum = true;
        }
        else if (packet.protocol == IP_PROTO_UDP)
        {
            if (! ipv4packetviewParseUdp(buf, available_len, &transport))
            {
                return false;
            }
            udph = (struct udp_hdr *) (buf + transport.transport_offset);
            if (udph->chksum != 0)
            {
                update_transport_chksum = true;
            }
        }
    }

    uint16_t old_ip_chksum    = IPH_CHKSUM(ipheader);
    uint16_t new_ip_chksum    = checksumUpdateWord32(old_ip_chksum, old_address_network, new_address_network);
    uint16_t new_trans_chksum = 0;

    if (update_transport_chksum)
    {
        if (packet.protocol == IP_PROTO_TCP)
        {
            new_trans_chksum = checksumUpdateWord32(tcph->chksum, old_address_network, new_address_network);
        }
        else if (packet.protocol == IP_PROTO_UDP)
        {
            new_trans_chksum = checksumUpdateWord32(udph->chksum, old_address_network, new_address_network);
            if (UNLIKELY(new_trans_chksum == 0))
            {
                new_trans_chksum = 0xFFFF;
            }
        }
    }

    if (field == kIpv4ChecksumAddressSource)
    {
        ipheader->src.addr = new_address_network;
    }
    else
    {
        ipheader->dest.addr = new_address_network;
    }
    IPH_CHKSUM_SET(ipheader, new_ip_chksum);

    if (update_transport_chksum)
    {
        if (packet.protocol == IP_PROTO_TCP)
        {
            tcph->chksum = new_trans_chksum;
        }
        else if (packet.protocol == IP_PROTO_UDP)
        {
            udph->chksum = new_trans_chksum;
        }
    }

    return true;
}

bool updateIpv4TransportChecksum16(uint8_t *buf, size_t available_len, uint16_t old_word_network,
                                   uint16_t new_word_network)
{
    ipv4_packet_view_t packet = {0};
    if (! ipv4packetviewParse(buf, available_len, &packet))
    {
        return false;
    }

    if (packet.protocol != IP_PROTO_TCP && packet.protocol != IP_PROTO_UDP)
    {
        return false;
    }

    if (packet.fragment_offset > 0)
    {
        return false;
    }

    struct tcp_hdr *tcph = NULL;
    struct udp_hdr *udph = NULL;

    ipv4_packet_view_t transport = {0};
    if (packet.protocol == IP_PROTO_TCP)
    {
        if (! ipv4packetviewParseTcp(buf, available_len, &transport))
        {
            return false;
        }
        tcph = (struct tcp_hdr *) (buf + transport.transport_offset);
    }
    else
    {
        if (! ipv4packetviewParseUdp(buf, available_len, &transport))
        {
            return false;
        }
        udph = (struct udp_hdr *) (buf + transport.transport_offset);
    }

    if (old_word_network == new_word_network)
    {
        return true;
    }

    if (packet.protocol == IP_PROTO_TCP)
    {
        tcph->chksum = checksumUpdateWord16(tcph->chksum, old_word_network, new_word_network);
    }
    else if (packet.protocol == IP_PROTO_UDP)
    {
        if (udph->chksum != 0)
        {
            uint16_t new_chksum = checksumUpdateWord16(udph->chksum, old_word_network, new_word_network);
            if (UNLIKELY(new_chksum == 0))
            {
                new_chksum = 0xFFFF;
            }
            udph->chksum = new_chksum;
        }
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

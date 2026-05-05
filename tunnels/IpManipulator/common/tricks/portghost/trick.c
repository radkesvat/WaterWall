#include "trick.h"

#include "loggers/network_logger.h"

enum
{
    kGhostedPortMin  = 1024U,
    kGhostedPortSpan = 65535U - kGhostedPortMin + 1U,
    kGhostSaltSource = 0x53U,
    kGhostSaltDest   = 0x44U
};

static uint32_t mixGhostPortSeed(uint32_t value)
{
    value ^= value >> 16;
    value *= 0x7FEB352DU;
    value ^= value >> 15;
    value *= 0x846CA68BU;
    value ^= value >> 16;
    return value;
}

static uint32_t rotateLeft32(uint32_t value, uint8_t bits)
{
    return (value << bits) | (value >> (32U - bits));
}

static uint8_t resolveTransportProtocol(const ipmanipulator_tstate_t *state, uint8_t packet_protocol)
{
    if (packet_protocol == IPPROTO_TCP || packet_protocol == state->trick_proto_swap_tcp_number ||
        packet_protocol == state->trick_proto_swap_tcp_number_2)
    {
        return IPPROTO_TCP;
    }

    if (packet_protocol == IPPROTO_UDP || packet_protocol == state->trick_proto_swap_udp_number)
    {
        return IPPROTO_UDP;
    }

    return 0;
}

static uint16_t ghostPortFromTuple(uint16_t original_port, uint16_t peer_port, uint32_t src_addr, uint32_t dst_addr,
                                   uint8_t protocol, uint8_t salt)
{
    uint32_t seed = ((uint32_t) original_port << 16) | peer_port;

    seed ^= lwip_ntohl(src_addr);
    seed ^= rotateLeft32(lwip_ntohl(dst_addr), 7);
    seed ^= ((uint32_t) protocol << 24) ^ ((uint32_t) salt << 8);

    uint16_t ghost_port = (uint16_t) (kGhostedPortMin + (mixGhostPortSeed(seed) % kGhostedPortSpan));
    if (ghost_port == original_port)
    {
        ghost_port = ghost_port == UINT16_MAX ? (uint16_t) kGhostedPortMin : (uint16_t) (ghost_port + 1U);
    }

    return ghost_port;
}

uint32_t portghosttrickGetTailLength(const ipmanipulator_tstate_t *state)
{
    uint32_t tail_len = 0;

    if (state->trick_source_port_ghost)
    {
        tail_len += sizeof(uint16_t);
    }

    if (state->trick_dest_port_ghost)
    {
        tail_len += sizeof(uint16_t);
    }

    return tail_len;
}

static bool dropGhostedPacket(line_t *l, sbuf_t **buf_ptr)
{
    if (buf_ptr == NULL || *buf_ptr == NULL)
    {
        return false;
    }

    lineReuseBuffer(l, *buf_ptr);
    *buf_ptr = NULL;
    return false;
}

static bool appendGhostBytes(line_t *l, sbuf_t **buf_ptr, struct ip_hdr **ipheader_ptr, uint32_t tail_len)
{
    sbuf_t  *buf          = *buf_ptr;
    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(*ipheader_ptr));

    if (tail_len == 0)
    {
        return false;
    }

    if (ip_total_len > UINT16_MAX - tail_len)
    {
        LOGW("portghosttrick: cannot append ghost bytes because IPv4 total length would overflow");
        return dropGhostedPacket(l, buf_ptr);
    }

    uint32_t new_len = (uint32_t) ip_total_len + tail_len;
    if (sbufGetMaximumWriteableSize(buf) < new_len)
    {
        LOGW("portghosttrick: dropping packet because source/dest-port-ghost needs %u extra bytes but the buffer has no room",
             (unsigned int) tail_len);
        return dropGhostedPacket(l, buf_ptr);
    }

    sbufSetLength(buf, new_len);
    *buf_ptr      = buf;
    *ipheader_ptr = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_LEN_SET(*ipheader_ptr, lwip_htons((uint16_t) new_len));
    return true;
}

bool portghosttrickApply(tunnel_t *t, line_t *l, sbuf_t **buf_ptr)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    sbuf_t                 *buf   = *buf_ptr;

    uint32_t tail_len = portghosttrickGetTailLength(state);
    if (tail_len == 0 || buf == NULL)
    {
        return false;
    }

    if (sbufGetLength(buf) < sizeof(struct ip_hdr))
    {
        return false;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    if (IPH_V(ipheader) != 4)
    {
        return false;
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    uint8_t ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        LOGE("portghosttrick: invalid IP header length: %u", ip_hdr_len_words);
        return false;
    }

    uint16_t iphdr_len = (uint16_t) (ip_hdr_len_words * 4U);
    if (sbufGetLength(buf) < iphdr_len)
    {
        LOGE("portghosttrick: buffer too small for IPv4 header");
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < iphdr_len || ip_total_len > sbufGetLength(buf))
    {
        LOGE("portghosttrick: invalid IPv4 total length");
        return false;
    }

    uint8_t *packet = sbufGetMutablePtr(buf);
    uint8_t *tail   = packet + ip_total_len;

    switch (resolveTransportProtocol(state, IPH_PROTO(ipheader)))
    {
    case IPPROTO_TCP: {
        if (ip_total_len < iphdr_len + sizeof(struct tcp_hdr))
        {
            LOGE("portghosttrick: packet too small for minimum TCP header");
            return false;
        }

        struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + iphdr_len);
        uint8_t         tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
        if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
        {
            LOGE("portghosttrick: invalid TCP header length: %u", tcp_hdr_len_words);
            return false;
        }

        uint16_t tcphdr_len = (uint16_t) (tcp_hdr_len_words * 4U);
        if (ip_total_len < iphdr_len + tcphdr_len)
        {
            LOGE("portghosttrick: invalid packet lengths while ghosting TCP packet");
            return false;
        }

        uint16_t original_src_port = lwip_ntohs(tcp_header->src);
        uint16_t original_dst_port = lwip_ntohs(tcp_header->dest);

        if (! appendGhostBytes(l, buf_ptr, &ipheader, tail_len))
        {
            return false;
        }

        packet     = sbufGetMutablePtr(*buf_ptr);
        tail       = packet + ip_total_len;
        tcp_header = (struct tcp_hdr *) (packet + iphdr_len);

        if (state->trick_source_port_ghost)
        {
            PUT_BE16(tail, original_src_port);
            tail += sizeof(uint16_t);
            tcp_header->src = lwip_htons(ghostPortFromTuple(original_src_port, original_dst_port, ipheader->src.addr,
                                                            ipheader->dest.addr, IPPROTO_TCP, kGhostSaltSource));
        }

        if (state->trick_dest_port_ghost)
        {
            PUT_BE16(tail, original_dst_port);
            tail += sizeof(uint16_t);
            tcp_header->dest = lwip_htons(ghostPortFromTuple(original_dst_port, original_src_port, ipheader->src.addr,
                                                             ipheader->dest.addr, IPPROTO_TCP, kGhostSaltDest));
        }

        return true;
    }

    case IPPROTO_UDP: {
        if (ip_total_len < iphdr_len + UDP_HLEN)
        {
            LOGE("portghosttrick: packet too small for minimum UDP header");
            return false;
        }

        struct udp_hdr *udp_header = (struct udp_hdr *) (packet + iphdr_len);
        uint16_t        udp_len       = lwip_ntohs(udp_header->len);
        uint16_t        transport_len = (uint16_t) (ip_total_len - iphdr_len);

        if (udp_len < UDP_HLEN || udp_len > transport_len || udp_len > UINT16_MAX - tail_len)
        {
            LOGE("portghosttrick: invalid packet lengths while ghosting UDP packet");
            return false;
        }

        uint16_t original_src_port = lwip_ntohs(udp_header->src);
        uint16_t original_dst_port = lwip_ntohs(udp_header->dest);

        if (! appendGhostBytes(l, buf_ptr, &ipheader, tail_len))
        {
            return false;
        }

        packet     = sbufGetMutablePtr(*buf_ptr);
        tail       = packet + ip_total_len;
        udp_header = (struct udp_hdr *) (packet + iphdr_len);

        if (state->trick_source_port_ghost)
        {
            PUT_BE16(tail, original_src_port);
            tail += sizeof(uint16_t);
            udp_header->src = lwip_htons(ghostPortFromTuple(original_src_port, original_dst_port, ipheader->src.addr,
                                                            ipheader->dest.addr, IPPROTO_UDP, kGhostSaltSource));
        }

        if (state->trick_dest_port_ghost)
        {
            PUT_BE16(tail, original_dst_port);
            tail += sizeof(uint16_t);
            udp_header->dest = lwip_htons(ghostPortFromTuple(original_dst_port, original_src_port, ipheader->src.addr,
                                                             ipheader->dest.addr, IPPROTO_UDP, kGhostSaltDest));
        }

        udp_header->len = lwip_htons((uint16_t) (udp_len + tail_len));
        return true;
    }

    default:
        return false;
    }
}

bool portghosttrickRestore(tunnel_t *t, line_t *l, sbuf_t **buf_ptr)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    sbuf_t                 *buf      = *buf_ptr;
    uint32_t                tail_len = portghosttrickGetTailLength(state);

    if (tail_len == 0 || buf == NULL)
    {
        return false;
    }

    if (sbufGetLength(buf) < sizeof(struct ip_hdr))
    {
        return false;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    if (IPH_V(ipheader) != 4)
    {
        return false;
    }

    uint16_t off_f = lwip_ntohs(IPH_OFFSET(ipheader));
    if ((off_f & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    uint8_t packet_protocol = resolveTransportProtocol(state, IPH_PROTO(ipheader));
    if (packet_protocol == 0)
    {
        return false;
    }

    uint8_t ip_hdr_len_words = IPH_HL(ipheader);
    if (ip_hdr_len_words < 5 || ip_hdr_len_words > 15)
    {
        LOGE("portghosttrick: invalid IP header length while restoring: %u", ip_hdr_len_words);
        return false;
    }

    uint16_t iphdr_len = (uint16_t) (ip_hdr_len_words * 4U);
    if (sbufGetLength(buf) < iphdr_len)
    {
        LOGE("portghosttrick: buffer too small for IPv4 header while restoring");
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < iphdr_len || ip_total_len > sbufGetLength(buf) || ip_total_len < iphdr_len + tail_len)
    {
        return false;
    }

    uint8_t *packet    = sbufGetMutablePtr(buf);
    uint8_t *tail      = packet + ip_total_len - tail_len;
    uint16_t tail_src  = 0;
    uint16_t tail_dest = 0;

    if (state->trick_source_port_ghost)
    {
        tail_src = GET_BE16(tail);
        tail += sizeof(uint16_t);
    }

    if (state->trick_dest_port_ghost)
    {
        tail_dest = GET_BE16(tail);
    }

    switch (packet_protocol)
    {
    case IPPROTO_TCP: {
        if (ip_total_len < iphdr_len + sizeof(struct tcp_hdr))
        {
            return false;
        }

        struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + iphdr_len);
        uint8_t         tcp_hdr_len_words = TCPH_HDRLEN(tcp_header);
        if (tcp_hdr_len_words < 5 || tcp_hdr_len_words > 15)
        {
            LOGE("portghosttrick: invalid TCP header length while restoring: %u", tcp_hdr_len_words);
            return false;
        }

        uint16_t tcphdr_len = (uint16_t) (tcp_hdr_len_words * 4U);
        if (ip_total_len < iphdr_len + tcphdr_len + tail_len)
        {
            return false;
        }

        uint16_t current_src = lwip_ntohs(tcp_header->src);
        uint16_t current_dst = lwip_ntohs(tcp_header->dest);
        uint16_t original_src = state->trick_source_port_ghost ? tail_src : current_src;
        uint16_t original_dst = state->trick_dest_port_ghost ? tail_dest : current_dst;

        if (state->trick_source_port_ghost &&
            current_src != ghostPortFromTuple(original_src, original_dst, ipheader->src.addr, ipheader->dest.addr,
                                              IPPROTO_TCP, kGhostSaltSource))
        {
            return false;
        }

        if (state->trick_dest_port_ghost &&
            current_dst != ghostPortFromTuple(original_dst, original_src, ipheader->src.addr, ipheader->dest.addr,
                                              IPPROTO_TCP, kGhostSaltDest))
        {
            return false;
        }

        tcp_header->src  = lwip_htons(original_src);
        tcp_header->dest = lwip_htons(original_dst);
        break;
    }

    case IPPROTO_UDP: {
        if (ip_total_len < iphdr_len + UDP_HLEN)
        {
            return false;
        }

        struct udp_hdr *udp_header    = (struct udp_hdr *) (packet + iphdr_len);
        uint16_t        udp_len       = lwip_ntohs(udp_header->len);
        uint16_t        transport_len = (uint16_t) (ip_total_len - iphdr_len);

        if (udp_len < UDP_HLEN + tail_len || udp_len > transport_len)
        {
            return false;
        }

        uint16_t current_src = lwip_ntohs(udp_header->src);
        uint16_t current_dst = lwip_ntohs(udp_header->dest);
        uint16_t original_src = state->trick_source_port_ghost ? tail_src : current_src;
        uint16_t original_dst = state->trick_dest_port_ghost ? tail_dest : current_dst;

        if (state->trick_source_port_ghost &&
            current_src != ghostPortFromTuple(original_src, original_dst, ipheader->src.addr, ipheader->dest.addr,
                                              IPPROTO_UDP, kGhostSaltSource))
        {
            return false;
        }

        if (state->trick_dest_port_ghost &&
            current_dst != ghostPortFromTuple(original_dst, original_src, ipheader->src.addr, ipheader->dest.addr,
                                              IPPROTO_UDP, kGhostSaltDest))
        {
            return false;
        }

        udp_header->src  = lwip_htons(original_src);
        udp_header->dest = lwip_htons(original_dst);
        udp_header->len  = lwip_htons((uint16_t) (udp_len - tail_len));
        break;
    }

    default:
        return false;
    }

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) (ip_total_len - tail_len)));
    sbufSetLength(buf, (uint16_t) (ip_total_len - tail_len));
    lineSetRecalculateChecksum(l, true);
    return true;
}

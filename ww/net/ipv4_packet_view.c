#include "ipv4_packet_view.h"

bool ipv4packetviewParse(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view)
{
    if (UNLIKELY(packet == NULL || view == NULL || available_length < IP_HLEN))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;
    if (UNLIKELY(IPH_V(ipheader) != 4))
    {
        return false;
    }

    uint16_t ip_header_length = IPH_HL_BYTES(ipheader);
    uint16_t ip_total_length  = lwip_ntohs(IPH_LEN(ipheader));
    if (UNLIKELY(ip_header_length < IP_HLEN || ip_header_length > IP_HLEN_MAX || ip_header_length > available_length ||
                 ip_total_length < ip_header_length || ip_total_length > available_length))
    {
        return false;
    }

    uint16_t fragment_state = lwip_ntohs(IPH_OFFSET(ipheader));

    *view = (ipv4_packet_view_t) {
        .source_address      = ipheader->src.addr,
        .destination_address = ipheader->dest.addr,
        .ip_total_length     = ip_total_length,
        .ip_header_length    = ip_header_length,
        .transport_offset    = ip_header_length,
        .transport_length    = (uint16_t) (ip_total_length - ip_header_length),
        .payload_offset      = ip_header_length,
        .payload_length      = (uint16_t) (ip_total_length - ip_header_length),
        .fragment_state      = fragment_state,
        .fragment_offset     = (uint16_t) (fragment_state & IP_OFFMASK),
        .ip_identification   = lwip_ntohs(IPH_ID(ipheader)),
        .protocol            = IPH_PROTO(ipheader),
        .ttl                 = ipheader->_ttl,
        .more_fragments      = (fragment_state & IP_MF) != 0,
        .fragmented          = (fragment_state & (IP_MF | IP_OFFMASK)) != 0,
    };

    return true;
}

bool ipv4packetviewParseTcp(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view)
{
    ipv4_packet_view_t parsed = {0};
    if (! ipv4packetviewParse(packet, available_length, &parsed) || parsed.protocol != IPPROTO_TCP ||
        parsed.fragment_offset != 0 || parsed.transport_length < TCP_HLEN)
    {
        return false;
    }

    const struct tcp_hdr *tcpheader         = (const struct tcp_hdr *) (packet + parsed.transport_offset);
    uint16_t              tcp_header_length = TCPH_HDRLEN_BYTES(tcpheader);
    if (UNLIKELY(tcp_header_length < TCP_HLEN || tcp_header_length > parsed.transport_length))
    {
        return false;
    }

    parsed.transport_header_length = tcp_header_length;
    parsed.payload_offset          = (uint16_t) (parsed.transport_offset + tcp_header_length);
    parsed.payload_length          = (uint16_t) (parsed.transport_length - tcp_header_length);
    parsed.source_port             = lwip_ntohs(tcpheader->src);
    parsed.destination_port        = lwip_ntohs(tcpheader->dest);
    parsed.tcp_sequence            = lwip_ntohl(tcpheader->seqno);
    parsed.tcp_acknowledgment      = lwip_ntohl(tcpheader->ackno);
    parsed.tcp_flags               = (uint8_t) (lwip_ntohs(tcpheader->_hdrlen_rsvd_flags) & 0x00FFU);
    parsed.tcp_sequence_span       = (uint32_t) parsed.payload_length + ((parsed.tcp_flags & TCP_SYN) != 0 ? 1U : 0U) +
                               ((parsed.tcp_flags & TCP_FIN) != 0 ? 1U : 0U);

    *view = parsed;
    return true;
}

bool ipv4packetviewParseUdp(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view)
{
    ipv4_packet_view_t parsed = {0};
    if (! ipv4packetviewParse(packet, available_length, &parsed) || parsed.protocol != IPPROTO_UDP ||
        parsed.fragment_offset != 0 || parsed.transport_length < UDP_HLEN)
    {
        return false;
    }

    const struct udp_hdr *udpheader  = (const struct udp_hdr *) (packet + parsed.transport_offset);
    uint16_t              udp_length = lwip_ntohs(udpheader->len);
    if (UNLIKELY(udp_length < UDP_HLEN || (! parsed.fragmented && udp_length > parsed.transport_length)))
    {
        return false;
    }

    parsed.transport_header_length = UDP_HLEN;
    parsed.payload_offset          = (uint16_t) (parsed.transport_offset + UDP_HLEN);
    parsed.payload_length          = (uint16_t) ((parsed.fragmented ? parsed.transport_length : udp_length) - UDP_HLEN);
    parsed.source_port             = lwip_ntohs(udpheader->src);
    parsed.destination_port        = lwip_ntohs(udpheader->dest);
    parsed.udp_datagram_length     = udp_length;

    *view = parsed;
    return true;
}

bool ipv4packetviewTcpFlagsAreOpeningSyn(uint8_t tcp_flags, uint32_t tcp_payload_length)
{
    if (tcp_payload_length != 0 || (tcp_flags & TCP_SYN) == 0)
    {
        return false;
    }

    return (tcp_flags & (uint8_t) (0xFFU & ~(TCP_SYN | TCP_ECE | TCP_CWR))) == 0;
}

bool ipv4packetviewIsOpeningTcpSyn(const ipv4_packet_view_t *view)
{
    return view != NULL && ! view->fragmented && view->protocol == IPPROTO_TCP &&
           view->transport_header_length >= TCP_HLEN &&
           ipv4packetviewTcpFlagsAreOpeningSyn(view->tcp_flags, view->payload_length);
}

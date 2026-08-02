#include "ipv4_packet_view.h"

enum
{
    kPacketCapacity = 256,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static uint16_t makeTcpPacket(uint8_t *packet, uint8_t flags, uint16_t payload_length, uint16_t fragment_state)
{
    memoryZero(packet, kPacketCapacity);

    const uint16_t ip_header_length = 24;
    const uint16_t total_length     = (uint16_t) (ip_header_length + TCP_HLEN + payload_length);
    struct ip_hdr *ipheader         = (struct ip_hdr *) packet;
    IPH_VHL_SET(ipheader, 4, ip_header_length / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_length));
    IPH_ID_SET(ipheader, lwip_htons(0x1234));
    IPH_OFFSET_SET(ipheader, lwip_htons(fragment_state));
    IPH_TTL_SET(ipheader, 61);
    IPH_PROTO_SET(ipheader, IPPROTO_TCP);
    ipheader->src.addr  = lwip_htonl(0xC0000201U);
    ipheader->dest.addr = lwip_htonl(0xC6336402U);

    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (packet + ip_header_length);
    tcpheader->src            = lwip_htons(12345);
    tcpheader->dest           = lwip_htons(443);
    tcpheader->seqno          = lwip_htonl(0x10203040U);
    tcpheader->ackno          = lwip_htonl(0x50607080U);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, TCP_HLEN / 4U, flags);
    return total_length;
}

static uint16_t makeUdpPacket(uint8_t *packet, uint16_t available_payload, uint16_t declared_payload,
                              uint16_t fragment_state)
{
    memoryZero(packet, kPacketCapacity);

    const uint16_t total_length = (uint16_t) (IP_HLEN + UDP_HLEN + available_payload);
    struct ip_hdr *ipheader     = (struct ip_hdr *) packet;
    IPH_VHL_SET(ipheader, 4, IP_HLEN / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_length));
    IPH_OFFSET_SET(ipheader, lwip_htons(fragment_state));
    IPH_PROTO_SET(ipheader, IPPROTO_UDP);

    struct udp_hdr *udpheader = (struct udp_hdr *) (packet + IP_HLEN);
    udpheader->src            = lwip_htons(5353);
    udpheader->dest           = lwip_htons(53);
    udpheader->len            = lwip_htons((uint16_t) (UDP_HLEN + declared_payload));
    return total_length;
}

int main(void)
{
    uint8_t packet[kPacketCapacity];

    uint16_t           length = makeTcpPacket(packet, TCP_SYN | TCP_ECE | TCP_CWR, 0, IP_RF | IP_DF);
    ipv4_packet_view_t view   = {0};
    require(ipv4packetviewParseTcp(packet, length, &view), "valid TCP packet was rejected");
    require(view.ip_header_length == 24 && view.transport_offset == 24 && view.payload_offset == 44,
            "TCP offsets are incorrect");
    require(view.source_port == 12345 && view.destination_port == 443 && view.tcp_sequence == 0x10203040U &&
                view.tcp_acknowledgment == 0x50607080U,
            "TCP transport fields are incorrect");
    require(view.fragment_state == (IP_RF | IP_DF) && ! view.fragmented, "non-fragment IPv4 flags were not preserved");
    require(view.tcp_flags == (TCP_SYN | TCP_ECE | TCP_CWR) && ipv4packetviewTcpHasAllFlags(&view, TCP_ECE | TCP_CWR),
            "TCP ECN flags were not preserved in the packet view");
    require(view.tcp_sequence_span == 1 && ipv4packetviewIsOpeningTcpSyn(&view), "ECN opening SYN was not recognized");

    length = makeTcpPacket(packet, TCP_SYN | TCP_FIN, 3, 0);
    require(ipv4packetviewParseTcp(packet, length, &view) && view.payload_length == 3 && view.tcp_sequence_span == 5 &&
                ! ipv4packetviewIsOpeningTcpSyn(&view),
            "TCP sequence span or opening-SYN rejection is incorrect");

    length = makeTcpPacket(packet, TCP_ACK, 0, IP_MF);
    require(ipv4packetviewParseTcp(packet, length, &view) && view.fragmented && view.more_fragments,
            "first TCP fragment was not represented");
    length = makeTcpPacket(packet, TCP_SYN, 0, IP_MF);
    require(ipv4packetviewParseTcp(packet, length, &view) && ! ipv4packetviewIsOpeningTcpSyn(&view),
            "fragmented TCP SYN was classified as a payload-free opening SYN");
    length = makeTcpPacket(packet, TCP_ACK, 0, 1);
    require(! ipv4packetviewParseTcp(packet, length, &view), "non-first TCP fragment was parsed as a TCP header");

    length = makeUdpPacket(packet, 8, 64, IP_MF);
    require(ipv4packetviewParseUdp(packet, length, &view) && view.payload_length == 8 &&
                view.udp_datagram_length == UDP_HLEN + 64,
            "first UDP fragment did not retain declared and available lengths");
    length = makeUdpPacket(packet, 8, 64, 0);
    require(! ipv4packetviewParseUdp(packet, length, &view), "oversized unfragmented UDP length was accepted");
    length = makeUdpPacket(packet, 16, 8, 0);
    require(ipv4packetviewParseUdp(packet, length, &view) && view.payload_length == 8 && view.transport_length == 24,
            "unfragmented UDP payload length did not follow its declared datagram length");

    require(! ipv4packetviewParse(NULL, 0, &view), "NULL IPv4 packet was accepted");
    require(! ipv4packetviewParse(packet, IP_HLEN - 1U, &view), "truncated IPv4 packet was accepted");
    return 0;
}

#include "wchecksum.h"
#include "wlibc.h"

#include <stdio.h>
#include <stdlib.h>

enum
{
    kTestPacketCapacity = 96
};

typedef union test_packet_u
{
    uint64_t alignment;
    uint8_t  bytes[kTestPacketCapacity];
} test_packet_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void initializeIpv4Packet(test_packet_t *packet, uint16_t total_len, uint8_t protocol)
{
    memoryZero(packet, sizeof(*packet));

    struct ip_hdr *ipheader = (struct ip_hdr *) packet->bytes;
    IPH_VHL_SET(ipheader, 4, IP_HLEN / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, protocol);
    ipheader->src.addr  = lwip_htonl(0xC0000201U);
    ipheader->dest.addr = lwip_htonl(0xC6336402U);
}

static void requireRejectedUnchanged(test_packet_t *packet, size_t available_len, const char *message)
{
    test_packet_t before = *packet;

    require(! calcFullPacketChecksum(packet->bytes, available_len), message);
    require(memoryEqual(packet->bytes, before.bytes, sizeof(packet->bytes)),
            "rejected checksum packet was modified");
}

static void testRejectsTruncatedIpv4Headers(void)
{
    require(! calcFullPacketChecksum(NULL, 0), "NULL checksum packet was accepted");

    for (size_t available_len = 0; available_len < IP_HLEN; ++available_len)
    {
        test_packet_t packet;
        initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
        requireRejectedUnchanged(&packet, available_len, "truncated IPv4 header was accepted");
    }
}

static void testRejectsMalformedIpv4Lengths(void)
{
    test_packet_t packet;

    initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 6, IP_HLEN / 4U);
    requireRejectedUnchanged(&packet, IP_HLEN, "non-IPv4 packet was accepted");

    initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 4, (IP_HLEN / 4U) - 1U);
    requireRejectedUnchanged(&packet, IP_HLEN, "short IPv4 IHL was accepted");

    initializeIpv4Packet(&packet, IP_HLEN_MAX, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 4, IP_HLEN_MAX / 4U);
    requireRejectedUnchanged(&packet, IP_HLEN, "IPv4 IHL beyond available bytes was accepted");

    initializeIpv4Packet(&packet, IP_HLEN - 1U, IP_PROTO_TCP);
    requireRejectedUnchanged(&packet, IP_HLEN, "IPv4 total length below IHL was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    requireRejectedUnchanged(&packet, IP_HLEN, "IPv4 total length beyond available bytes was accepted");
}

static void testRejectsMalformedTransportLengths(void)
{
    test_packet_t   packet;
    struct tcp_hdr *tcpheader;
    struct udp_hdr *udpheader;

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN - 1U, IP_PROTO_TCP);
    requireRejectedUnchanged(&packet, IP_HLEN + TCP_HLEN - 1U, "truncated TCP header was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    tcpheader = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, (TCP_HLEN / 4U) - 1U, TCP_ACK);
    requireRejectedUnchanged(&packet, IP_HLEN + TCP_HLEN, "short TCP data offset was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    tcpheader = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, 15U, TCP_ACK);
    requireRejectedUnchanged(&packet, IP_HLEN + TCP_HLEN, "TCP data offset beyond packet was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN - 1U, IP_PROTO_UDP);
    requireRejectedUnchanged(&packet, IP_HLEN + UDP_HLEN - 1U, "truncated UDP header was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN, IP_PROTO_UDP);
    udpheader      = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udpheader->len = lwip_htons(UDP_HLEN + 1U);
    requireRejectedUnchanged(&packet, IP_HLEN + UDP_HLEN, "UDP length beyond packet was accepted");

    initializeIpv4Packet(&packet, IP_HLEN + sizeof(struct icmp_hdr) - 1U, IP_PROTO_ICMP);
    requireRejectedUnchanged(&packet, IP_HLEN + sizeof(struct icmp_hdr) - 1U,
                             "truncated ICMP header was accepted");
}

static void testCalculatesValidChecksums(void)
{
    test_packet_t       packet;
    struct ip_hdr      *ipheader;
    struct tcp_hdr     *tcpheader;
    struct udp_hdr     *udpheader;
    struct icmp_echo_hdr *icmpheader;
    uint16_t            tcp_checksum;

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    ipheader                  = (struct ip_hdr *) packet.bytes;
    tcpheader                 = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcpheader->src             = lwip_htons(12345);
    tcpheader->dest            = lwip_htons(443);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, TCP_HLEN / 4U, TCP_ACK);

    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN), "valid TCP packet was rejected");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 checksum was generated for TCP packet");
    tcp_checksum = tcpheader->chksum;
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN), "valid TCP packet failed second checksum");
    require(tcpheader->chksum == tcp_checksum, "TCP checksum recalculation was not deterministic");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN, IP_PROTO_UDP);
    ipheader       = (struct ip_hdr *) packet.bytes;
    udpheader      = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udpheader->src  = lwip_htons(5353);
    udpheader->dest = lwip_htons(53);
    udpheader->len  = lwip_htons(UDP_HLEN);

    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN), "valid UDP packet was rejected");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 checksum was generated for UDP packet");
    require(udpheader->chksum != 0, "zero UDP checksum was emitted");

    initializeIpv4Packet(&packet, IP_HLEN + sizeof(struct icmp_echo_hdr), IP_PROTO_ICMP);
    ipheader   = (struct ip_hdr *) packet.bytes;
    icmpheader = (struct icmp_echo_hdr *) (packet.bytes + IP_HLEN);
    ICMPH_TYPE_SET(icmpheader, ICMP_ECHO);
    icmpheader->id    = lwip_htons(1);
    icmpheader->seqno = lwip_htons(2);

    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + sizeof(struct icmp_echo_hdr)),
            "valid ICMP packet was rejected");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 checksum was generated for ICMP packet");
    require(inet_chksum(icmpheader, sizeof(*icmpheader)) == 0, "invalid ICMP checksum was generated");
}

static void testFragmentOnlyUpdatesIpv4Checksum(void)
{
    test_packet_t packet;
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN, IP_PROTO_UDP);

    struct ip_hdr *ipheader = (struct ip_hdr *) packet.bytes;
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    memorySet(packet.bytes + IP_HLEN, 0xA5, UDP_HLEN);

    uint8_t transport_before[UDP_HLEN];
    memoryCopy(transport_before, packet.bytes + IP_HLEN, sizeof(transport_before));

    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN), "valid IPv4 fragment was rejected");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 checksum was generated for fragment");
    require(memoryEqual(packet.bytes + IP_HLEN, transport_before, sizeof(transport_before)),
            "fragment transport bytes were modified");
}

int main(void)
{
    checkSumInit();
    testRejectsTruncatedIpv4Headers();
    testRejectsMalformedIpv4Lengths();
    testRejectsMalformedTransportLengths();
    testCalculatesValidChecksums();
    testFragmentOnlyUpdatesIpv4Checksum();
    return 0;
}

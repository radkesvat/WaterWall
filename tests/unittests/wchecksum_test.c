#include "wchecksum.h"
#include "wlibc.h"
#include "wwapi.h"

enum
{
    kTestPacketCapacity = 512
};

typedef union test_packet_u {
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
    require(memoryEqual(packet->bytes, before.bytes, sizeof(packet->bytes)), "rejected checksum packet was modified");
}

static void requireHeaderChecksumRejectedUnchanged(test_packet_t *packet, size_t available_len, const char *message)
{
    test_packet_t before = *packet;

    require(! calcIpv4HeaderChecksum(packet->bytes, available_len), message);
    require(memoryEqual(packet->bytes, before.bytes, sizeof(packet->bytes)),
            "rejected header-only checksum packet was modified");
}

static void requireAddressUpdateRejectedUnchanged(test_packet_t *packet, size_t available_len,
                                                  ipv4_checksum_address_field_e field, uint32_t new_addr,
                                                  const char *message)
{
    test_packet_t before = *packet;

    require(! setIpv4AddressWithChecksumUpdate(packet->bytes, available_len, field, new_addr), message);
    require(memoryEqual(packet->bytes, before.bytes, sizeof(packet->bytes)),
            "rejected address-update packet was modified");
}

static void requireTransport16UpdateRejectedUnchanged(test_packet_t *packet, size_t available_len, uint16_t old_word,
                                                      uint16_t new_word, const char *message)
{
    test_packet_t before = *packet;

    require(! updateIpv4TransportChecksum16(packet->bytes, available_len, old_word, new_word), message);
    require(memoryEqual(packet->bytes, before.bytes, sizeof(packet->bytes)),
            "rejected transport16-update packet was modified");
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
    requireRejectedUnchanged(&packet, IP_HLEN + sizeof(struct icmp_hdr) - 1U, "truncated ICMP header was accepted");
}

static void testCalculatesValidChecksums(void)
{
    test_packet_t         packet;
    struct ip_hdr        *ipheader;
    struct tcp_hdr       *tcpheader;
    struct udp_hdr       *udpheader;
    struct icmp_echo_hdr *icmpheader;
    uint16_t              tcp_checksum;

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    ipheader        = (struct ip_hdr *) packet.bytes;
    tcpheader       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcpheader->src  = lwip_htons(12345);
    tcpheader->dest = lwip_htons(443);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, TCP_HLEN / 4U, TCP_ACK);

    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN), "valid TCP packet was rejected");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 checksum was generated for TCP packet");
    tcp_checksum = tcpheader->chksum;
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN), "valid TCP packet failed second checksum");
    require(tcpheader->chksum == tcp_checksum, "TCP checksum recalculation was not deterministic");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN, IP_PROTO_UDP);
    ipheader        = (struct ip_hdr *) packet.bytes;
    udpheader       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
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

static void testIpv4HeaderOnlyRecalculation(void)
{
    test_packet_t  packet;
    struct ip_hdr *ipheader;

    /* 1. Normal IPv4 header */
    initializeIpv4Packet(&packet, IP_HLEN + 20, IP_PROTO_TCP);
    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_CHKSUM_SET(ipheader, 0x1234);
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + 20), "valid IPv4 header-only recalculation failed");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid IPv4 header checksum calculated");

    /* 2. Header with options (IHL = 8, 32 bytes) */
    initializeIpv4Packet(&packet, 32 + 20, IP_PROTO_TCP);
    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_VHL_SET(ipheader, 4, 8);
    IPH_LEN_SET(ipheader, lwip_htons(52));
    IPH_CHKSUM_SET(ipheader, 0xABCD);
    require(calcIpv4HeaderChecksum(packet.bytes, 52), "IPv4 header with options failed");
    require(inet_chksum(ipheader, 32) == 0, "invalid IPv4 header with options checksum calculated");

    /* 3. Fragmented IPv4 packet */
    initializeIpv4Packet(&packet, IP_HLEN + 20, IP_PROTO_UDP);
    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF | 10));
    IPH_CHKSUM_SET(ipheader, 0x5555);
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + 20), "fragmented IPv4 header-only recalculation failed");
    require(inet_chksum(ipheader, IP_HLEN) == 0, "invalid fragmented IPv4 header checksum");

    /* Rejections - byte-for-byte equality */
    require(! calcIpv4HeaderChecksum(NULL, IP_HLEN), "NULL buffer accepted");

    for (size_t avail = 0; avail < IP_HLEN; ++avail)
    {
        initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
        requireHeaderChecksumRejectedUnchanged(&packet, avail, "truncated base header accepted");
    }

    initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 4, 4);
    requireHeaderChecksumRejectedUnchanged(&packet, IP_HLEN, "IHL < 5 accepted");

    initializeIpv4Packet(&packet, 32, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 4, 8);
    IPH_LEN_SET((struct ip_hdr *) packet.bytes, lwip_htons(32));
    requireHeaderChecksumRejectedUnchanged(&packet, 24, "IHL > available_len accepted");

    initializeIpv4Packet(&packet, 15, IP_PROTO_TCP);
    IPH_LEN_SET((struct ip_hdr *) packet.bytes, lwip_htons(15));
    requireHeaderChecksumRejectedUnchanged(&packet, IP_HLEN, "total_len < IHL accepted");

    initializeIpv4Packet(&packet, 40, IP_PROTO_TCP);
    IPH_LEN_SET((struct ip_hdr *) packet.bytes, lwip_htons(40));
    requireHeaderChecksumRejectedUnchanged(&packet, 30, "total_len > available_len accepted");

    initializeIpv4Packet(&packet, IP_HLEN, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 6, 5);
    requireHeaderChecksumRejectedUnchanged(&packet, IP_HLEN, "IPv6 packet accepted for header checksum");
}

static void testTcpAddressReplacement(void)
{
    test_packet_t   packet;
    test_packet_t   oracle;
    struct tcp_hdr *tcph;
    uint32_t        new_src  = lwip_htonl(0x0A000001U);
    uint32_t        new_dest = lwip_htonl(0x0A000002U);

    /* Setup base TCP packet with payload */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN + 20, IP_PROTO_TCP);
    tcph       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->src  = lwip_htons(12345);
    tcph->dest = lwip_htons(80);
    TCPH_HDRLEN_FLAGS_SET(tcph, TCP_HLEN / 4U, TCP_ACK);
    for (int i = 0; i < 20; ++i)
    {
        packet.bytes[IP_HLEN + TCP_HLEN + i] = (uint8_t) (i + 1);
    }
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 20), "TCP base checksum failed");

    /* 1. Replace Source Address */
    oracle = packet;
    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + TCP_HLEN + 20, kIpv4ChecksumAddressSource, new_src),
        "set source address failed");
    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 20), "oracle calc failed TCP src");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 20),
            "source address replacement mismatch with oracle");

    /* 2. Replace Destination Address */
    oracle = packet;
    require(setIpv4AddressWithChecksumUpdate(
                packet.bytes, IP_HLEN + TCP_HLEN + 20, kIpv4ChecksumAddressDestination, new_dest),
            "set dest address failed");
    ((struct ip_hdr *) oracle.bytes)->dest.addr = new_dest;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 20), "oracle calc failed TCP dst");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 20),
            "dest address replacement mismatch with oracle");

    /* 3. Unchanged address returns true without modification */
    test_packet_t before = packet;
    require(setIpv4AddressWithChecksumUpdate(
                packet.bytes, IP_HLEN + TCP_HLEN + 20, kIpv4ChecksumAddressDestination, new_dest),
            "unchanged address returned false");
    require(memoryEqual(packet.bytes, before.bytes, IP_HLEN + TCP_HLEN + 20), "unchanged address modified packet");
}

static void testUdpAddressReplacement(void)
{
    test_packet_t   packet;
    test_packet_t   oracle;
    struct udp_hdr *udph;
    uint32_t        new_src  = lwip_htonl(0x0A010101U);
    uint32_t        new_dest = lwip_htonl(0x0A010102U);

    /* 1. Even-length UDP payload */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 10, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src  = lwip_htons(5000);
    udph->dest = lwip_htons(5001);
    udph->len  = lwip_htons(UDP_HLEN + 10);
    for (int i = 0; i < 10; ++i)
    {
        packet.bytes[IP_HLEN + UDP_HLEN + i] = (uint8_t) (i + 10);
    }
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 10), "even UDP checksum failed");

    oracle = packet;
    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + UDP_HLEN + 10, kIpv4ChecksumAddressSource, new_src),
        "even UDP source update failed");
    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + UDP_HLEN + 10), "oracle calc failed even UDP");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + UDP_HLEN + 10), "even UDP src mismatch");

    /* 2. Odd-length UDP payload */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 11, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src  = lwip_htons(5000);
    udph->dest = lwip_htons(5001);
    udph->len  = lwip_htons(UDP_HLEN + 11);
    for (int i = 0; i < 11; ++i)
    {
        packet.bytes[IP_HLEN + UDP_HLEN + i] = (uint8_t) (i + 5);
    }
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 11), "odd UDP checksum failed");

    oracle = packet;
    require(setIpv4AddressWithChecksumUpdate(
                packet.bytes, IP_HLEN + UDP_HLEN + 11, kIpv4ChecksumAddressDestination, new_dest),
            "odd UDP dest update failed");
    ((struct ip_hdr *) oracle.bytes)->dest.addr = new_dest;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + UDP_HLEN + 11), "oracle calc failed odd UDP");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + UDP_HLEN + 11), "odd UDP dest mismatch");

    /* 3. Zero UDP checksum stays zero */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 10, IP_PROTO_UDP);
    udph         = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src    = lwip_htons(5000);
    udph->dest   = lwip_htons(5001);
    udph->len    = lwip_htons(UDP_HLEN + 10);
    udph->chksum = 0;
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 10), "IP header calc failed");

    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + UDP_HLEN + 10, kIpv4ChecksumAddressSource, new_src),
        "zero UDP chksum address update failed");
    require(udph->chksum == 0, "zero UDP checksum was modified to non-zero");

    /* 4. Enabled UDP checksum whose update yields 0 -> stored as 0xFFFF */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 4, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src  = lwip_htons(1000);
    udph->dest = lwip_htons(2000);
    udph->len  = lwip_htons(UDP_HLEN + 4);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 4), "base UDP checksum failed");

    uint32_t target_src = 0;
    uint32_t old_src    = ((struct ip_hdr *) packet.bytes)->src.addr;
    for (uint32_t candidate = 1; candidate < 0x00FFFF00U; candidate += 0x100U)
    {
        uint32_t cand_net = lwip_htonl(candidate);
        if (cand_net == old_src)
        {
            continue;
        }
        test_packet_t tmp = packet;
        if (setIpv4AddressWithChecksumUpdate(tmp.bytes, IP_HLEN + UDP_HLEN + 4, kIpv4ChecksumAddressSource, cand_net))
        {
            struct udp_hdr *tmp_u = (struct udp_hdr *) (tmp.bytes + IP_HLEN);
            if (tmp_u->chksum == 0xFFFF)
            {
                target_src = cand_net;
                break;
            }
        }
    }
    require(target_src != 0, "failed to find candidate address yielding 0xFFFF UDP checksum");

    oracle = packet;
    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + UDP_HLEN + 4, kIpv4ChecksumAddressSource, target_src),
        "target address update failed");
    udph = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    require(udph->chksum == 0xFFFF, "mathematical zero UDP checksum was not stored as 0xFFFF");

    ((struct ip_hdr *) oracle.bytes)->src.addr = target_src;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + UDP_HLEN + 4), "oracle calc failed zero UDP");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + UDP_HLEN + 4),
            "0xFFFF UDP checksum mismatch with oracle");
}

static void testIcmpAndUnknownProtocols(void)
{
    test_packet_t         packet;
    test_packet_t         oracle;
    struct icmp_echo_hdr *icmph;
    uint32_t              new_src = lwip_htonl(0x0A0A0A0AU);

    /* 1. ICMP */
    initializeIpv4Packet(&packet, IP_HLEN + sizeof(struct icmp_echo_hdr) + 8, IP_PROTO_ICMP);
    icmph = (struct icmp_echo_hdr *) (packet.bytes + IP_HLEN);
    ICMPH_TYPE_SET(icmph, ICMP_ECHO);
    icmph->id    = lwip_htons(10);
    icmph->seqno = lwip_htons(20);
    for (int i = 0; i < 8; ++i)
    {
        packet.bytes[IP_HLEN + sizeof(struct icmp_echo_hdr) + i] = (uint8_t) (i + 1);
    }
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + sizeof(struct icmp_echo_hdr) + 8),
            "ICMP full checksum failed");

    uint16_t original_icmp_chksum = icmph->chksum;
    oracle                        = packet;

    require(setIpv4AddressWithChecksumUpdate(
                packet.bytes, IP_HLEN + sizeof(struct icmp_echo_hdr) + 8, kIpv4ChecksumAddressSource, new_src),
            "ICMP address update failed");
    icmph = (struct icmp_echo_hdr *) (packet.bytes + IP_HLEN);
    require(icmph->chksum == original_icmp_chksum, "ICMP checksum was modified by address change");

    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcIpv4HeaderChecksum(oracle.bytes, IP_HLEN + sizeof(struct icmp_echo_hdr) + 8),
            "oracle header calc failed");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + sizeof(struct icmp_echo_hdr) + 8),
            "ICMP address update mismatch with oracle");

    /* 2. Unknown protocol (99) */
    initializeIpv4Packet(&packet, IP_HLEN + 16, 99);
    for (int i = 0; i < 16; ++i)
    {
        packet.bytes[IP_HLEN + i] = (uint8_t) (i + 100);
    }
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + 16), "unknown proto header calc failed");
    oracle = packet;

    require(setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + 16, kIpv4ChecksumAddressSource, new_src),
            "unknown proto address update failed");
    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcIpv4HeaderChecksum(oracle.bytes, IP_HLEN + 16), "oracle header calc failed");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + 16), "unknown proto address update mismatch with oracle");
}

static void testFragmentedAddressReplacement(void)
{
    test_packet_t   packet;
    test_packet_t   oracle;
    struct ip_hdr  *ipheader;
    struct tcp_hdr *tcph;
    struct udp_hdr *udph;
    uint32_t        new_src = lwip_htonl(0x0A020202U);

    /* 1. First TCP fragment with MF (frag_offset = 0, IP_MF set) */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN + 16, IP_PROTO_TCP);
    tcph       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->src  = lwip_htons(1111);
    tcph->dest = lwip_htons(2222);
    TCPH_HDRLEN_FLAGS_SET(tcph, TCP_HLEN / 4U, TCP_SYN);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 16), "TCP checksum failed");

    oracle                                     = packet;
    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle calc failed frag TCP");
    IPH_OFFSET_SET((struct ip_hdr *) oracle.bytes, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle IP chksum failed");

    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 16), "packet IP chksum failed");

    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + TCP_HLEN + 16, kIpv4ChecksumAddressSource, new_src),
        "first TCP fragment address update failed");

    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 16),
            "first TCP fragment mismatch with oracle");

    /* 2. First UDP fragment with MF whose udph->len exceeds fragment size */
    test_packet_t full_datagram;
    initializeIpv4Packet(&full_datagram, IP_HLEN + 480, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (full_datagram.bytes + IP_HLEN);
    udph->src  = lwip_htons(3333);
    udph->dest = lwip_htons(4444);
    udph->len  = lwip_htons(480);
    for (int i = 0; i < 472; ++i)
    {
        full_datagram.bytes[IP_HLEN + UDP_HLEN + i] = (uint8_t) (i + 1);
    }
    require(calcFullPacketChecksum(full_datagram.bytes, IP_HLEN + 480), "full UDP datagram checksum failed");

    test_packet_t full_oracle                       = full_datagram;
    ((struct ip_hdr *) full_oracle.bytes)->src.addr = new_src;
    require(calcFullPacketChecksum(full_oracle.bytes, IP_HLEN + 480), "full oracle UDP checksum failed");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 20, IP_PROTO_UDP);
    memoryCopy(packet.bytes, full_datagram.bytes, IP_HLEN + UDP_HLEN + 20);
    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_LEN_SET(ipheader, lwip_htons(IP_HLEN + UDP_HLEN + 20));
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 20), "fragment IP chksum failed");

    initializeIpv4Packet(&oracle, IP_HLEN + UDP_HLEN + 20, IP_PROTO_UDP);
    memoryCopy(oracle.bytes, full_oracle.bytes, IP_HLEN + UDP_HLEN + 20);
    ipheader = (struct ip_hdr *) oracle.bytes;
    IPH_LEN_SET(ipheader, lwip_htons(IP_HLEN + UDP_HLEN + 20));
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(oracle.bytes, IP_HLEN + UDP_HLEN + 20), "oracle fragment IP chksum failed");

    require(
        setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + UDP_HLEN + 20, kIpv4ChecksumAddressSource, new_src),
        "first UDP fragment address update failed");

    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + UDP_HLEN + 20),
            "first UDP fragment mismatch with oracle");

    /* 3. Non-first fragment (frag_offset > 0) -> only IP header updated */
    initializeIpv4Packet(&packet, IP_HLEN + 30, IP_PROTO_TCP);
    ipheader = (struct ip_hdr *) packet.bytes;
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF | 5));
    for (int i = 0; i < 30; ++i)
    {
        packet.bytes[IP_HLEN + i] = (uint8_t) (i + 50);
    }
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + 30), "non-first frag base calc failed");
    oracle = packet;

    require(setIpv4AddressWithChecksumUpdate(packet.bytes, IP_HLEN + 30, kIpv4ChecksumAddressSource, new_src),
            "non-first frag address update failed");

    require(memoryEqual(packet.bytes + IP_HLEN, oracle.bytes + IP_HLEN, 30),
            "non-first fragment payload bytes were modified");
    ((struct ip_hdr *) oracle.bytes)->src.addr = new_src;
    require(calcIpv4HeaderChecksum(oracle.bytes, IP_HLEN + 30), "oracle IP calc failed");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + 30), "non-first fragment mismatch with oracle");

    /* 4. Truncated first TCP fragment (transport_len < TCP_HLEN) -> rejected unchanged */
    initializeIpv4Packet(&packet, IP_HLEN + 10, IP_PROTO_TCP);
    requireAddressUpdateRejectedUnchanged(
        &packet, IP_HLEN + 10, kIpv4ChecksumAddressSource, new_src, "truncated first TCP fragment was accepted");

    /* 5. First UDP fragment with udp_len < UDP_HLEN -> rejected unchanged */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 20, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src  = lwip_htons(3333);
    udph->dest = lwip_htons(4444);
    udph->len  = lwip_htons(4);
    ipheader   = (struct ip_hdr *) packet.bytes;
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 20), "invalid udp len IP calc failed");

    requireAddressUpdateRejectedUnchanged(&packet,
                                          IP_HLEN + UDP_HLEN + 20,
                                          kIpv4ChecksumAddressSource,
                                          new_src,
                                          "first UDP fragment with short udp_len accepted");
}

static void testTransport16BitReplacement(void)
{
    test_packet_t   packet;
    test_packet_t   oracle;
    struct tcp_hdr *tcph;
    struct udp_hdr *udph;

    /* 1. TCP flags replacement */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN + 16, IP_PROTO_TCP);
    tcph       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->src  = lwip_htons(1234);
    tcph->dest = lwip_htons(80);
    TCPH_HDRLEN_FLAGS_SET(tcph, TCP_HLEN / 4U, TCP_ACK);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 16), "TCP base chksum failed");

    uint16_t       old_flags = tcph->_hdrlen_rsvd_flags;
    struct tcp_hdr dummy_tcph;
    TCPH_HDRLEN_FLAGS_SET(&dummy_tcph, TCP_HLEN / 4U, TCP_ACK | TCP_ECE | TCP_CWR);
    uint16_t new_flags = dummy_tcph._hdrlen_rsvd_flags;

    oracle = packet;
    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, old_flags, new_flags),
            "TCP transport16 update failed");
    tcph->_hdrlen_rsvd_flags = new_flags;

    tcph                     = (struct tcp_hdr *) (oracle.bytes + IP_HLEN);
    tcph->_hdrlen_rsvd_flags = new_flags;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle calc failed transport16 TCP");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 16),
            "TCP transport16 update mismatch with oracle");

    /* 2. TCP no-op replacement (old == new) */
    test_packet_t before = packet;
    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, new_flags, new_flags),
            "no-op transport16 update returned false");
    require(memoryEqual(packet.bytes, before.bytes, IP_HLEN + TCP_HLEN + 16), "no-op update modified packet");

    /* 3. UDP port replacement */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 12, IP_PROTO_UDP);
    udph       = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src  = lwip_htons(5000);
    udph->dest = lwip_htons(53);
    udph->len  = lwip_htons(UDP_HLEN + 12);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 12), "UDP base chksum failed");

    uint16_t old_port = udph->dest;
    uint16_t new_port = lwip_htons(8080);
    oracle            = packet;

    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + UDP_HLEN + 12, old_port, new_port),
            "UDP transport16 update failed");
    udph->dest = new_port;

    udph       = (struct udp_hdr *) (oracle.bytes + IP_HLEN);
    udph->dest = new_port;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + UDP_HLEN + 12), "oracle calc failed transport16 UDP");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + UDP_HLEN + 12),
            "UDP transport16 update mismatch with oracle");

    /* 4. UDP zero checksum stays zero */
    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN + 12, IP_PROTO_UDP);
    udph         = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->src    = lwip_htons(5000);
    udph->dest   = lwip_htons(53);
    udph->len    = lwip_htons(UDP_HLEN + 12);
    udph->chksum = 0;
    require(calcIpv4HeaderChecksum(packet.bytes, IP_HLEN + UDP_HLEN + 12), "IP calc failed");

    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + UDP_HLEN + 12, old_port, new_port),
            "zero UDP transport16 update failed");
    require(udph->chksum == 0, "zero UDP checksum was modified");

    /* Rejections - byte-for-byte unchanged */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    IPH_VHL_SET((struct ip_hdr *) packet.bytes, 6, 5);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + TCP_HLEN, old_flags, new_flags, "IPv6 accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + sizeof(struct icmp_hdr), IP_PROTO_ICMP);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + sizeof(struct icmp_hdr), old_flags, new_flags, "ICMP accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + 10, 99);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + 10, old_flags, new_flags, "unknown proto accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    tcph = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    TCPH_HDRLEN_FLAGS_SET(tcph, 4, TCP_ACK);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + TCP_HLEN, old_flags, new_flags, "malformed TCP offset accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + UDP_HLEN, IP_PROTO_UDP);
    udph      = (struct udp_hdr *) (packet.bytes + IP_HLEN);
    udph->len = lwip_htons(UDP_HLEN + 10);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + UDP_HLEN, old_port, new_port, "malformed UDP len accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    IPH_OFFSET_SET((struct ip_hdr *) packet.bytes, lwip_htons(5));
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + TCP_HLEN, old_flags, new_flags, "non-first fragment accepted for transport16");

    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN, IP_PROTO_TCP);
    requireTransport16UpdateRejectedUnchanged(
        &packet, IP_HLEN + TCP_HLEN - 1, old_flags, new_flags, "insufficient available_len accepted for transport16");
}

static void testArithmeticEdgeCoverage(void)
{
    test_packet_t   packet;
    test_packet_t   oracle;
    struct tcp_hdr *tcph;

    /* 1. Word updates with 0x0000 and 0xFFFF */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN + 16, IP_PROTO_TCP);
    tcph       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->src  = lwip_htons(0x0000);
    tcph->dest = lwip_htons(0xFFFF);
    TCPH_HDRLEN_FLAGS_SET(tcph, TCP_HLEN / 4U, TCP_ACK);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 16), "TCP base chksum failed");

    oracle = packet;
    require(
        updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, lwip_htons(0x0000), lwip_htons(0x1234)),
        "0x0000 to 0x1234 update failed");
    tcph->src = lwip_htons(0x1234);

    tcph      = (struct tcp_hdr *) (oracle.bytes + IP_HLEN);
    tcph->src = lwip_htons(0x1234);
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle calc failed edge 1");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 16), "0x0000 update mismatch");

    oracle = packet;
    require(
        updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, lwip_htons(0xFFFF), lwip_htons(0x4321)),
        "0xFFFF to 0x4321 update failed");
    tcph       = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->dest = lwip_htons(0x4321);

    tcph       = (struct tcp_hdr *) (oracle.bytes + IP_HLEN);
    tcph->dest = lwip_htons(0x4321);
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle calc failed edge 2");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 16), "0xFFFF update mismatch");

    /* 2. Consecutive incremental changes equal single full recalculation */
    initializeIpv4Packet(&packet, IP_HLEN + TCP_HLEN + 16, IP_PROTO_TCP);
    tcph        = (struct tcp_hdr *) (packet.bytes + IP_HLEN);
    tcph->src   = lwip_htons(100);
    tcph->dest  = lwip_htons(200);
    tcph->seqno = lwip_htonl(0x11223344U);
    tcph->ackno = lwip_htonl(0x55667788U);
    TCPH_HDRLEN_FLAGS_SET(tcph, TCP_HLEN / 4U, TCP_ACK);
    require(calcFullPacketChecksum(packet.bytes, IP_HLEN + TCP_HLEN + 16), "base checksum failed");

    uint16_t old_src    = tcph->src;
    uint16_t new_src    = lwip_htons(500);
    uint16_t old_dest   = tcph->dest;
    uint16_t new_dest   = lwip_htons(600);
    uint16_t old_seq1   = (uint16_t) ((lwip_ntohl(tcph->seqno) >> 16) & 0xFFFFU);
    uint16_t new_seq1   = lwip_htons(0x99AA);
    uint16_t old_seq1_n = lwip_htons(old_seq1);

    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, old_src, new_src), "step 1 failed");
    tcph->src = new_src;

    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, old_dest, new_dest), "step 2 failed");
    tcph->dest = new_dest;

    require(updateIpv4TransportChecksum16(packet.bytes, IP_HLEN + TCP_HLEN + 16, old_seq1_n, new_seq1),
            "step 3 failed");
    tcph->seqno = lwip_htonl(0x99AA3344U);

    oracle = packet;
    require(calcFullPacketChecksum(oracle.bytes, IP_HLEN + TCP_HLEN + 16), "oracle calc failed edge 3");
    require(memoryEqual(packet.bytes, oracle.bytes, IP_HLEN + TCP_HLEN + 16),
            "consecutive incremental updates mismatch with oracle");
}

int main(void)
{
    checkSumInit();
    testRejectsTruncatedIpv4Headers();
    testRejectsMalformedIpv4Lengths();
    testRejectsMalformedTransportLengths();
    testCalculatesValidChecksums();
    testFragmentOnlyUpdatesIpv4Checksum();
    testIpv4HeaderOnlyRecalculation();
    testTcpAddressReplacement();
    testUdpAddressReplacement();
    testIcmpAndUnknownProtocols();
    testFragmentedAddressReplacement();
    testTransport16BitReplacement();
    testArithmeticEdgeCoverage();
    return 0;
}

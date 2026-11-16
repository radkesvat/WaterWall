/*
 * Covers: Ping6 wire; independent ICMPv6 pseudo-header checksum vectors, exact packet geometry,
 * request/reply behavior, parser rejection, checksum repair, and unaligned packet input.
 * CTest: waterwall.ping6_wire_unit
 */
#include "PingCommon/ping6_wire.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

enum
{
    kTestInnerProtocol = 253,
    kTestIdentifier    = 0x1234,
};

static uint32_t ipv4Address(const char *text)
{
    ip4_addr_t address = {0};
    require(ip4AddrAddressToNetwork(text, &address) != 0, "test IPv4 parsing failed");
    return ip4AddrGetU32(&address);
}

static ip6_addr_t ipv6Address(const char *text)
{
    ip6_addr_t address = {0};
    require(ip6addr_aton(text, &address) != 0, "test IPv6 parsing failed");
    return address;
}

static ping6_wire_config_t clientConfig(void)
{
    ping6_wire_config_t config = {
        .local_ipv4 = ipv4Address("192.0.2.10"),
        .peer_ipv4  = ipv4Address("198.51.100.10"),
        .local_ipv6 = ipv6Address("2001:db8::10"),
        .peer_ipv6  = ipv6Address("2001:db8::20"),
        .identifier = kTestIdentifier,
        .ttl        = 61,
        .tos        = 11,
    };
    return config;
}

static ping6_wire_config_t serverConfig(const ping6_wire_config_t *client)
{
    ping6_wire_config_t config = {
        .local_ipv4 = client->peer_ipv4,
        .peer_ipv4  = client->local_ipv4,
        .local_ipv6 = client->peer_ipv6,
        .peer_ipv6  = client->local_ipv6,
        .identifier = 0x9999,
        .ttl        = 47,
        .tos        = 0,
    };
    return config;
}

static uint32_t independentSum(const uint8_t *data, size_t length, uint32_t sum)
{
    while (length >= 2)
    {
        sum += ((uint32_t) data[0] << 8U) | data[1];
        data += 2;
        length -= 2;
    }
    if (length != 0)
    {
        sum += (uint32_t) data[0] << 8U;
    }
    return sum;
}

static uint32_t independentPseudoSum(const uint8_t *message, uint32_t length, const ip6_addr_t *source,
                                     const ip6_addr_t *destination)
{
    uint32_t sum = independentSum((const uint8_t *) source->addr, sizeof(source->addr), 0);
    sum          = independentSum((const uint8_t *) destination->addr, sizeof(destination->addr), sum);
    sum += (length >> 16U) & UINT16_MAX;
    sum += length & UINT16_MAX;
    sum += kPing6WireProtocol;
    return independentSum(message, length, sum);
}

static uint16_t independentFold(uint32_t sum)
{
    while (sum >> 16U)
    {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }
    return (uint16_t) sum;
}

static uint16_t independentChecksum(const uint8_t *message, uint32_t length, const ip6_addr_t *source,
                                    const ip6_addr_t *destination)
{
    return (uint16_t) ~independentFold(independentPseudoSum(message, length, source, destination));
}

static void requireValidCarrier(const sbuf_t *buf, const ping6_wire_config_t *config)
{
    const uint8_t       *packet = sbufGetRawPtr(buf);
    const struct ip_hdr *ip     = (const struct ip_hdr *) packet;
    const uint16_t       hlen   = IPH_HL_BYTES(ip);
    const uint16_t       total  = lwip_ntohs(IPH_LEN(ip));

    require(total == sbufGetLength(buf), "outer total length does not equal buffer length");
    require(IPH_PROTO(ip) == kPing6WireProtocol, "outer Protocol is not 58");
    require(inet_chksum(packet, hlen) == 0, "outer IPv4 checksum is invalid");
    require(independentFold(independentPseudoSum(
                packet + hlen, total - hlen, &config->local_ipv6, &config->peer_ipv6)) == UINT16_MAX,
            "ICMPv6 pseudo-header checksum is invalid");
}

static void repairCarrierIndependently(sbuf_t *buf, const ping6_wire_config_t *config)
{
    uint8_t               *packet = sbufGetMutablePtr(buf);
    struct ip_hdr         *ip     = (struct ip_hdr *) packet;
    const uint16_t         length = (uint16_t) sbufGetLength(buf);
    const uint16_t         hlen   = IPH_HL_BYTES(ip);
    struct icmp6_echo_hdr *icmp   = (struct icmp6_echo_hdr *) (packet + hlen);
    icmp->chksum                  = 0;
    icmp->chksum =
        lwip_htons(independentChecksum((const uint8_t *) icmp, length - hlen, &config->local_ipv6, &config->peer_ipv6));
    require(calcIpv4HeaderChecksum(packet, length), "independent outer checksum repair failed");
}

static sbuf_t *makeInnerPacket(uint16_t length, uint16_t offset)
{
    require(length >= IP_HLEN, "test inner packet is too short");
    sbuf_t *buf = sbufCreateWithPadding(length, kPing6WireEncapsulationOverhead);
    sbufSetLength(buf, length);
    memoryZero(sbufGetMutablePtr(buf), length);

    struct ip_hdr *ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ip, 4, IP_HLEN / 4U);
    IPH_TOS_SET(ip, 7);
    IPH_LEN_SET(ip, lwip_htons(length));
    IPH_ID_SET(ip, lwip_htons(0x8877));
    IPH_OFFSET_SET(ip, offset);
    IPH_TTL_SET(ip, 55);
    IPH_PROTO_SET(ip, kTestInnerProtocol);
    ip->src.addr  = ipv4Address("10.10.0.1");
    ip->dest.addr = ipv4Address("10.10.0.2");
    for (uint16_t i = IP_HLEN; i < length; ++i)
    {
        sbufGetMutablePtr(buf)[i] = (uint8_t) (i * 13U + 9U);
    }
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), length), "test inner checksum failed");
    return buf;
}

static struct icmp6_echo_hdr *icmp6Header(sbuf_t *buf)
{
    return (struct icmp6_echo_hdr *) (sbufGetMutablePtr(buf) + kPing6WireIpv4HeaderLength);
}

static void testRequestReplyAndIndependentChecksums(void)
{
    const ping6_wire_config_t client      = clientConfig();
    const ping6_wire_config_t server      = serverConfig(&client);
    const uint16_t            lengths[]   = {96, 95, 72};
    const uint16_t            sequences[] = {1, UINT16_MAX, 0};

    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        const uint16_t inner_length = lengths[i];
        sbuf_t        *request      = makeInnerPacket(inner_length, 0);
        uint8_t        original[96];
        memoryCopy(original, sbufGetRawPtr(request), inner_length);

        require(ping6wireEchoRequestPreflight(request), "preflight rejected valid Ping6 input");
        require(ping6wireBuildEchoRequest(request, &client, sequences[i]), "Ping6 request build failed");
        require(sbufGetLength(request) == (size_t) inner_length + kPing6WireEncapsulationOverhead,
                "Ping6 request length is wrong");
        requireValidCarrier(request, &client);

        const struct ip_hdr   *outer = (const struct ip_hdr *) sbufGetRawPtr(request);
        struct icmp6_echo_hdr *icmp  = icmp6Header(request);
        require(icmp->type == kPing6WireEchoRequest && icmp->code == 0, "request type/code is wrong");
        require(lwip_ntohs(icmp->id) == client.identifier && lwip_ntohs(icmp->seqno) == sequences[i],
                "request identifier/sequence is wrong");
        require(IPH_TOS(outer) == client.tos && IPH_TTL(outer) == client.ttl, "request TOS/TTL is wrong");
        require(IPH_ID(outer) == 0 && lwip_ntohs(IPH_OFFSET(outer)) == IP_DF, "request DF/ID policy is wrong");
        require(memoryEqual(sbufGetRawPtr(request) + kPing6WireEncapsulationOverhead, original, inner_length),
                "request altered the inner IPv4 packet");

        ping6_wire_envelope_t request_view = {0};
        require(ping6wireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &server, &request_view) ==
                    kPingWireInboundEchoRequest,
                "receiver rejected a valid Ping6 request");

        sbuf_t *reply = sbufDuplicate(request);
        require(ping6wireBuildEchoReply(reply, &server, &request_view, 0x4321), "Ping6 reply build failed");
        requireValidCarrier(reply, &server);
        const struct ip_hdr   *reply_outer = (const struct ip_hdr *) sbufGetRawPtr(reply);
        struct icmp6_echo_hdr *reply_icmp  = icmp6Header(reply);
        require(reply_icmp->type == kPing6WireEchoReply && reply_icmp->code == 0, "reply type/code is wrong");
        require(reply_icmp->id == icmp->id && reply_icmp->seqno == icmp->seqno,
                "reply did not mirror identifier/sequence");
        require(IPH_TOS(reply_outer) == client.tos && IPH_TTL(reply_outer) == server.ttl,
                "reply TOS/TTL policy is wrong");
        require(lwip_ntohs(IPH_OFFSET(reply_outer)) == 0 && lwip_ntohs(IPH_ID(reply_outer)) == 0x4321,
                "reply fragmentation/ID policy is wrong");
        require(memoryEqual(sbufGetRawPtr(reply) + kPing6WireEncapsulationOverhead, original, inner_length),
                "reply did not preserve the inner packet");

        ping6_wire_envelope_t reply_view = {0};
        require(ping6wireParseInbound(sbufGetRawPtr(reply), sbufGetLength(reply), &client, &reply_view) ==
                    kPingWireInboundEchoReply,
                "client rejected a valid Ping6 reply");
        require(ping6wireStripEchoRequest(request, &request_view), "validated request did not strip");
        require(sbufGetLength(request) == inner_length && memoryEqual(sbufGetRawPtr(request), original, inner_length),
                "stripping did not restore the exact inner packet");

        uint8_t unaligned[kMaxAllowedPacketLength + 1];
        memoryCopy(unaligned + 1, sbufGetRawPtr(reply), sbufGetLength(reply));
        require(ping6wireParseInbound(unaligned + 1, sbufGetLength(reply), &client, &reply_view) ==
                    kPingWireInboundEchoReply,
                "unaligned valid carrier was rejected");

        sbufDestroy(reply);
        sbufDestroy(request);
    }
}

static void testBoundsAndMalformedMatrix(void)
{
    const ping6_wire_config_t client = clientConfig();
    const ping6_wire_config_t server = serverConfig(&client);
    ping6_wire_envelope_t     view   = {0};

    sbuf_t *maximum = makeInnerPacket(kPing6WireMaxInnerPacketLength, lwip_htons(IP_MF));
    require(ping6wireBuildEchoRequest(maximum, &client, 3), "maximum inner fragment was rejected");
    require(sbufGetLength(maximum) == kMaxAllowedPacketLength, "maximum carrier length is wrong");
    sbufDestroy(maximum);

    sbuf_t *oversize = makeInnerPacket(kPing6WireMaxInnerPacketLength + 1U, 0);
    require(! ping6wireEchoRequestPreflight(oversize) && ! ping6wireBuildEchoRequest(oversize, &client, 3),
            "oversized inner packet was accepted");
    sbufDestroy(oversize);

    sbuf_t *short_padding = sbufCreateWithPadding(72, 0);
    sbufSetLength(short_padding, 72);
    memoryZero(sbufGetMutablePtr(short_padding), 72);
    struct ip_hdr *short_ip = (struct ip_hdr *) sbufGetMutablePtr(short_padding);
    IPH_VHL_SET(short_ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(short_ip, lwip_htons(72));
    IPH_TTL_SET(short_ip, 64);
    IPH_PROTO_SET(short_ip, kTestInnerProtocol);
    require(calcFullPacketChecksum(sbufGetMutablePtr(short_padding), 72), "short-padding checksum failed");
    require(! ping6wireEchoRequestPreflight(short_padding) && ! ping6wireBuildEchoRequest(short_padding, &client, 4),
            "insufficient padding was accepted");
    sbufDestroy(short_padding);

    sbuf_t *ipv6 = sbufCreateWithPadding(40, kPing6WireEncapsulationOverhead);
    sbufSetLength(ipv6, 40);
    memoryZero(sbufGetMutablePtr(ipv6), 40);
    sbufGetMutablePtr(ipv6)[0] = 0x60;
    require(! ping6wireEchoRequestPreflight(ipv6), "IPv6 inner input passed preflight");
    sbufDestroy(ipv6);

    uint8_t truncated[IP_HLEN - 1U] = {0x45};
    require(ping6wireParseInbound(truncated, sizeof(truncated), &server, &view) == kPingWireInboundMalformed,
            "truncated outer header was accepted");
    require(ping6wireParseInbound(truncated, sizeof(truncated), NULL, &view) == kPingWireInboundMalformed,
            "null parser config was accepted");

    sbuf_t *request = makeInnerPacket(80, 0);
    require(ping6wireBuildEchoRequest(request, &client, 9), "malformed-matrix request build failed");

    sbuf_t *trailing = sbufCreateWithPadding(sbufGetLength(request) + 1U, kPing6WireEncapsulationOverhead);
    sbufSetLength(trailing, sbufGetLength(request) + 1U);
    memoryCopy(sbufGetMutablePtr(trailing), sbufGetRawPtr(request), sbufGetLength(request));
    require(ping6wireParseInbound(sbufGetRawPtr(trailing), sbufGetLength(trailing), &server, &view) ==
                kPingWireInboundMalformed,
            "carrier with trailing bytes was accepted");
    sbufDestroy(trailing);

    sbuf_t *bad_outer = sbufDuplicate(request);
    sbufGetMutablePtr(bad_outer)[8] ^= 1U;
    require(ping6wireParseInbound(sbufGetRawPtr(bad_outer), sbufGetLength(bad_outer), &server, &view) ==
                kPingWireInboundMalformed,
            "bad outer checksum was accepted");
    sbufDestroy(bad_outer);

    sbuf_t *bad_icmp = sbufDuplicate(request);
    sbufGetMutablePtr(bad_icmp)[kPing6WireEncapsulationOverhead] ^= 1U;
    require(ping6wireParseInbound(sbufGetRawPtr(bad_icmp), sbufGetLength(bad_icmp), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "bad ICMPv6 checksum was accepted");
    sbufDestroy(bad_icmp);

    const uint8_t wrong_types[] = {kPing6WireEchoReply, 130};
    for (size_t i = 0; i < ARRAY_SIZE(wrong_types); ++i)
    {
        sbuf_t *wrong            = sbufDuplicate(request);
        icmp6Header(wrong)->type = wrong_types[i];
        repairCarrierIndependently(wrong, &client);
        const ping_wire_inbound_kind_t expected =
            wrong_types[i] == kPing6WireEchoReply ? kPingWireInboundEchoReply : kPingWireInboundInvalidCarrier;
        require(ping6wireParseInbound(sbufGetRawPtr(wrong), sbufGetLength(wrong), &server, &view) == expected,
                "wrong ICMPv6 type classification changed");
        sbufDestroy(wrong);
    }

    sbuf_t *wrong_code            = sbufDuplicate(request);
    icmp6Header(wrong_code)->code = 1;
    repairCarrierIndependently(wrong_code, &client);
    require(ping6wireParseInbound(sbufGetRawPtr(wrong_code), sbufGetLength(wrong_code), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "nonzero ICMPv6 code was accepted");
    sbufDestroy(wrong_code);

    sbuf_t *bad_inner                                             = sbufDuplicate(request);
    sbufGetMutablePtr(bad_inner)[kPing6WireEncapsulationOverhead] = 0x60;
    repairCarrierIndependently(bad_inner, &client);
    require(ping6wireParseInbound(sbufGetRawPtr(bad_inner), sbufGetLength(bad_inner), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "non-IPv4 inner payload was accepted");
    sbufDestroy(bad_inner);

    sbuf_t        *fragment    = sbufDuplicate(request);
    struct ip_hdr *fragment_ip = (struct ip_hdr *) sbufGetMutablePtr(fragment);
    IPH_OFFSET_SET(fragment_ip, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(fragment), sbufGetLength(fragment)),
            "fragment outer checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(fragment), sbufGetLength(fragment), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "fragmented outer carrier was accepted");
    sbufDestroy(fragment);

    sbuf_t        *unrelated    = sbufDuplicate(request);
    struct ip_hdr *unrelated_ip = (struct ip_hdr *) sbufGetMutablePtr(unrelated);
    unrelated_ip->src.addr      = ipv4Address("203.0.113.99");
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(unrelated), sbufGetLength(unrelated)),
            "unrelated outer checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(unrelated), sbufGetLength(unrelated), &server, &view) ==
                kPingWireInboundUnrelated,
            "unrelated source was not passed through");
    IPH_PROTO_SET(unrelated_ip, IP_PROTO_ICMP);
    unrelated_ip->src.addr = client.local_ipv4;
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(unrelated), sbufGetLength(unrelated)),
            "unrelated Protocol checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(unrelated), sbufGetLength(unrelated), &server, &view) ==
                kPingWireInboundUnrelated,
            "unrelated Protocol was not passed through");
    sbufDestroy(unrelated);

    const uint16_t options_length = 4;
    const uint16_t packet_length  = (uint16_t) sbufGetLength(request) + options_length;
    sbuf_t        *options        = sbufCreateWithPadding(packet_length, kPing6WireEncapsulationOverhead);
    sbufSetLength(options, packet_length);
    uint8_t *bytes = sbufGetMutablePtr(options);
    memoryCopy(bytes, sbufGetRawPtr(request), IP_HLEN);
    memoryCopy(bytes + IP_HLEN, (const uint8_t[]) {1, 1, 0, 0}, options_length);
    memoryCopy(bytes + IP_HLEN + options_length, sbufGetRawPtr(request) + IP_HLEN, sbufGetLength(request) - IP_HLEN);
    struct ip_hdr *options_ip = (struct ip_hdr *) bytes;
    IPH_VHL_SET(options_ip, 4, (IP_HLEN + options_length) / 4U);
    IPH_LEN_SET(options_ip, lwip_htons(packet_length));
    repairCarrierIndependently(options, &client);
    require(ping6wireParseInbound(bytes, packet_length, &server, &view) == kPingWireInboundInvalidCarrier,
            "outer IPv4 options were accepted");
    sbufDestroy(options);

    sbuf_t *short_icmp = sbufCreateWithPadding(IP_HLEN + 4U, kPing6WireEncapsulationOverhead);
    sbufSetLength(short_icmp, IP_HLEN + 4U);
    memoryZero(sbufGetMutablePtr(short_icmp), IP_HLEN + 4U);
    struct ip_hdr *short_outer = (struct ip_hdr *) sbufGetMutablePtr(short_icmp);
    IPH_VHL_SET(short_outer, 4, IP_HLEN / 4U);
    IPH_LEN_SET(short_outer, lwip_htons(IP_HLEN + 4U));
    IPH_TTL_SET(short_outer, 64);
    IPH_PROTO_SET(short_outer, kPing6WireProtocol);
    short_outer->src.addr  = client.local_ipv4;
    short_outer->dest.addr = client.peer_ipv4;
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(short_icmp), sbufGetLength(short_icmp)),
            "short ICMPv6 outer checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(short_icmp), sbufGetLength(short_icmp), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "truncated ICMPv6 message was accepted");
    sbufDestroy(short_icmp);
    sbufDestroy(request);
}

static void testMappedAddressesAndChecksumRepair(void)
{
    ip6_addr_t mapped = {0};
    ping6wireIpv4MappedAddress(ipv4Address("192.0.2.10"), &mapped);
    const ip6_addr_t expected = ipv6Address("::ffff:192.0.2.10");
    require(memoryEqual(mapped.addr, expected.addr, sizeof(mapped.addr)), "mapped IPv6 address bytes are wrong");

    ping6_wire_config_t       client  = clientConfig();
    const ping6_wire_config_t server  = serverConfig(&client);
    sbuf_t                   *request = makeInnerPacket(81, 0);
    require(ping6wireBuildEchoRequest(request, &client, 12), "checksum-repair request build failed");
    struct ip_hdr *outer = (struct ip_hdr *) sbufGetMutablePtr(request);
    IPH_CHKSUM_SET(outer, 0);
    icmp6Header(request)->chksum = 0;
    require(ping6wireRecalculateCarrierChecksums(request, &server.peer_ipv6, &server.local_ipv6),
            "inbound-direction checksum repair failed");
    requireValidCarrier(request, &client);

    ping6_wire_envelope_t view = {0};
    require(ping6wireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &server, &view) ==
                kPingWireInboundEchoRequest,
            "repaired request did not parse");
    /* The pseudo-header sum commutes, so the checksum alone cannot tell a swapped local/peer pair apart. */
    ping6_wire_config_t swapped = server;
    swapped.local_ipv6          = server.peer_ipv6;
    swapped.peer_ipv6           = server.local_ipv6;
    require(ping6wireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &swapped, &view) ==
                kPingWireInboundEchoRequest,
            "swapped pseudo-address pair changed the commutative checksum");
    ping6_wire_config_t wrong_peer = server;
    wrong_peer.peer_ipv6           = ipv6Address("2001:db8::ffff");
    require(ping6wireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &wrong_peer, &view) ==
                kPingWireInboundInvalidCarrier,
            "wrong pseudo-address was accepted");

    bool found_zero = false;
    for (uint32_t candidate = 0; candidate <= UINT16_MAX; ++candidate)
    {
        uint8_t *inner = sbufGetMutablePtr(request) + kPing6WireEncapsulationOverhead;
        inner[sbufGetLength(request) - kPing6WireEncapsulationOverhead - 2U] = (uint8_t) (candidate >> 8U);
        inner[sbufGetLength(request) - kPing6WireEncapsulationOverhead - 1U] = (uint8_t) candidate;
        struct icmp6_echo_hdr *icmp                                          = icmp6Header(request);
        icmp->chksum                                                         = 0;
        if (independentChecksum((const uint8_t *) icmp,
                                (uint32_t) sbufGetLength(request) - kPing6WireIpv4HeaderLength,
                                &client.local_ipv6,
                                &client.peer_ipv6) == 0)
        {
            require(ping6wireRecalculateCarrierChecksums(request, &client.local_ipv6, &client.peer_ipv6),
                    "zero-checksum repair failed");
            require(icmp->chksum == 0, "ICMPv6 zero checksum was replaced with UDP-style all-ones");
            requireValidCarrier(request, &client);
            found_zero = true;
            break;
        }
    }
    require(found_zero, "could not construct an ICMPv6 zero-checksum vector");
    sbufDestroy(request);
}

static void testUnrelatedOversizeAndEqualAddressRepair(void)
{
    ping6_wire_config_t       client = clientConfig();
    const ping6_wire_config_t server = serverConfig(&client);
    ping6_wire_envelope_t     view   = {0};

    sbuf_t        *unrelated = makeInnerPacket(kMaxAllowedPacketLength + 1U, 0);
    struct ip_hdr *ip        = (struct ip_hdr *) sbufGetMutablePtr(unrelated);
    ip->src.addr             = ipv4Address("203.0.113.99");
    ip->dest.addr            = server.local_ipv4;
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(unrelated), sbufGetLength(unrelated)),
            "oversized unrelated IPv4 checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(unrelated), sbufGetLength(unrelated), &server, &view) ==
                kPingWireInboundUnrelated,
            "valid unrelated IPv4 over 1500 bytes was not preserved");
    sbufDestroy(unrelated);

    sbuf_t *addressed = makeInnerPacket(kMaxAllowedPacketLength + 1U, 0);
    ip                = (struct ip_hdr *) sbufGetMutablePtr(addressed);
    ip->src.addr      = client.local_ipv4;
    ip->dest.addr     = client.peer_ipv4;
    IPH_PROTO_SET(ip, kPing6WireProtocol);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(addressed), sbufGetLength(addressed)),
            "oversized addressed IPv4 checksum failed");
    require(ping6wireParseInbound(sbufGetRawPtr(addressed), sbufGetLength(addressed), &server, &view) ==
                kPingWireInboundInvalidCarrier,
            "oversized addressed carrier did not get a carrier-specific rejection");
    sbufDestroy(addressed);

    client.peer_ipv4                       = client.local_ipv4;
    const ping6_wire_config_t equal_server = serverConfig(&client);
    sbuf_t                   *request      = makeInnerPacket(81, 0);
    require(ping6wireBuildEchoRequest(request, &client, 12), "equal-address request build failed");
    struct ip_hdr *outer = (struct ip_hdr *) sbufGetMutablePtr(request);
    IPH_CHKSUM_SET(outer, 0);
    icmp6Header(request)->chksum = 0;
    require(ping6wireRecalculateCarrierChecksums(request, &equal_server.peer_ipv6, &equal_server.local_ipv6),
            "equal-IPv4 inbound checksum repair failed");
    requireValidCarrier(request, &client);
    require(ping6wireParseInbound(sbufGetRawPtr(request), sbufGetLength(request), &equal_server, &view) ==
                kPingWireInboundEchoRequest,
            "equal-IPv4 request with distinct pseudo-addresses was rejected");
    sbufDestroy(request);
}

static void testStrictAddressText(void)
{
    const char *const valid_ipv4[] = {"0.0.0.0", "192.0.2.10", "255.255.255.255"};
    for (size_t i = 0; i < ARRAY_SIZE(valid_ipv4); ++i)
    {
        uint32_t parsed = 0;
        require(ping6wireParseIpv4Text(valid_ipv4[i], &parsed) && parsed == ipv4Address(valid_ipv4[i]),
                "plain dotted-quad IPv4 text was rejected or misparsed");
    }

    /* Each of these is either accepted or silently reinterpreted by lwIP's own IPv4 parser. */
    const char *const invalid_ipv4[] = {"",
                                        "192.0.2",
                                        "192.0.2.10.1",
                                        "192.0.2.256",
                                        "192.0.2.010",
                                        "0xc0.0.2.10",
                                        "192.0.2.10 ",
                                        " 192.0.2.10",
                                        "192.0.2.10x",
                                        "192.0..10",
                                        "1921.0.2.1",
                                        "192.0.2.",
                                        "3221225994",
                                        "2001:db8::1"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid_ipv4); ++i)
    {
        uint32_t parsed = UINT32_C(0x5a5a5a5a);
        require(! ping6wireParseIpv4Text(invalid_ipv4[i], &parsed) && parsed == UINT32_C(0x5a5a5a5a),
                "lenient IPv4 text was accepted or wrote its output");
    }

    /* Expected network bytes are independent of the parser used by production. */
    const struct
    {
        const char *text;
        uint8_t     bytes[16];
    } valid_ipv6[] = {
        {"::", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"::1", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
        {"2001:db8::10", {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}},
        {"2001:DB8:0:0:0:0:0:10", {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}},
        {"1:2:3:4:5:6:7:8", {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}},
        {"1:2:3:4:5:6:7::", {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0}},
        {"::ffff:192.0.2.10", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10}},
        {"::192.0.2.1", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}},
        {"2001:db8::192.0.2.1", {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}},
        {"2001:db8:0:1:2:3:192.0.2.1", {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 2, 0, 3, 192, 0, 2, 1}},
        {"2001:db8:0:1::192.0.2.1", {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 192, 0, 2, 1}},
        {"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
         {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 255, 255, 255, 255}},
    };
    for (size_t i = 0; i < ARRAY_SIZE(valid_ipv6); ++i)
    {
        ip6_addr_t parsed = {0};
        require(ping6wireParseIpv6Text(valid_ipv6[i].text, &parsed) &&
                    memoryEqual(parsed.addr, valid_ipv6[i].bytes, sizeof(valid_ipv6[i].bytes)),
                "valid IPv6 text was rejected or misparsed");
    }

    /* Reject foreign text, malformed compression and non-canonical dotted-quad tails. */
    const char *const invalid_ipv6[] = {"2001:db8::1 ",
                                        "2001:db8::1 2001:db8::2",
                                        "2001:db8::1,2001:db8::2",
                                        "2001:db8::1%eth0",
                                        "2001:db8::1/128",
                                        "2001:db8::12345",
                                        "::ffff:192.0.2",
                                        "::ffff:192.0.2.010",
                                        "",
                                        "[2001:db8::1]",
                                        "192.0.2.1",
                                        "1:2:3:4:5:6:7",
                                        "1:2:3:4:5:6:7:8:9",
                                        ":1:2:3:4:5:6:7",
                                        "1:2:3:4:5:6:7:",
                                        "::1:2:3:4:5:6:7:8",
                                        "1:2:3:4:5:6:7:8::",
                                        "1:2:3:4::5:6:7:8",
                                        "1::2::3",
                                        ":",
                                        ":::1",
                                        "2001:db8:::1",
                                        "::192.0.2",
                                        "::192.0.2.1.2",
                                        "::192.0.2.256",
                                        "::192.0.2.01",
                                        "::192.0..1",
                                        "::192.0.2.1:1",
                                        "1:2:3:4:5:6:7:192.0.2.1",
                                        "1:2:3:4:5:192.0.2.1",
                                        "1:2:3:4:5:6::192.0.2.1",
                                        "2001:db8::g"};
    ip6_addr_t        unchanged;
    memorySet(&unchanged, 0x5a, sizeof(unchanged));
    for (size_t i = 0; i < ARRAY_SIZE(invalid_ipv6); ++i)
    {
        ip6_addr_t parsed;
        memoryCopy(&parsed, &unchanged, sizeof(parsed));
        require(! ping6wireParseIpv6Text(invalid_ipv6[i], &parsed) && memoryEqual(&parsed, &unchanged, sizeof(parsed)),
                "malformed IPv6 text was accepted or wrote its output");
    }
}

int main(void)
{
    testCaseSet("ping6_wire_test");
    initWLibc();
    checkSumInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");

    testRequestReplyAndIndependentChecksums();
    testBoundsAndMalformedMatrix();
    testMappedAddressesAndChecksumRepair();
    testUnrelatedOversizeAndEqualAddressRepair();
    testStrictAddressText();

    wCryptoGlobalCleanup();
    puts("ping6_wire_test: all cases passed");
    return 0;
}

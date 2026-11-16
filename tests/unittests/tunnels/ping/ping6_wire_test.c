/*
 * Covers: single IPv4 Echo framing, final protocol trailer, actual IHL, checksum
 * parity and address normalization, exact capacity, fragment/geometry refusal,
 * visible repair, arbitrary unmatched replies and bounded request identities.
 * Setup: ordinary in-memory packets; independent RFC 1071 checksum expectations.
 * CTest: waterwall.ping6_wire_unit. These sources require Debug and Release execution.
 */
#include "PingCommon/ping6_wire.h"
#include "test_assert.h"
#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static uint32_t ipv4Address(const char *text)
{
    ip4_addr_t address = {0};
    require(ip4AddrAddressToNetwork(text, &address) != 0, "IPv4 fixture parse failed");
    return ip4AddrGetU32(&address);
}

static uint32_t sumBytes(const uint8_t *bytes, size_t length, uint32_t sum)
{
    while (length >= 2)
    {
        sum += ((uint32_t) bytes[0] << 8U) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length != 0)
        sum += (uint32_t) bytes[0] << 8U;
    return sum;
}

static uint16_t foldChecksum(uint32_t sum)
{
    while (sum >> 16U)
        sum = (sum & 65535U) + (sum >> 16U);
    return (uint16_t) ~sum;
}

static void checksumAt(uint8_t *bytes, size_t length, uint32_t seed, size_t field)
{
    bytes[field] = bytes[field + 1] = 0;
    PUT_BE16(bytes + field, foldChecksum(sumBytes(bytes, length, seed)));
}

static ping6_wire_config_t config(void)
{
    ping6_wire_config_t result = {.identifier = 0x1234};
    return result;
}

static uint32_t carrierSeed(const ping6_wire_config_t *cfg, size_t length)
{
    return sumBytes((const uint8_t *) cfg->local_ipv6.addr,
                    16,
                    sumBytes((const uint8_t *) cfg->peer_ipv6.addr, 16, (uint32_t) length + 58U));
}

static void repairCarrier(sbuf_t *buf, const ping6_wire_config_t *cfg)
{
    uint8_t     *bytes  = sbufGetMutablePtr(buf);
    const size_t header = (bytes[0] & 15U) * 4U;
    checksumAt(bytes + header, sbufGetLength(buf) - header, carrierSeed(cfg, sbufGetLength(buf) - header), 2);
    checksumAt(bytes, header, 0, 10);
}

static void requireCarrier(const sbuf_t *buf, const ping6_wire_config_t *cfg)
{
    const uint8_t *bytes  = sbufGetRawPtr(buf);
    const size_t   header = (bytes[0] & 15U) * 4U;
    require(GET_BE16(bytes + 2) == sbufGetLength(buf), "carrier declared length mismatch");
    require(bytes[9] == 58 && foldChecksum(sumBytes(bytes, header, 0)) == 0,
            "carrier protocol or IPv4 checksum invalid");
    require(foldChecksum(sumBytes(
                bytes + header, sbufGetLength(buf) - header, carrierSeed(cfg, sbufGetLength(buf) - header))) == 0,
            "Echo checksum invalid");
}

static uint32_t transportSeed(const uint8_t *packet, uint8_t protocol, uint16_t length)
{
    return sumBytes(packet + 12, 8, (uint32_t) protocol + length);
}

static sbuf_t *nativePacket(uint8_t protocol, uint16_t header, uint16_t body)
{
    sbuf_t *buf = sbufCreateWithPadding(header + body + 25U, 0);
    /* Exercise exactly nine bytes of headroom, unaligned storage and no tailroom.
     * The allocator may round capacity; restrict the test's accessible geometry. */
    buf->data = buf->head + 9;
    memorySet(buf->head + 9U + header + body, 0xa5, 16);
    buf->capacity = (size_t) 9 + header + body;
    sbufSetLength(buf, header + body);
    uint8_t *p = sbufGetMutablePtr(buf);
    memoryZero(p, header + body);
    p[0] = (uint8_t) (0x40U | header / 4U);
    p[1] = 0x2e;
    PUT_BE16(p + 2, header + body);
    PUT_BE16(p + 4, 0x8877);
    PUT_BE16(p + 6, IP_DF);
    p[8]                      = 55;
    p[9]                      = protocol;
    const uint8_t addresses[] = {10, 10, 0, 1, 10, 10, 0, 2};
    memoryCopy(p + 12, addresses, 8);
    for (uint16_t i = 20; i < header; ++i)
        p[i] = 1; /* IPv4 NOP options */
    for (uint16_t i = 0; i < body; ++i)
        p[header + i] = (uint8_t) (i * 13U + 9U);
    if (protocol == IP_PROTO_TCP && body >= 20)
    {
        p[header + 12] = 0x50;
        checksumAt(p + header, body, transportSeed(p, protocol, body), 16);
    }
    if (protocol == IP_PROTO_UDP && body >= 8)
    {
        PUT_BE16(p + header + 4, body);
        checksumAt(p + header, body, transportSeed(p, protocol, body), 6);
        if (GET_BE16(p + header + 6) == 0)
            PUT_BE16(p + header + 6, 65535);
    }
    if (protocol == IP_PROTO_ICMP && body >= 4)
        checksumAt(p + header, body, 0, 2);
    checksumAt(p, header, 0, 10);
    return buf;
}

static void requireCanary(const sbuf_t *buf)
{
    for (size_t i = 0; i < 16; ++i)
        require(buf->head[buf->capacity + i] == 0xa5, "codec wrote beyond the declared allocation boundary");
}

static void testExactWireVector(void)
{
    ping6_wire_config_t cfg    = config();
    sbuf_t             *buf    = nativePacket(49, 20, 2);
    sbufGetMutablePtr(buf)[20] = 0x11;
    sbufGetMutablePtr(buf)[21] = 0x22;
    const uint8_t expected[]   = {0x45, 0x2e, 0x00, 0x1f, 0x88, 0x77, 0x40, 0x00, 0x37, 0x3a, 0xa6,
                                  0xe9, 10,   10,   0,    1,    10,   10,   0,    2,    0x80, 0,
                                  0x7f, 0x96, 0x12, 0x34, 0xab, 0xcd, 0x11, 0x22, 49};
    require(ping6wireBuildEchoRequest(buf, &cfg, 0xabcd), "known-vector encode refused");
    require(sbufGetLength(buf) == sizeof(expected) && memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
            "exact carrier bytes differ: framing, trailer or checksum parity");
    requireCarrier(buf, &cfg);
    sbufDestroy(buf);
}

static void testArithmeticZeroChecksum(void)
{
    ping6_wire_config_t cfg = config();
    sbuf_t             *buf = nativePacket(49, 24, 2);
    /* 0x8000 (type), 0x1234 (ID), 0 (sequence), 0x3c86 (body), 0x3100 (trailer)
     * and 0x0045 (11-byte message plus protocol 58, with :: pseudo-addresses)
     * sum to 0xffff: the transmitted Echo checksum must be zero, not UDP's all-ones. */
    PUT_BE16(sbufGetMutablePtr(buf) + 24, 0x3c86);
    require(ping6wireBuildEchoRequest(buf, &cfg, 0), "zero-checksum vector encode refused");
    uint8_t *echo = sbufGetMutablePtr(buf) + 24;
    require(GET_BE16(echo + 2) == 0, "encoded arithmetic-zero Echo checksum was replaced");
    requireCarrier(buf, &cfg);

    PUT_BE16(echo + 2, 0x1234);
    require(ping6wireRecalculateCarrierChecksums(buf, &cfg.local_ipv6, &cfg.peer_ipv6),
            "zero-checksum carrier repair failed");
    require(GET_BE16(echo + 2) == 0, "repaired arithmetic-zero Echo checksum was replaced");
    requireCarrier(buf, &cfg);
    ping_wire_envelope_t view = {0};
    require(ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &cfg, &view) == kPingWireInboundEchoRequest,
            "zero-checksum request was rejected");
    requireCanary(buf);
    sbufDestroy(buf);
}

static void testProtocolOptionsAndParityMatrix(void)
{
    ping6_wire_config_t cfg       = config();
    const uint16_t      headers[] = {20, 24, 60};
    for (unsigned protocol = 0; protocol <= 255; ++protocol)
        for (size_t h = 0; h < ARRAY_SIZE(headers); ++h)
            for (unsigned odd = 0; odd < 2; ++odd)
            {
                const uint16_t body = (uint16_t) ((protocol == 6    ? 20
                                                   : protocol == 17 ? 8
                                                   : protocol == 1  ? sizeof(struct icmp_hdr)
                                                                    : 0) +
                                                  odd);
                sbuf_t        *buf  = nativePacket((uint8_t) protocol, headers[h], body);
                uint8_t        original[100];
                const size_t   native_length = sbufGetLength(buf);
                memoryCopy(original, sbufGetRawPtr(buf), native_length);
                require(sbufGetHeadroom(buf) == 9 && sbufGetTailroom(buf) == 0,
                        "exact buffer fixture geometry changed");
                require(ping6wireBuildEchoRequest(buf, &cfg, (uint16_t) protocol), "matrix encode refused");
                require(sbufGetHeadroom(buf) == 0 && sbufGetTailroom(buf) == 0, "encode used unadvertised space");
                require(sbufGetLength(buf) == native_length + 9 && sbufGetRawPtr(buf)[native_length + 8] == protocol,
                        "matrix trailer or overhead mismatch");
                requireCarrier(buf, &cfg);
                requireCanary(buf);
                ping_wire_envelope_t view = {0};
                require(ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &cfg, &view) ==
                            kPingWireInboundEchoRequest,
                        "matrix request did not parse");
                require(view.native_protocol == protocol && view.native_body_length == body &&
                            view.ip_header_length == headers[h],
                        "request geometry includes framing in native span");
                sbuf_t *reply = sbufDuplicate(buf);
                require(ping6wireBuildEchoReply(reply, &cfg, &view, 0x4321), "optional reply clone refused");
                const uint8_t *r = sbufGetRawPtr(reply);
                require(r[8] == 64 && r[1] == original[1] && GET_BE16(r + 6) == 0 && GET_BE16(r + 4) == 0x4321,
                        "generated reply header policy mismatch");
                require(memoryEqual(r + 12, original + 16, 4) && memoryEqual(r + 16, original + 12, 4),
                        "reply addresses not reversed");
                require(memoryEqual(r + headers[h] + 4, sbufGetRawPtr(buf) + headers[h] + 4, body + 5),
                        "reply changed identifier/sequence or exact body+trailer");
                requireCarrier(reply, &cfg);
                sbufDestroy(reply);
                require(ping6wireStripEchoRequest(buf, &view), "matrix strip refused");
                require(sbufGetLength(buf) == native_length && sbufGetHeadroom(buf) == 9 &&
                            memoryEqual(sbufGetRawPtr(buf), original, native_length),
                        "roundtrip changed native header/options/body");
                requireCanary(buf);
                sbufDestroy(buf);
            }
}

static void testShortNativeIcmpRejected(void)
{
    ping6_wire_config_t cfg = config();
    for (uint16_t body = 0; body < sizeof(struct icmp_hdr); ++body)
    {
        sbuf_t      *buf    = nativePacket(IP_PROTO_ICMP, 20, body);
        uint8_t     *packet = sbufGetMutablePtr(buf);
        uint8_t      original[20 + sizeof(struct icmp_hdr)];
        const size_t length = sbufGetLength(buf);
        memoryCopy(original, packet, length);
        require(! ping6wireBuildEchoRequest(buf, &cfg, 0) && sbufGetRawPtr(buf) == packet &&
                    sbufGetLength(buf) == length && memoryEqual(packet, original, length),
                "undersized native ICMP body was accepted or mutated");
        requireCanary(buf);
        sbufDestroy(buf);
    }
}

static void testRefusalsAndVisibleRepair(void)
{
    ping6_wire_config_t cfg     = config();
    sbuf_t             *maximum = nativePacket(49, 20, 1471);
    require(ping6wireBuildEchoRequest(maximum, &cfg, 1) && sbufGetLength(maximum) == 1500,
            "1491-byte native limit refused");
    sbufDestroy(maximum);
    const uint16_t fragments[] = {IP_MF, 1, (uint16_t) (IP_MF | 2)};
    for (unsigned repair = 0; repair < 2; ++repair)
        for (size_t f = 0; f < ARRAY_SIZE(fragments); ++f)
            for (unsigned proto = 0; proto < 3; ++proto)
            {
                const uint8_t protocols[] = {6, 17, 49};
                sbuf_t       *buf         = nativePacket(protocols[proto], 20, 1); /* too short for transport parsing */
                uint8_t      *p           = sbufGetMutablePtr(buf);
                PUT_BE16(p + 6, fragments[f]);
                sbufSetRecalculateChecksum(buf, repair != 0);
                uint8_t original[21];
                memoryCopy(original, p, sizeof(original));
                require(! ping6wireBuildEchoRequest(buf, &cfg, 2) && sbufGetRawPtr(buf) == p &&
                            sbufGetLength(buf) == 21 && memoryEqual(p, original, sizeof(original)) &&
                            sbufGetRecalculateChecksum(buf) == (repair != 0),
                        "fragment refusal mutated native geometry/bytes/intent");
                sbufDestroy(buf);
            }
    for (unsigned failure = 0; failure < 7; ++failure)
    {
        sbuf_t  *buf = nativePacket(49, 20, failure == 0 ? 1472 : 16);
        uint8_t *p   = sbufGetMutablePtr(buf);
        if (failure == 1)
        {
            buf->data -= 1;
            memmove(buf->data, p, sbufGetLength(buf));
            p = buf->data;
        }
        if (failure == 2)
            PUT_BE16(p + 2, 35);
        if (failure == 3)
            p[0] = 0x4f;
        if (failure == 4)
            p[9] = 6; /* short TCP */
        if (failure == 5)
        {
            p[9] = 17;
            PUT_BE16(p + 24, 17);
        }
        if (failure == 6)
        {
            p[9] = 1;
            PUT_BE16(p + 2, 22);
            sbufSetLength(buf, 22);
        }
        uint8_t      before[1600];
        const size_t n = sbufGetLength(buf);
        memoryCopy(before, buf->head, buf->capacity + 16U);
        sbufSetRecalculateChecksum(buf, true);
        require(! ping6wireBuildEchoRequest(buf, &cfg, 3) && sbufGetRawPtr(buf) == p && sbufGetLength(buf) == n &&
                    memoryEqual(before, buf->head, buf->capacity + 16U) && sbufGetRecalculateChecksum(buf),
                "expected refusal changed input");
        sbufDestroy(buf);
    }
    sbuf_t *buf = nativePacket(49, 60, 3);
    require(ping6wireBuildEchoRequest(buf, &cfg, 4), "repair fixture encode failed");
    uint8_t             *p    = sbufGetMutablePtr(buf);
    ping_wire_envelope_t view = {0};
    p[sbufGetLength(buf) - 1] ^= 1;
    require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundInvalidCarrier,
            "corrupt trailer passed checksum");
    require(ping6wireRecalculateCarrierChecksums(buf, &cfg.local_ipv6, &cfg.peer_ipv6), "carrier repair failed");
    require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundEchoRequest,
            "repaired carrier rejected");
    for (size_t f = 0; f < ARRAY_SIZE(fragments); ++f)
    {
        PUT_BE16(p + 6, fragments[f]);
        uint8_t before[80];
        memoryCopy(before, p, sbufGetLength(buf));
        require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundInvalidCarrier,
                "fragment carrier admitted");
        require(! (ping6wireRecalculateCarrierChecksums(buf, &cfg.local_ipv6, &cfg.peer_ipv6)) &&
                    memoryEqual(before, p, sbufGetLength(buf)),
                "fragment carrier partially repaired");
    }
    PUT_BE16(p + 6, IP_DF);
    repairCarrier(buf, &cfg);
    p[9] = 132;
    checksumAt(p, 60, 0, 10);
    require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundUnrelated,
            "unrelated protocol rejected");
    sbufDestroy(buf);
    /* A present zero trailer with empty opaque body is valid; no trailer is not. */
    for (unsigned length = 0; length < 3; ++length)
        for (unsigned reply = 0; reply < 2; ++reply)
        {
            buf  = nativePacket(49, 20, 8 + length);
            p    = sbufGetMutablePtr(buf);
            p[9] = 58;
            memoryZero(p + 20, 8 + length);
            p[20] = reply ? 129 : 128;
            if (reply && length)
                p[28 + length - 1U] = 6; /* invalid native TCP framing is legal in an unmatched reply */
            repairCarrier(buf, &cfg);
            const ping_wire_inbound_kind_t expected = reply         ? kPingWireInboundEchoReply
                                                      : length == 0 ? kPingWireInboundInvalidCarrier
                                                                    : kPingWireInboundEchoRequest;
            require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == expected,
                    "empty reply or missing/zero trailer misclassified");
            sbufDestroy(buf);
        }
}

static void testCarrierGeometryAndUdpPadding(void)
{
    ping6_wire_config_t  cfg              = config();
    ping_wire_envelope_t view             = {0};
    uint8_t              short_header[19] = {0x45};
    require(ping6wireParseInbound(short_header, sizeof(short_header), &cfg, &view) == kPingWireInboundMalformed,
            "short IPv4 header admitted");
    require(ping6wireParseInbound(short_header, sizeof(short_header), NULL, &view) == kPingWireInboundMalformed,
            "null parser config admitted");
    sbuf_t *buf = nativePacket(49, 20, 3);
    require(ping6wireBuildEchoRequest(buf, &cfg, 10), "geometry fixture encode failed");
    uint8_t *packet = sbufGetMutablePtr(buf);
    PUT_BE16(packet + 2, (uint16_t) (sbufGetLength(buf) - 1U));
    require(ping6wireParseInbound(packet, sbufGetLength(buf), &cfg, &view) == kPingWireInboundMalformed,
            "trailing bytes beyond declared IPv4 length admitted");
    PUT_BE16(packet + 2, (uint16_t) (sbufGetLength(buf) + 1U));
    require(ping6wireParseInbound(packet, sbufGetLength(buf), &cfg, &view) == kPingWireInboundMalformed,
            "truncated declared packet admitted");
    sbufDestroy(buf);
    buf       = nativePacket(49, 20, 1481); /* valid candidate geometry, final carrier 1501 */
    packet    = sbufGetMutablePtr(buf);
    packet[9] = 58;
    memoryZero(packet + 20, 1481);
    packet[20]   = 128;
    packet[1500] = 49;
    repairCarrier(buf, &cfg);
    require(ping6wireParseInbound(packet, sbufGetLength(buf), &cfg, &view) == kPingWireInboundInvalidCarrier,
            "1501-byte candidate admitted");
    sbufDestroy(buf);
    buf    = nativePacket(17, 60, 13);
    packet = sbufGetMutablePtr(buf);
    PUT_BE16(packet + 64, 8); /* five bytes of permitted IP padding */
    checksumAt(packet + 60, 8, transportSeed(packet, 17, 8), 6);
    if (GET_BE16(packet + 66) == 0)
        PUT_BE16(packet + 66, 65535);
    uint8_t expected[73];
    memoryCopy(expected, packet, sizeof(expected));
    require(ping6wireBuildEchoRequest(buf, &cfg, 11) &&
                ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &cfg, &view) ==
                    kPingWireInboundEchoRequest &&
                ping6wireStripEchoRequest(buf, &view) && memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
            "UDP padding semantics or checksum length changed");
    sbufDestroy(buf);
}

static void testExplicitPseudoAddresses(void)
{
    ping6_wire_config_t cfg = config();
    require(ping6wireParseIpv6Text("2001:db8::1", &cfg.local_ipv6) &&
                ping6wireParseIpv6Text("2001:db8::192.0.2.1", &cfg.peer_ipv6),
            "explicit checksum addresses rejected");
    sbuf_t *buf = nativePacket(49, 24, 5);
    require(ping6wireBuildEchoRequest(buf, &cfg, 12), "explicit-context encode failed");
    requireCarrier(buf, &cfg);
    ping6_wire_config_t  peer = {.local_ipv6 = cfg.peer_ipv6, .peer_ipv6 = cfg.local_ipv6};
    ping_wire_envelope_t view = {0};
    require(ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &peer, &view) == kPingWireInboundEchoRequest,
            "mirrored explicit checksum inputs rejected");
    ping6_wire_config_t zero = config();
    require(ping6wireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &zero, &view) ==
                kPingWireInboundInvalidCarrier,
            "wrong checksum context accepted");
    sbufDestroy(buf);
}

static void testNativeChecksumResiduals(void)
{
    ping6_wire_config_t cfg = config();
    for (unsigned proto = 0; proto < 2; ++proto)
        for (unsigned mode = 0; mode < 4; ++mode)
        {
            const uint8_t  protocol = proto ? 17 : 6;
            const uint16_t body     = proto ? 13 : 25;
            sbuf_t        *buf      = nativePacket(protocol, 24, body);
            uint8_t       *p        = sbufGetMutablePtr(buf);
            const size_t   field    = 24 + (proto ? 6 : 16);
            if (mode == 1)
                p[24 + body - 1] ^= 0x80; /* invalid hidden residual */
            if (mode == 2 && proto)
                PUT_BE16(p + field, 0); /* disabled UDP */
            if (mode == 3)
            {
                p[24 + body - 1] ^= 0x80;
                sbufSetRecalculateChecksum(buf, true);
            }
            const uint16_t residual = foldChecksum(sumBytes(p + 24, body, transportSeed(p, protocol, body)));
            require(ping6wireBuildEchoRequest(buf, &cfg, (uint16_t) mode), "checksum fixture encode failed");
            p = sbufGetMutablePtr(buf);
            /* Independent address edit during carriage; real IpOverrider is covered by flow units. */
            const uint8_t changed[] = {192, 0, 2, 10, 198, 51, 100, 10};
            memoryCopy(p + 12, changed, 8);
            repairCarrier(buf, &cfg);
            ping_wire_envelope_t view = {0};
            require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundEchoRequest &&
                        ping6wireStripEchoRequest(buf, &view),
                    "rewritten carrier did not decode");
            p = sbufGetMutablePtr(buf);
            if (mode == 2 && proto)
                require(GET_BE16(p + field) == 0, "disabled UDP checksum became enabled");
            else
                require(foldChecksum(sumBytes(p + 24, body, transportSeed(p, protocol, body))) ==
                            (mode == 3 ? 0 : residual),
                        "normalization lost native checksum residual or native repair intent");
            sbufDestroy(buf);
        }
    sbuf_t *buf = nativePacket(6, 20, 25);
    require(ping6wireBuildEchoRequest(buf, &cfg, 9), "hidden corruption fixture encode failed");
    uint8_t *p = sbufGetMutablePtr(buf);
    p[28 + 24] ^= 0x80;
    require(ping6wireRecalculateCarrierChecksums(buf, &cfg.local_ipv6, &cfg.peer_ipv6),
            "visible repair of corrupt payload failed");
    ping_wire_envelope_t view = {0};
    require(ping6wireParseInbound(p, sbufGetLength(buf), &cfg, &view) == kPingWireInboundEchoRequest &&
                ping6wireStripEchoRequest(buf, &view),
            "visible repaired request failed to decode");
    p = sbufGetMutablePtr(buf);
    require(foldChecksum(sumBytes(p + 20, 25, transportSeed(p, 6, 25))) != 0,
            "carrier repair silently repaired hidden TCP");
    sbufDestroy(buf);
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
    testCaseSet("ping6_wire");
    initWLibc();
    checkSumInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    testExactWireVector();
    testArithmeticZeroChecksum();
    testProtocolOptionsAndParityMatrix();
    testShortNativeIcmpRejected();
    testRefusalsAndVisibleRepair();
    testNativeChecksumResiduals();
    testCarrierGeometryAndUdpPadding();
    testExplicitPseudoAddresses();
    testStrictAddressText();
    wCryptoGlobalCleanup();
    return 0;
}

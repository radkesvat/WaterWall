/*
 * Covers the Ping IPv4 carrier independently of node dispatch and configuration.
 * CTest: waterwall.ping_wire_unit.
 */
#include "PingCommon/ping_ipv4.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kCanaryLength = 16,
    kIcmpHeader   = 8,
};

static uint32_t sumWords(const uint8_t *data, size_t length, uint32_t sum)
{
    for (; length >= 2; length -= 2, data += 2)
    {
        sum += ((uint32_t) data[0] << 8U) | data[1];
    }
    if (length == 1)
    {
        sum += (uint32_t) data[0] << 8U;
    }
    return sum;
}

static uint16_t checksum(const uint8_t *bytes, size_t length, uint32_t seed)
{
    uint32_t sum = sumWords(bytes, length, seed);
    while (sum > UINT16_MAX)
    {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static void setChecksum(uint8_t *bytes, size_t length, size_t offset, uint32_t seed)
{
    PUT_BE16(bytes + offset, 0);
    PUT_BE16(bytes + offset, checksum(bytes, length, seed));
}

static ping_ipv4_config_t clientConfig(void)
{
    return (ping_ipv4_config_t) {
        .type = 253,
        .code = 7,
        .role = kPingIpv4Client,
    };
}

static ping_ipv4_config_t serverConfig(void)
{
    return (ping_ipv4_config_t) {
        .type = 8,
        .code = 0,
        .role = kPingIpv4Server,
    };
}

static sbuf_t *newNative(size_t length, uint8_t ihl, uint8_t protocol, size_t headroom, size_t tailroom)
{
    const size_t capacity = length + headroom + tailroom;
    sbuf_t      *buf      = sbufCreateWithPadding(capacity + kCanaryLength, 0);
    /* Keep exact accessible geometry independent of allocator over-allocation. */
    buf->capacity = capacity;
    buf->data     = buf->head + headroom;
    memorySet(buf->head, 0xa5, capacity + kCanaryLength);
    sbufSetLength(buf, length);
    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, length);
    packet[0] = (uint8_t) (0x40U | ihl / 4U);
    packet[1] = 0x2e;
    PUT_BE16(packet + 2, length);
    PUT_BE16(packet + 4, 0x8877);
    PUT_BE16(packet + 6, IP_DF);
    packet[8]                 = 55;
    packet[9]                 = protocol;
    const uint8_t addresses[] = {10, 10, 0, 1, 10, 10, 0, 2};
    memoryCopy(packet + 12, addresses, sizeof(addresses));
    memorySet(packet + IP_HLEN, 1, ihl - IP_HLEN); /* IPv4 NOP options. */
    for (size_t i = ihl; i < length; ++i)
    {
        packet[i] = (uint8_t) (i * 13U + 9U);
    }
    setChecksum(packet, ihl, 10, 0);
    return buf;
}

static void requireCanary(const sbuf_t *buf)
{
    for (size_t i = 0; i < kCanaryLength; ++i)
    {
        require(buf->head[buf->capacity + i] == 0xa5, "codec wrote beyond the declared allocation boundary");
    }
}

static void repairCarrier(sbuf_t *buf)
{
    uint8_t     *bytes = sbufGetMutablePtr(buf);
    const size_t ihl   = (bytes[0] & 15U) * 4U;
    setChecksum(bytes + ihl, sbufGetLength(buf) - ihl, 2, 0);
    setChecksum(bytes, ihl, 10, 0);
}

static sbuf_t *newCarrier(size_t length, uint8_t protocol, uint8_t role)
{
    sbuf_t  *buf   = newNative(length, IP_HLEN, IP_PROTO_ICMP, 0, 0);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    memoryZero(bytes + IP_HLEN, kIcmpHeader);
    bytes[IP_HLEN]     = 8;
    bytes[length - 2U] = protocol;
    bytes[length - 1U] = role;
    repairCarrier(buf);
    return buf;
}

static void requireRefusal(sbuf_t *buf, const ping_ipv4_config_t *config, bool encode)
{
    uint8_t        expected[1501 + kPingIpv4Overhead];
    const size_t   capacity = buf->capacity;
    const size_t   length   = sbufGetLength(buf);
    const uint8_t *cursor   = sbufGetRawPtr(buf);
    const bool     repair   = sbufGetRecalculateChecksum(buf);
    require(capacity <= sizeof(expected), "refusal fixture capacity exceeds capture");
    memoryCopy(expected, buf->head, capacity);
    require((encode ? pingipv4Encode(buf, config) : pingipv4Decode(buf, config)) != NULL, "invalid packet accepted");
    require(sbufGetRawPtr(buf) == cursor && sbufGetLength(buf) == length && buf->capacity == capacity &&
                sbufGetRecalculateChecksum(buf) == repair && memoryEqual(buf->head, expected, capacity),
            "refusal changed caller-owned storage, cursor, length or repair request");
    requireCanary(buf);
}

static void requireCarrierChecksums(const sbuf_t *buf)
{
    const uint8_t *bytes = sbufGetRawPtr(buf);
    const size_t   ihl   = (bytes[0] & 15U) * 4U;
    require(checksum(bytes, ihl, 0) == 0, "outer IPv4 checksum invalid");
    require(checksum(bytes + ihl, sbufGetLength(buf) - ihl, 0) == 0, "outer ICMP checksum invalid");
}

static void testAllPairs(void)
{
    testCaseSet("Ping IPv4 all type/code pairs");
    ping_ipv4_config_t       sender   = clientConfig();
    const ping_ipv4_config_t receiver = serverConfig();
    uint8_t                  native[25];
    sbuf_t                  *buf = newNative(sizeof(native), IP_HLEN, 49, kPingIpv4Overhead, 0);
    memoryCopy(native, sbufGetRawPtr(buf), sizeof(native));
    for (unsigned int type = 0; type <= UINT8_MAX; ++type)
    {
        for (unsigned int code = 0; code <= UINT8_MAX; ++code)
        {
            sender.type = (uint8_t) type;
            sender.code = (uint8_t) code;
            require(pingipv4Encode(buf, &sender) == NULL, "ICMP type/code bytes refused at transmit");
            const uint8_t *bytes = sbufGetRawPtr(buf);
            require(bytes[20] == type && bytes[21] == code, "configured type/code missing from the wire");
            requireCarrierChecksums(buf);
            require(pingipv4Decode(buf, &receiver) == NULL, "receive unexpectedly depends on the type/code bytes");
            require(sbufGetLength(buf) == sizeof(native) && memoryEqual(sbufGetRawPtr(buf), native, sizeof(native)),
                    "round trip changed the native IPv4 packet");
        }
    }
    requireCanary(buf);
    sbufDestroy(buf);
}

static void testWireLayout(void)
{
    testCaseSet("Ping IPv4 exact wire bytes and header preservation");
    const struct
    {
        uint8_t ihl;
        uint8_t protocol;
        uint8_t payload_length;
        bool    server;
    } cases[] = {
        {20, 0, 0, false},
        {60, 49, 1, true},
        {20, 253, 4, false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        const size_t             ihl      = cases[i].ihl;
        const size_t             body     = cases[i].payload_length;
        const size_t             length   = ihl + body;
        const ping_ipv4_config_t sender   = cases[i].server ? serverConfig() : clientConfig();
        const ping_ipv4_config_t receiver = cases[i].server ? clientConfig() : serverConfig();
        uint8_t                  native[64];
        sbuf_t                  *buf   = newNative(length, cases[i].ihl, cases[i].protocol, kPingIpv4Overhead + 1, 0);
        uint8_t                 *bytes = sbufGetMutablePtr(buf);
        if (body == 1)
        {
            bytes[ihl] = 0xa6; /* Distinct from the saved protocol and both roles. */
        }
        memoryCopy(native, bytes, length);
        require((uintptr_t) bytes % 2U == 1, "fixture needs an unaligned native cursor");

        require(pingipv4Encode(buf, &sender) == NULL, "carrier encode refused");
        bytes = sbufGetMutablePtr(buf);
        require((uintptr_t) bytes % 2U == 1 && sbufGetHeadroom(buf) == 1 && sbufGetTailroom(buf) == 0,
                "encode unexpectedly changed alignment or geometry");
        require(sbufGetLength(buf) == length + 10 && GET_BE16(bytes + 2) == length + 10 && bytes[9] == IP_PROTO_ICMP,
                "wrong IPv4 protocol or carrier length");
        require(memoryEqual(bytes, native, 2) && memoryEqual(bytes + 4, native + 4, 5) &&
                    memoryEqual(bytes + 12, native + 12, ihl - 12),
                "encode changed an inherited IPv4 header field");
        const uint8_t *icmp      = bytes + ihl;
        const uint8_t  zeroes[4] = {0};
        require(icmp[0] == sender.type && icmp[1] == sender.code && memoryEqual(icmp + 4, zeroes, sizeof(zeroes)),
                "wrong transmit type/code or reserved bytes");
        uint8_t data[6];
        memoryCopy(data, native + ihl, body);
        data[body]      = cases[i].protocol;
        data[body + 1U] = (uint8_t) sender.role;
        require(memoryEqual(icmp + 8, data, body + 2U), "ICMP data must be exactly payload, protocol, then role");
        requireCarrierChecksums(buf);

        require(pingipv4Decode(buf, &receiver) == NULL, "carrier decode refused");
        require(sbufGetHeadroom(buf) == kPingIpv4Overhead + 1 && sbufGetTailroom(buf) == 0 &&
                    sbufGetLength(buf) == length && memoryEqual(sbufGetRawPtr(buf), native, length),
                "decode did not restore the original geometry and bytes");
        requireCanary(buf);
        sbufDestroy(buf);
    }
}

static void testTransitChanges(void)
{
    testCaseSet("Ping IPv4 receives transit changes and arbitrary ICMP prefix bytes");
    const ping_ipv4_config_t sender   = serverConfig();
    const ping_ipv4_config_t receiver = clientConfig();
    /* The experimental option's data contains both source-route type bytes. */
    const uint8_t options[] = {30, 4, 131, 137, 7, 7, 8, 192, 0, 2, 1, 1};
    const uint8_t ihl       = IP_HLEN + sizeof(options);
    uint8_t       expected[IP_HLEN + sizeof(options) + 2];
    sbuf_t       *buf   = newNative(sizeof(expected), ihl, 49, kPingIpv4Overhead, 0);
    uint8_t      *bytes = sbufGetMutablePtr(buf);
    memoryCopy(bytes + IP_HLEN, options, sizeof(options));
    setChecksum(bytes, ihl, 10, 0);
    memoryCopy(expected, bytes, sizeof(expected));
    require(pingipv4Encode(buf, &sender) == NULL, "carrier encode refused");
    bytes    = sbufGetMutablePtr(buf);
    bytes[1] = expected[1] = 0x2f;
    bytes[8] = expected[8] = 53;
    bytes[15] = expected[15] = 44;
    bytes[19] = expected[19] = 81;
    bytes[ihl - 1] = expected[ihl - 1] = 0; /* Replace the final NOP with EOL. */
    PUT_BE16(bytes + 4, 0x3412);
    PUT_BE16(expected + 4, 0x3412);
    PUT_BE16(bytes + 6, 0);
    PUT_BE16(expected + 6, 0);
    memorySet(bytes + ihl + 4, 0x5c, 4);
    repairCarrier(buf);
    setChecksum(expected, ihl, 10, 0);
    require(pingipv4Decode(buf, &receiver) == NULL && sbufGetLength(buf) == sizeof(expected) &&
                memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
            "decode did not expose the received IPv4 header and preserve its native payload");
    requireCanary(buf);
    sbufDestroy(buf);
}

static void testRefusedIpv4Options(void)
{
    testCaseSet("Ping IPv4 source routes and malformed option lists");
    const ping_ipv4_config_t sender   = clientConfig();
    const ping_ipv4_config_t receiver = serverConfig();
    const struct
    {
        uint8_t protocol;
        uint8_t options[12];
    } cases[] = {
        {IP_PROTO_TCP, {30, 4, 0, 0, 1, 131, 7, 4, 192, 0, 2, 1}}, /* LSRR after another option and NOP. */
        {IP_PROTO_UDP, {137, 7, 8, 192, 0, 2, 1}},                 /* Completed SSRR. */
        {49, {131, 7, 8, 192, 0, 2, 1}},                           /* Completed LSRR, opaque payload. */
        {IP_PROTO_ICMP, {137, 7, 4, 192, 0, 2, 1}},
        {49, {30, 0}},
        {49, {30, 1}},
        {49, {30, 13}},                                /* Length extends past the IPv4 header. */
        {49, {30, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30}}, /* Last option has no length byte. */
    };
    const uint8_t ihl = IP_HLEN + sizeof(cases[0].options);
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        for (unsigned direction = 0; direction < 2; ++direction)
        {
            sbuf_t  *buf   = newNative(ihl + 20, ihl, cases[i].protocol, kPingIpv4Overhead, 0);
            uint8_t *bytes = sbufGetMutablePtr(buf);
            if (cases[i].protocol == IP_PROTO_TCP)
            {
                bytes[ihl + 12] = 0x50;
            }
            if (cases[i].protocol == IP_PROTO_UDP)
            {
                PUT_BE16(bytes + ihl + 4, 20);
            }
            const bool encode = direction == 0;
            if (! encode)
            {
                require(pingipv4Encode(buf, &sender) == NULL, "cannot construct control carrier");
                bytes = sbufGetMutablePtr(buf);
            }
            memoryCopy(bytes + IP_HLEN, cases[i].options, sizeof(cases[i].options));
            setChecksum(bytes, ihl, 10, 0);
            const ping_ipv4_config_t *config = encode ? &sender : &receiver;
            requireRefusal(buf, config, encode);
            bytes[10] ^= 0x80;
            sbufSetRecalculateChecksum(buf, true);
            requireRefusal(buf, config, encode);
            sbufDestroy(buf);
        }
    }
}

static void testSizeHeadroomAndFragments(void)
{
    testCaseSet("Ping IPv4 size, headroom and fragment boundaries");
    const ping_ipv4_config_t sender   = clientConfig();
    const ping_ipv4_config_t receiver = serverConfig();
    sbuf_t                  *buf      = newNative(1490, 60, 49, 10, 0);
    require(kPingIpv4Overhead == 10 && kPingIpv4MaxInnerLength == 1490 && pingipv4Encode(buf, &sender) == NULL &&
                sbufGetLength(buf) == 1500 && sbufGetHeadroom(buf) == 0 && sbufGetTailroom(buf) == 0,
            "exact-ceiling packet failed with ten bytes of headroom and no tailroom");
    require(pingipv4Decode(buf, &receiver) == NULL && sbufGetLength(buf) == 1490, "exact-ceiling decode failed");
    requireCanary(buf);
    sbufDestroy(buf);

    buf = newNative(1491, IP_HLEN, 49, 10, 0);
    sbufSetRecalculateChecksum(buf, true);
    requireRefusal(buf, &sender, true);
    sbufDestroy(buf);

    buf = newCarrier(1500, 49, 1);
    requireCarrierChecksums(buf);
    require(pingipv4Decode(buf, &receiver) == NULL && sbufGetLength(buf) == 1490,
            "standalone 1500-byte carrier was refused");
    requireCanary(buf);
    sbufDestroy(buf);

    /* Independently frame the maximum plus one, which the encoder cannot produce. */
    buf = newCarrier(1501, 49, 1);
    requireCarrierChecksums(buf);
    sbufSetRecalculateChecksum(buf, true);
    requireRefusal(buf, &receiver, false);
    sbufDestroy(buf);

    buf = newNative(21, IP_HLEN, 49, 9, 0);
    sbufSetRecalculateChecksum(buf, true);
    requireRefusal(buf, &sender, true);
    sbufDestroy(buf);

    for (size_t i = 0; i < 2; ++i)
    {
        const uint16_t fragment = i == 0 ? IP_MF : 1;
        buf                     = newNative(28, IP_HLEN, 49, 10, 0);
        PUT_BE16(sbufGetMutablePtr(buf) + 6, fragment);
        sbufSetRecalculateChecksum(buf, true);
        requireRefusal(buf, &sender, true);
        sbufDestroy(buf);

        buf = newCarrier(38, 49, 1);
        PUT_BE16(sbufGetMutablePtr(buf) + 6, fragment);
        repairCarrier(buf);
        requireRefusal(buf, &receiver, false);
        sbufDestroy(buf);
    }
}

static void testCarrierRefusals(void)
{
    testCaseSet("Ping IPv4 incomplete geometry, checksums and sender roles");
    const ping_ipv4_config_t receiver  = serverConfig();
    const uint8_t            offsets[] = {0, 3, 9, 10, IP_HLEN + 2};
    for (size_t i = 0; i < ARRAY_SIZE(offsets); ++i)
    {
        sbuf_t  *buf   = newCarrier(35, 49, 1);
        uint8_t *bytes = sbufGetMutablePtr(buf);
        bytes[offsets[i]] ^= 1U;
        if (offsets[i] == 9)
        {
            repairCarrier(buf);
        }
        requireRefusal(buf, &receiver, false);
        sbufDestroy(buf);
    }

    for (size_t length = 0; length < 10; ++length)
    {
        sbuf_t *buf = newNative(IP_HLEN + length, IP_HLEN, IP_PROTO_ICMP, 0, 0);
        if (length >= 4)
        {
            repairCarrier(buf);
        }
        requireRefusal(buf, &receiver, false);
        if (length < 4)
        {
            sbufSetRecalculateChecksum(buf, true);
            requireRefusal(buf, &receiver, false);
        }
        sbufDestroy(buf);
    }

    const uint8_t rejected_roles[] = {0, 2, 3, 255};
    for (size_t i = 0; i < ARRAY_SIZE(rejected_roles); ++i)
    {
        sbuf_t *buf = newCarrier(35, 49, rejected_roles[i]);
        requireRefusal(buf, &receiver, false);
        sbufDestroy(buf);
    }

    const ping_ipv4_config_t client = clientConfig();
    sbuf_t                  *buf    = newCarrier(35, 49, 1);
    sbufGetMutablePtr(buf)[IP_HLEN] = 0; /* Echo Reply retaining the sender's data. */
    repairCarrier(buf);
    requireRefusal(buf, &client, false);
    sbufDestroy(buf);
}

static void testTransportGeometry(void)
{
    testCaseSet("Ping IPv4 native transport checks exclude the frame trailer");
    const ping_ipv4_config_t sender   = clientConfig();
    const ping_ipv4_config_t receiver = serverConfig();
    const struct
    {
        uint8_t protocol;
        uint8_t length;
        uint8_t field;
    } cases[] = {
        {IP_PROTO_TCP, 19, 0x50},
        {IP_PROTO_TCP, 20, 0x40},
        {IP_PROTO_TCP, 22, 0x60},
        {IP_PROTO_UDP, 7, 8},
        {IP_PROTO_UDP, 8, 7},
        {IP_PROTO_UDP, 8, 9},
        {IP_PROTO_ICMP, 7, 0},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        const size_t  length   = cases[i].length;
        const uint8_t protocol = cases[i].protocol;
        sbuf_t       *native   = newNative(IP_HLEN + length, IP_HLEN, protocol, 10, 0);
        uint8_t      *body     = sbufGetMutablePtr(native) + IP_HLEN;
        if (protocol == IP_PROTO_TCP)
        {
            body[12] = cases[i].field;
        }
        if (protocol == IP_PROTO_UDP)
        {
            PUT_BE16(body + 4, cases[i].field);
        }
        sbufSetRecalculateChecksum(native, true);
        requireRefusal(native, &sender, true);

        sbuf_t *carrier = newCarrier(IP_HLEN + length + 10, protocol, 1);
        memoryCopy(sbufGetMutablePtr(carrier) + IP_HLEN + kIcmpHeader, body, length);
        repairCarrier(carrier);
        sbufSetRecalculateChecksum(carrier, true);
        requireRefusal(carrier, &receiver, false);
        sbufDestroy(carrier);
        sbufDestroy(native);
    }

    sbuf_t  *buf   = newNative(IP_HLEN + 11, IP_HLEN, IP_PROTO_UDP, 10, 0);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    PUT_BE16(bytes + IP_HLEN + 4, 8);
    PUT_BE16(bytes + IP_HLEN + 6, 0);
    uint8_t expected[IP_HLEN + 11];
    memoryCopy(expected, bytes, sizeof(expected));
    require(pingipv4Encode(buf, &sender) == NULL && pingipv4Decode(buf, &receiver) == NULL &&
                sbufGetLength(buf) == sizeof(expected) && memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
            "UDP length with IPv4 padding lost data or enabled the disabled checksum");
    requireCanary(buf);
    sbufDestroy(buf);
}

static void testChecksumRepairBoundaries(void)
{
    testCaseSet("Ping IPv4 checksum repair boundaries");
    const ping_ipv4_config_t sender   = clientConfig();
    const ping_ipv4_config_t receiver = serverConfig();
    const size_t             ihl      = 24;
    const size_t             udp_len  = 9;
    uint8_t                  expected[33];
    sbuf_t                  *buf    = newNative(sizeof(expected), (uint8_t) ihl, IP_PROTO_UDP, kPingIpv4Overhead, 0);
    uint8_t                 *native = sbufGetMutablePtr(buf);
    PUT_BE16(native + ihl + 4, udp_len);
    uint32_t seed = sumWords(native + 12, 8, IP_PROTO_UDP + udp_len);
    setChecksum(native + ihl, udp_len, 6, seed);
    require(GET_BE16(native + ihl + 6) != 0, "fixture needs a nonzero UDP checksum");
    memoryCopy(expected, native, sizeof(expected));
    native[10] ^= 0x80;
    native[ihl + 6] ^= 0x80;
    sbufSetRecalculateChecksum(buf, true);
    require(pingipv4Encode(buf, &sender) == NULL && ! sbufGetRecalculateChecksum(buf),
            "native pending repair was not consumed");
    requireCarrierChecksums(buf);
    uint8_t *carrier   = sbufGetMutablePtr(buf);
    uint8_t *transport = carrier + ihl + kIcmpHeader;
    require(checksum(transport, udp_len, IP_PROTO_UDP + udp_len) == 0,
            "native UDP repair or address neutralization failed");

    /* Outer repair must not affect even a deliberately corrupt native checksum. */
    carrier[10] ^= 0x80;
    carrier[ihl + 2] ^= 0x80;
    transport[udp_len - 1U] ^= 0x80;
    expected[sizeof(expected) - 1U] ^= 0x80;
    sbufSetRecalculateChecksum(buf, true);
    require(pingipv4Decode(buf, &receiver) == NULL && ! sbufGetRecalculateChecksum(buf),
            "pending carrier repair was not consumed");
    require(sbufGetLength(buf) == sizeof(expected) && memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
            "carrier repair modified hidden native checksum bytes");
    requireCanary(buf);
    sbufDestroy(buf);
}

int main(void)
{
    initWLibc();
    checkSumInit();
    testAllPairs();
    testWireLayout();
    testTransitChanges();
    testRefusedIpv4Options();
    testSizeHeadroomAndFragments();
    testCarrierRefusals();
    testTransportGeometry();
    testChecksumRepairBoundaries();
    return 0;
}

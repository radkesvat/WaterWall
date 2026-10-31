/*
 * Covers: FakeTcpHeaderCommon wire codec, carrier port mapping and strict settings loader.
 * Contract: encode prepends outer IPv4 (0x45, TOS = inner TOS & 0xFC, ID 0, DF, TTL 64, protocol 6,
 * inner addresses) and TCP (ports per mapping, ACK|PSH, template fields, options verbatim) to one complete
 * inner IPv4 packet whose bytes stay unchanged; inner checksums are repaired only on request. Decode checks
 * framing and ports, verifies outer checksums unless repair is requested, and strips to the inner packet.
 * Every refusal names its reason and leaves bytes, length, cursor and the repair request unchanged.
 * Cases: testResultNames, testKnownAnswer, testChecksumOracle, testOuterFields, testPortMapping,
 * testDecodePortRules, testOuterIntegrity, testIntentionalCorruption, testRepair, testOuterOptions,
 * testLimitsAndRefusals, testSettings
 * Setup: deterministic in-memory packets checked by an independent RFC 1071 oracle; main() selects the
 * production checksum backend first. Known-answer carriers were computed outside the codec.
 * Limits: no line, tunnel, chain or OS socket is involved.
 * CTest: waterwall.fake_tcp_header_wire_unit
 */
#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#define requireResult(actual, expected, message)                                                                       \
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, (uintmax_t) (actual), (uintmax_t) (expected), message)
#define requireBytes(actual, expected, size, message)                                                                  \
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, actual, expected, size, message)

enum
{
    kTestPacketCapacity = 2048,
    kTestAlignments     = 64,
    kTestProtocolIcmp   = 1,
    kTestProtocolTcp    = 6,
    kTestProtocolUdp    = 17,
};

/* Inner request 10.0.0.1:5000 -> 10.0.0.2:53 UDP "fake-tcp", TOS 0x2e, valid checksums. */
static const uint8_t kRequestInner[] = {
    0x45, 0x2e, 0x00, 0x24, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x14, 0x65, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x13, 0x88, 0x00, 0x35, 0x00, 0x10, 0x75, 0x63, 0x66, 0x61, 0x6b, 0x65, 0x2d, 0x74, 0x63, 0x70,
};

/* Its reply 10.0.0.2:53 -> 10.0.0.1:5000 UDP "reply!!" (odd length), TOS 0x03, valid checksums. */
static const uint8_t kReplyInner[] = {
    0x45, 0x03, 0x00, 0x23, 0x43, 0x21, 0x40, 0x00, 0x40, 0x11, 0xe3, 0xa3, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
    0x00, 0x01, 0x00, 0x35, 0x13, 0x88, 0x00, 0x0f, 0x5b, 0x1d, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x21, 0x21,
};

/* Client carrier of kRequestInner under katConfig(): port index 1 -> 40002 -> 40000. */
static const uint8_t kRequestCarrier[] = {
    0x45, 0x2c, 0x00, 0x50, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x26, 0x7a, 0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x02, 0x9c, 0x42, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xd3, 0x55, 0x00, 0x07, 0x02, 0x04, 0x05, 0xb4, 0x45, 0x2e, 0x00, 0x24,
    0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x14, 0x65, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    0x13, 0x88, 0x00, 0x35, 0x00, 0x10, 0x75, 0x63, 0x66, 0x61, 0x6b, 0x65, 0x2d, 0x74, 0x63, 0x70,
};

/* Server carrier of kReplyInner under katConfig(): 40000 -> 40002. */
static const uint8_t kReplyCarrier[] = {
    0x45, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x26, 0xa7, 0x0a, 0x00, 0x00, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x9c, 0x40, 0x9c, 0x42, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xd3, 0x55, 0x00, 0x07, 0x02, 0x04, 0x05, 0xb4, 0x45, 0x03, 0x00, 0x23,
    0x43, 0x21, 0x40, 0x00, 0x40, 0x11, 0xe3, 0xa3, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x01,
    0x00, 0x35, 0x13, 0x88, 0x00, 0x0f, 0x5b, 0x1d, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x21, 0x21,
};

typedef struct test_flow_s
{
    uint32_t source;
    uint32_t destination;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t identification;
    uint8_t  protocol;
    uint8_t  tos;
} test_flow_t;

static const faketcpheader_wire_side_t kSides[] = {kFakeTcpHeaderWireClient, kFakeTcpHeaderWireServer};

static faketcpheader_wire_side_t peerSide(faketcpheader_wire_side_t side)
{
    return side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer : kFakeTcpHeaderWireClient;
}

/* ---- Independent RFC 1071 oracle ------------------------------------------------------------- */

static uint32_t oracleAdd(uint32_t sum, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i + 1 < length; i += 2)
    {
        sum += ((uint32_t) bytes[i] << 8) | bytes[i + 1];
    }
    if (length % 2 != 0)
    {
        sum += (uint32_t) bytes[length - 1] << 8;
    }
    return sum;
}

static uint16_t oracleFold(uint32_t sum)
{
    while ((sum >> 16) != 0)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t) sum;
}

static uint16_t headerLength(const uint8_t *packet)
{
    return (uint16_t) ((packet[0] & 0x0FU) * 4U);
}

static uint16_t totalLength(const uint8_t *packet)
{
    return (uint16_t) (((uint16_t) packet[2] << 8) | packet[3]);
}

static uint32_t oraclePseudoSum(const uint8_t *packet, uint16_t transport_length)
{
    return oracleAdd(0, packet + 12, 8) + packet[9] + transport_length;
}

static bool oracleIpv4HeaderValid(const uint8_t *packet)
{
    return oracleFold(oracleAdd(0, packet, headerLength(packet))) == 0xFFFFU;
}

/* TCP/UDP checksum including the pseudo-header, over the IPv4 payload. */
static bool oracleTransportValid(const uint8_t *packet)
{
    const uint16_t ihl              = headerLength(packet);
    const uint16_t transport_length = (uint16_t) (totalLength(packet) - ihl);
    return oracleFold(oracleAdd(oraclePseudoSum(packet, transport_length), packet + ihl, transport_length)) == 0xFFFFU;
}

static uint16_t transportChecksumOffset(uint8_t protocol)
{
    return protocol == kTestProtocolTcp ? 16 : protocol == kTestProtocolUdp ? 6 : 2;
}

/* Write valid IPv4 header and TCP/UDP/ICMP checksums with the oracle. */
static void oracleSetChecksums(uint8_t *packet)
{
    const uint16_t ihl              = headerLength(packet);
    const uint16_t transport_length = (uint16_t) (totalLength(packet) - ihl);
    const uint8_t  protocol         = packet[9];

    PUT_BE16(packet + 10, 0);
    PUT_BE16(packet + 10, (uint16_t) ~oracleFold(oracleAdd(0, packet, ihl)));

    if (protocol != kTestProtocolTcp && protocol != kTestProtocolUdp && protocol != kTestProtocolIcmp)
    {
        return;
    }
    uint8_t *field = packet + ihl + transportChecksumOffset(protocol);
    PUT_BE16(field, 0);
    const uint32_t seed     = protocol == kTestProtocolIcmp ? 0 : oraclePseudoSum(packet, transport_length);
    uint16_t       checksum = (uint16_t) ~oracleFold(oracleAdd(seed, packet + ihl, transport_length));
    if (protocol == kTestProtocolUdp && checksum == 0)
    {
        checksum = 0xFFFFU;
    }
    PUT_BE16(field, checksum);
}

/* ---- Fixtures --------------------------------------------------------------------------------- */

static faketcpheader_wire_config_t baseConfig(void)
{
    return (faketcpheader_wire_config_t) {
        .sequence          = 0x80000001U,
        .acknowledgment    = 0xFFFFFFFFU,
        .window            = 0xA5C3U,
        .urgent_pointer    = 0x0102U,
        .server_port       = 40000,
        .client_port       = 40001,
        .client_port_count = 16,
    };
}

static faketcpheader_wire_config_t katConfig(void)
{
    faketcpheader_wire_config_t config = baseConfig();
    config.sequence                    = 0x01020304U;
    config.acknowledgment              = 0x0a0b0c0dU;
    config.window                      = 29200;
    config.urgent_pointer              = 7;
    config.options_length              = 4;
    const uint8_t options[]            = {0x02, 0x04, 0x05, 0xb4};
    memoryCopy(config.options, options, sizeof(options));
    return config;
}

static void setOptions(faketcpheader_wire_config_t *config, uint8_t length)
{
    config->options_length = length;
    for (uint8_t i = 0; i < length; ++i)
    {
        config->options[i] = (uint8_t) (0xC0U + i);
    }
}

static test_flow_t udpFlow(uint16_t source_port)
{
    return (test_flow_t) {
        .source           = 0x0A000001U,
        .destination      = 0x0A000002U,
        .source_port      = source_port,
        .destination_port = 53,
        .identification   = 0x2468,
        .protocol         = kTestProtocolUdp,
        .tos              = 0x2e,
    };
}

static test_flow_t reverseFlow(test_flow_t flow)
{
    const uint32_t address = flow.source;
    const uint16_t port    = flow.source_port;
    flow.source            = flow.destination;
    flow.destination       = address;
    flow.source_port       = flow.destination_port;
    flow.destination_port  = port;
    return flow;
}

/* Build one complete IPv4 packet of exactly total_length bytes with valid checksums. */
static uint16_t buildInner(uint8_t *out, const test_flow_t *flow, uint16_t total_length)
{
    require(total_length >= IP_HLEN + 8U && total_length <= kTestPacketCapacity, "bad inner fixture length");
    memoryZero(out, total_length);
    out[0] = 0x45;
    out[1] = flow->tos;
    PUT_BE16(out + 2, total_length);
    PUT_BE16(out + 4, flow->identification);
    PUT_BE16(out + 6, 0x4000);
    out[8] = 61;
    out[9] = flow->protocol;
    PUT_BE32(out + 12, flow->source);
    PUT_BE32(out + 16, flow->destination);

    uint8_t *transport = out + IP_HLEN;
    if (flow->protocol == kTestProtocolUdp)
    {
        PUT_BE16(transport, flow->source_port);
        PUT_BE16(transport + 2, flow->destination_port);
        PUT_BE16(transport + 4, (uint16_t) (total_length - IP_HLEN));
    }
    else if (flow->protocol == kTestProtocolIcmp)
    {
        transport[0] = 8;
        PUT_BE16(transport + 4, flow->source_port);
        PUT_BE16(transport + 6, flow->destination_port);
    }
    for (uint16_t i = 8; i < total_length - IP_HLEN; ++i)
    {
        transport[i] = (uint8_t) (i * 37U + total_length);
    }
    oracleSetChecksums(out);
    return total_length;
}

/* Ordinary buffer holding length bytes after exactly left_capacity bytes of headroom. */
static sbuf_t *makeBuffer(const uint8_t *bytes, uint32_t length, uint32_t left_capacity)
{
    sbuf_t *buf = sbufCreateWithPadding(left_capacity + length + 1U, 0);
    require(sbufGetLeftCapacity(buf) == 0, "test buffer starts with unexpected headroom");
    sbufSetLength(buf, left_capacity + length);
    sbufShiftRight(buf, left_capacity);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    return buf;
}

static const uint8_t *bufferBytes(const sbuf_t *buf)
{
    return (const uint8_t *) sbufGetRawPtr(buf);
}

static sbuf_t *encodeOk(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side, const uint8_t *inner,
                        uint32_t length, uint32_t left_capacity, bool repair)
{
    sbuf_t *buf = makeBuffer(inner, length, left_capacity);
    sbufSetRecalculateChecksum(buf, repair);
    requireResult(faketcpheaderWireEncode(config, side, buf), kFakeTcpHeaderWireOk, "encode refused a valid packet");
    require(! sbufGetRecalculateChecksum(buf), "encode left the checksum repair request set");
    return buf;
}

static void decodeOk(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side, sbuf_t *buf,
                     const uint8_t *expected_inner, uint32_t expected_length)
{
    requireResult(faketcpheaderWireDecode(config, side, buf), kFakeTcpHeaderWireOk, "decode refused a valid carrier");
    require(! sbufGetRecalculateChecksum(buf), "decode left the checksum repair request set");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), expected_length, "decoded inner length");
    requireBytes(bufferBytes(buf), expected_inner, expected_length, "decoded inner bytes differ");
}

/* Run one refusal and prove bytes (including headroom), length, cursor and intent are unchanged. */
static void expectRefusal(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side, bool encode,
                          const uint8_t *bytes, uint32_t length, uint32_t left_capacity, bool repair,
                          faketcpheader_wire_result_t expected, const char *message)
{
    sbuf_t *buf = makeBuffer(bytes, length, left_capacity);
    sbufSetRecalculateChecksum(buf, repair);

    static uint8_t before[2 * kTestPacketCapacity];
    require(left_capacity + length <= sizeof(before), "refusal fixture too large");
    const uint8_t *window = bufferBytes(buf) - left_capacity;
    memoryCopy(before, window, left_capacity + length);

    const faketcpheader_wire_result_t result =
        encode ? faketcpheaderWireEncode(config, side, buf) : faketcpheaderWireDecode(config, side, buf);
    requireResult(result, expected, message);
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), length, "refusal changed the length");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLeftCapacity(buf), left_capacity, "refusal moved the cursor");
    require(sbufGetRecalculateChecksum(buf) == repair, "refusal changed the checksum repair request");
    requireBytes(bufferBytes(buf) - left_capacity, before, left_capacity + length, "refusal changed bytes");
    sbufDestroy(buf);
}

static void expectRefusalAnyIntent(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side,
                                   bool encode, const uint8_t *bytes, uint32_t length, uint32_t left_capacity,
                                   faketcpheader_wire_result_t expected, const char *message)
{
    expectRefusal(config, side, encode, bytes, length, left_capacity, false, expected, message);
    expectRefusal(config, side, encode, bytes, length, left_capacity, true, expected, message);
}

/* Encode an inner packet and copy the resulting carrier out; returns its length. */
static uint32_t carrierOf(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side,
                          const uint8_t *inner, uint32_t length, uint8_t *out)
{
    sbuf_t        *buf            = encodeOk(config, side, inner, length, kFakeTcpHeaderWireRequiredPaddingLeft, false);
    const uint32_t carrier_length = sbufGetLength(buf);
    memoryCopy(out, bufferBytes(buf), carrier_length);
    sbufDestroy(buf);
    return carrier_length;
}

static uint16_t carrierSourcePort(const uint8_t *carrier)
{
    return GET_BE16(carrier + headerLength(carrier));
}

static uint16_t carrierDestinationPort(const uint8_t *carrier)
{
    return GET_BE16(carrier + headerLength(carrier) + 2);
}

/* ---- Cases ------------------------------------------------------------------------------------ */

static void testResultNames(void)
{
    const faketcpheader_wire_result_t results[] = {kFakeTcpHeaderWireOk,
                                                   kFakeTcpHeaderWireMalformedInner,
                                                   kFakeTcpHeaderWireOversizedInner,
                                                   kFakeTcpHeaderWireMissingHeadroom,
                                                   kFakeTcpHeaderWireInnerRepairFailed,
                                                   kFakeTcpHeaderWireMalformedCarrier,
                                                   kFakeTcpHeaderWireCarrierPorts,
                                                   kFakeTcpHeaderWireOuterChecksum,
                                                   kFakeTcpHeaderWireInnerFraming};
    for (size_t i = 0; i < ARRAY_SIZE(results); ++i)
    {
        const char *name = faketcpheaderWireResultName(results[i]);
        require(name != NULL && name[0] != '\0', "result has no name");
        for (size_t j = 0; j < i; ++j)
        {
            require(stringCompare(name, faketcpheaderWireResultName(results[j])) != 0, "result names collide");
        }
    }
}

static void testKnownAnswer(void)
{
    const faketcpheader_wire_config_t config = katConfig();
    require(faketcpheaderWirePortIndex(&config, kRequestInner, sizeof(kRequestInner)) == 1 &&
                faketcpheaderWirePortIndex(&config, kReplyInner, sizeof(kReplyInner)) == 1,
            "known-answer port index changed");

    sbuf_t *buf = encodeOk(&config,
                           kFakeTcpHeaderWireClient,
                           kRequestInner,
                           sizeof(kRequestInner),
                           kFakeTcpHeaderWireRequiredPaddingLeft,
                           false);
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), sizeof(kRequestCarrier), "client carrier length");
    requireBytes(bufferBytes(buf), kRequestCarrier, sizeof(kRequestCarrier), "client carrier bytes");
    decodeOk(&config, kFakeTcpHeaderWireServer, buf, kRequestInner, sizeof(kRequestInner));
    sbufDestroy(buf);

    buf = encodeOk(&config,
                   kFakeTcpHeaderWireServer,
                   kReplyInner,
                   sizeof(kReplyInner),
                   kFakeTcpHeaderWireRequiredPaddingLeft,
                   false);
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), sizeof(kReplyCarrier), "server carrier length");
    requireBytes(bufferBytes(buf), kReplyCarrier, sizeof(kReplyCarrier), "server carrier bytes");
    decodeOk(&config, kFakeTcpHeaderWireClient, buf, kReplyInner, sizeof(kReplyInner));
    sbufDestroy(buf);
}

static void testChecksumOracle(void)
{
    static const uint8_t option_lengths[] = {0, 4, 40};
    uint8_t              inner[kTestPacketCapacity];

    for (size_t o = 0; o < ARRAY_SIZE(option_lengths); ++o)
    {
        faketcpheader_wire_config_t config = baseConfig();
        setOptions(&config, option_lengths[o]);
        const uint16_t maximum = faketcpheaderWireMaxInnerLength(&config);
        const uint16_t sizes[] = {28, 29, 30, 31, 33, 64, 257, 1001, (uint16_t) (maximum - 1U), maximum};
        for (size_t s = 0; s < ARRAY_SIZE(sizes); ++s)
        {
            const test_flow_t flow   = udpFlow((uint16_t) (1000 + s));
            const uint16_t    length = buildInner(inner, &flow, sizes[s]);
            for (uint32_t alignment = 0; alignment < kTestAlignments; ++alignment)
            {
                const faketcpheader_wire_side_t side = kSides[alignment % 2];
                sbuf_t                         *buf =
                    encodeOk(&config, side, inner, length, kFakeTcpHeaderWireRequiredPaddingLeft + alignment, false);
                const uint8_t *carrier = bufferBytes(buf);
                TEST_EQUAL_UINT(TEST_FAILURE_EXIT,
                                sbufGetLength(buf),
                                (uintmax_t) length + faketcpheaderWireOverhead(&config),
                                "carrier length");
                require(oracleIpv4HeaderValid(carrier), "outer IPv4 checksum fails the oracle");
                require(oracleTransportValid(carrier), "outer TCP checksum fails the oracle");
                decodeOk(&config, peerSide(side), buf, inner, length);
                sbufDestroy(buf);
            }
        }
    }
}

static void testOuterFields(void)
{
    static const uint8_t option_lengths[] = {0, 4, 40};
    static const uint8_t tos_cases[][2]   = {{0x2e, 0x2c}, {0x03, 0x00}, {0xff, 0xfc}, {0x00, 0x00}};
    uint8_t              inner[256];

    for (size_t o = 0; o < ARRAY_SIZE(option_lengths); ++o)
    {
        faketcpheader_wire_config_t config = baseConfig();
        setOptions(&config, option_lengths[o]);
        const uint16_t tcp_length = (uint16_t) (TCP_HLEN + option_lengths[o]);

        for (size_t t = 0; t < ARRAY_SIZE(tos_cases); ++t)
        {
            test_flow_t flow      = udpFlow(7000);
            flow.tos              = tos_cases[t][0];
            const uint16_t length = buildInner(inner, &flow, 77);
            sbuf_t        *buf =
                encodeOk(&config, kSides[t % 2], inner, length, kFakeTcpHeaderWireRequiredPaddingLeft + 3U, false);
            const uint8_t *p   = bufferBytes(buf);
            const uint8_t *tcp = p + IP_HLEN;

            require(p[0] == 0x45, "outer version/IHL is not 0x45");
            require(p[1] == tos_cases[t][1], "outer TOS is not inner TOS with Not-ECT");
            require(GET_BE16(p + 2) == sbufGetLength(buf), "outer total length");
            require(GET_BE16(p + 4) == 0, "outer IPv4 identification is not zero");
            require(GET_BE16(p + 6) == 0x4000, "outer IPv4 is not DF without fragment offset");
            require(p[8] == 64, "outer TTL is not 64");
            require(p[9] == 6, "outer protocol is not TCP");
            requireBytes(p + 12, inner + 12, 8, "outer addresses are not the inner addresses");
            require(GET_BE32(tcp + 4) == config.sequence, "TCP sequence");
            require(GET_BE32(tcp + 8) == config.acknowledgment, "TCP acknowledgment");
            require(tcp[12] == (uint8_t) ((tcp_length / 4U) << 4), "TCP data offset");
            require(tcp[13] == 0x18, "TCP flags are not ACK|PSH");
            require(GET_BE16(tcp + 14) == config.window, "TCP window");
            require(GET_BE16(tcp + 18) == config.urgent_pointer, "TCP urgent pointer");
            requireBytes(tcp + TCP_HLEN, config.options, option_lengths[o], "TCP options are not verbatim");
            requireBytes(tcp + tcp_length, inner, length, "inner packet changed inside the carrier");
            sbufDestroy(buf);
        }
    }
}

static void testPortMapping(void)
{
    uint8_t request[256];
    uint8_t reply[256];
    uint8_t carrier[512];

    faketcpheader_wire_config_t config   = baseConfig();
    bool                        used[16] = {false};
    uint32_t                    distinct = 0;
    for (uint16_t i = 0; i < 32; ++i)
    {
        const test_flow_t flow           = udpFlow((uint16_t) (20000 + i * 7U));
        const test_flow_t back           = reverseFlow(flow);
        const uint16_t    request_length = buildInner(request, &flow, 60);
        const uint16_t    reply_length   = buildInner(reply, &back, 45);

        const uint16_t index = faketcpheaderWirePortIndex(&config, request, request_length);
        require(index < config.client_port_count, "port index not below client-port-count");
        require(faketcpheaderWirePortIndex(&config, reply, reply_length) == index, "reply maps to another index");

        discard carrierOf(&config, kFakeTcpHeaderWireClient, request, request_length, carrier);
        require(carrierSourcePort(carrier) == config.client_port + index, "client carrier source port");
        require(carrierDestinationPort(carrier) == config.server_port, "client carrier destination port");
        discard carrierOf(&config, kFakeTcpHeaderWireServer, reply, reply_length, carrier);
        require(carrierSourcePort(carrier) == config.server_port, "server carrier source port");
        require(carrierDestinationPort(carrier) == config.client_port + index,
                "server reply does not use its request's client port");

        if (! used[index])
        {
            used[index] = true;
            ++distinct;
        }
    }
    require(distinct >= 2, "32 distinct flows collapsed onto one client port");

    static const uint16_t counts[] = {1, 2, 3, 16, 1024};
    for (size_t c = 0; c < ARRAY_SIZE(counts); ++c)
    {
        config                   = baseConfig();
        config.client_port       = 50000;
        config.client_port_count = counts[c];
        for (uint16_t i = 0; i < 200; ++i)
        {
            const test_flow_t flow   = udpFlow((uint16_t) (1 + i * 311U));
            const uint16_t    length = buildInner(request, &flow, 40);
            const uint16_t    index  = faketcpheaderWirePortIndex(&config, request, length);
            require(index < counts[c], "port index not below client-port-count");
            discard carrierOf(&config, kFakeTcpHeaderWireClient, request, length, carrier);
            require(carrierSourcePort(carrier) == config.client_port + index, "client port is not client-port + index");
            if (counts[c] == 1)
            {
                require(carrierSourcePort(carrier) == config.client_port, "count 1 did not use client-port");
            }
        }
    }

    config              = baseConfig();
    uint16_t icmp_index = UINT16_MAX;
    for (uint16_t i = 0; i < 32; ++i)
    {
        test_flow_t flow              = udpFlow(0);
        flow.protocol                 = kTestProtocolIcmp;
        flow.source_port              = (uint16_t) (i * 101U); /* ICMP identifier */
        flow.destination_port         = i;                     /* ICMP sequence */
        const test_flow_t packet_flow = i % 2 == 0 ? flow : reverseFlow(flow);
        const uint16_t    length      = buildInner(request, &packet_flow, (uint16_t) (48U + i));
        const uint16_t    index       = faketcpheaderWirePortIndex(&config, request, length);
        if (icmp_index == UINT16_MAX)
        {
            icmp_index = index;
        }
        require(index == icmp_index, "ICMP packets of one address pair use different client ports");
        discard carrierOf(&config, kFakeTcpHeaderWireClient, request, length, carrier);
        require(carrierSourcePort(carrier) == config.client_port + icmp_index, "ICMP carrier client port");
    }

    const uint8_t not_ip[24] = {0xF0};
    require(faketcpheaderWirePortIndex(&config, not_ip, sizeof(not_ip)) == 0, "unhashable packet index is not 0");
}

static void testDecodePortRules(void)
{
    faketcpheader_wire_config_t config = baseConfig();
    uint8_t                     inner[128];
    uint8_t                     carrier[256];
    const test_flow_t           flow   = udpFlow(33333);
    const uint16_t              length = buildInner(inner, &flow, 50);

    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        const faketcpheader_wire_side_t encoder        = kSides[s];
        const faketcpheader_wire_side_t decoder        = peerSide(encoder);
        const uint32_t                  carrier_length = carrierOf(&config, encoder, inner, length, carrier);
        uint8_t *client_field = carrier + IP_HLEN + (encoder == kFakeTcpHeaderWireClient ? 0 : 2);
        uint8_t *server_field = carrier + IP_HLEN + (encoder == kFakeTcpHeaderWireClient ? 2 : 0);

        const struct
        {
            uint16_t client_port;
            uint16_t server_port;
            bool     accepted;
        } cases[] = {
            {config.client_port, config.server_port, true},
            {(uint16_t) (config.client_port + config.client_port_count - 1U), config.server_port, true},
            {(uint16_t) (config.client_port - 1U), config.server_port, false},
            {(uint16_t) (config.client_port + config.client_port_count), config.server_port, false},
            {config.client_port, (uint16_t) (config.server_port + 1U), false},
            {config.client_port, config.client_port, false},
        };
        for (size_t c = 0; c < ARRAY_SIZE(cases); ++c)
        {
            PUT_BE16(client_field, cases[c].client_port);
            PUT_BE16(server_field, cases[c].server_port);
            oracleSetChecksums(carrier);
            if (cases[c].accepted)
            {
                sbuf_t *buf = makeBuffer(carrier, carrier_length, 0);
                decodeOk(&config, decoder, buf, inner, length);
                sbufDestroy(buf);
            }
            else
            {
                expectRefusalAnyIntent(
                    &config, decoder, false, carrier, carrier_length, 0, kFakeTcpHeaderWireCarrierPorts, "port rule");
            }
            /* The encoder's own side never accepts its own carrier. */
            expectRefusalAnyIntent(&config,
                                   encoder,
                                   false,
                                   carrier,
                                   carrier_length,
                                   0,
                                   kFakeTcpHeaderWireCarrierPorts,
                                   "a side accepted its own direction");
        }

        /* Outer addresses are never checked. */
        PUT_BE16(client_field, config.client_port);
        PUT_BE16(server_field, config.server_port);
        PUT_BE32(carrier + 12, 0xCB007109U);
        PUT_BE32(carrier + 16, 0xC6336407U);
        oracleSetChecksums(carrier);
        sbuf_t *buf = makeBuffer(carrier, carrier_length, 5);
        decodeOk(&config, decoder, buf, inner, length);
        sbufDestroy(buf);
    }
}

static void testOuterIntegrity(void)
{
    const faketcpheader_wire_config_t config = katConfig();
    uint8_t                           carrier[sizeof(kRequestCarrier)];
    const uint32_t                    offsets[] = {5, 10, IP_HLEN + 16, IP_HLEN + 24 + 30};

    for (size_t i = 0; i < ARRAY_SIZE(offsets); ++i)
    {
        /* Identification byte, IPv4 checksum, TCP checksum, inner payload byte. */
        memoryCopy(carrier, kRequestCarrier, sizeof(carrier));
        carrier[offsets[i]] ^= 0x01;
        expectRefusal(&config,
                      kFakeTcpHeaderWireServer,
                      false,
                      carrier,
                      sizeof(carrier),
                      0,
                      false,
                      kFakeTcpHeaderWireOuterChecksum,
                      "corrupted outer carrier was accepted");

        sbuf_t *buf = makeBuffer(carrier, sizeof(carrier), 0);
        sbufSetRecalculateChecksum(buf, true);
        requireResult(faketcpheaderWireDecode(&config, kFakeTcpHeaderWireServer, buf),
                      kFakeTcpHeaderWireOk,
                      "pending repair did not skip outer checksum verification");
        require(! sbufGetRecalculateChecksum(buf), "decode left the repair request set");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), sizeof(kRequestInner), "repair decode length");
        if (offsets[i] < IP_HLEN + 24)
        {
            requireBytes(bufferBytes(buf), kRequestInner, sizeof(kRequestInner), "repair decode inner bytes");
        }
        sbufDestroy(buf);
    }
}

static void testIntentionalCorruption(void)
{
    const faketcpheader_wire_config_t config = baseConfig();
    uint8_t                           inner[128];
    const test_flow_t                 flow   = udpFlow(4444);
    const uint16_t                    length = buildInner(inner, &flow, 71);
    inner[10] ^= 0x5A;
    inner[IP_HLEN + 6] ^= 0xA5;
    require(! oracleIpv4HeaderValid(inner) && ! oracleTransportValid(inner), "corruption fixture is valid");

    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        sbuf_t        *buf = encodeOk(&config, kSides[s], inner, length, kFakeTcpHeaderWireRequiredPaddingLeft, false);
        const uint8_t *carrier = bufferBytes(buf);
        requireBytes(carrier + IP_HLEN + TCP_HLEN, inner, length, "intentional inner corruption was changed");
        require(oracleIpv4HeaderValid(carrier) && oracleTransportValid(carrier), "carrier checksums invalid");
        decodeOk(&config, peerSide(kSides[s]), buf, inner, length);
        require(! oracleIpv4HeaderValid(bufferBytes(buf)), "decode repaired an intentionally corrupt inner packet");
        sbufDestroy(buf);
    }
}

static void testRepair(void)
{
    const faketcpheader_wire_config_t config = baseConfig();
    uint8_t                           inner[128];
    const test_flow_t                 flow   = udpFlow(5555);
    const uint16_t                    length = buildInner(inner, &flow, 64);
    inner[10] ^= 0x11;
    inner[IP_HLEN + 6] ^= 0x22;
    require(GET_BE16(inner + IP_HLEN + 6) != 0 && ! oracleTransportValid(inner), "repair fixture is not dirty");

    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        sbuf_t        *buf = encodeOk(&config, kSides[s], inner, length, kFakeTcpHeaderWireRequiredPaddingLeft, true);
        const uint8_t *carrier  = bufferBytes(buf);
        const uint8_t *repaired = carrier + IP_HLEN + TCP_HLEN;
        require(oracleIpv4HeaderValid(repaired), "requested inner IPv4 checksum repair was ignored");
        require(oracleTransportValid(repaired), "requested inner UDP checksum repair was ignored");
        require(oracleIpv4HeaderValid(carrier) && oracleTransportValid(carrier), "carrier checksums invalid");
        sbufDestroy(buf);
    }

    /* A repair the checksum API refuses (UDP length beyond the packet) keeps the request. */
    uint8_t broken[128];
    memoryCopy(broken, inner, length);
    PUT_BE16(broken + IP_HLEN + 4, (uint16_t) (length + 4U));
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        expectRefusal(&config,
                      kSides[s],
                      true,
                      broken,
                      length,
                      kFakeTcpHeaderWireRequiredPaddingLeft,
                      true,
                      kFakeTcpHeaderWireInnerRepairFailed,
                      "unrepairable inner packet was accepted");
        sbuf_t *buf = encodeOk(&config, kSides[s], broken, length, kFakeTcpHeaderWireRequiredPaddingLeft, false);
        sbufDestroy(buf);
    }
}

/* Hand-built carrier: outer IHL 6 with an option word, then TCP with tcp_options bytes. */
static uint32_t buildOptionCarrier(uint8_t *out, const uint8_t *inner, uint16_t inner_length, uint16_t source_port,
                                   uint16_t destination_port, uint8_t tcp_options)
{
    const uint16_t ihl   = 24;
    const uint16_t tcp   = (uint16_t) (TCP_HLEN + tcp_options);
    const uint16_t total = (uint16_t) (ihl + tcp + inner_length);
    memoryZero(out, total);
    out[0] = 0x46;
    PUT_BE16(out + 2, total);
    PUT_BE16(out + 4, 0x7777);
    out[8] = 33;
    out[9] = kTestProtocolTcp;
    PUT_BE32(out + 12, 0xC0000201U);
    PUT_BE32(out + 16, 0xC0000202U);
    PUT_BE32(out + IP_HLEN, 0x94040000U);
    PUT_BE16(out + ihl, source_port);
    PUT_BE16(out + ihl + 2, destination_port);
    out[ihl + 12] = (uint8_t) ((tcp / 4U) << 4);
    out[ihl + 13] = 0x10;
    memset(out + ihl + TCP_HLEN, 0x01, tcp_options);
    memoryCopy(out + ihl + tcp, inner, inner_length);
    oracleSetChecksums(out);
    return total;
}

static void testOuterOptions(void)
{
    const faketcpheader_wire_config_t config = baseConfig();
    uint8_t                           inner[128];
    uint8_t                           carrier[256];
    const test_flow_t                 flow   = udpFlow(6000);
    const uint16_t                    length = buildInner(inner, &flow, 41);

    static const uint8_t tcp_options[] = {0, 8, 40};
    for (size_t i = 0; i < ARRAY_SIZE(tcp_options); ++i)
    {
        uint32_t carrier_length =
            buildOptionCarrier(carrier, inner, length, config.client_port + 3U, config.server_port, tcp_options[i]);
        sbuf_t *buf = makeBuffer(carrier, carrier_length, 0);
        decodeOk(&config, kFakeTcpHeaderWireServer, buf, inner, length);
        sbufDestroy(buf);

        carrier_length =
            buildOptionCarrier(carrier, inner, length, config.server_port, config.client_port + 15U, tcp_options[i]);
        buf = makeBuffer(carrier, carrier_length, 0);
        decodeOk(&config, kFakeTcpHeaderWireClient, buf, inner, length);
        sbufDestroy(buf);
    }
}

static void testLimitsAndRefusals(void)
{
    static uint8_t       inner[kTestPacketCapacity];
    static uint8_t       carrier[kTestPacketCapacity];
    static const uint8_t option_lengths[] = {0, 40};

    for (size_t o = 0; o < ARRAY_SIZE(option_lengths); ++o)
    {
        faketcpheader_wire_config_t config = baseConfig();
        setOptions(&config, option_lengths[o]);
        const uint16_t overhead = faketcpheaderWireOverhead(&config);
        const uint16_t maximum  = faketcpheaderWireMaxInnerLength(&config);
        require(overhead == 40U + option_lengths[o] && maximum == 1500U - overhead, "overhead helpers changed");
        const test_flow_t flow = udpFlow(9000);

        for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        {
            const faketcpheader_wire_side_t side   = kSides[s];
            uint16_t                        length = buildInner(inner, &flow, maximum);
            sbuf_t                         *buf    = encodeOk(&config, side, inner, length, overhead, false);
            TEST_EQUAL_UINT(TEST_FAILURE_EXIT, sbufGetLength(buf), 1500, "maximum inner did not fill 1500 bytes");
            require(sbufGetLeftCapacity(buf) == 0, "encode did not use exactly the overhead headroom");
            sbufDestroy(buf);

            /* Dirty inner checksums expose a repair performed before the size/headroom preflight. */
            length = buildInner(inner, &flow, (uint16_t) (maximum + 1U));
            inner[IP_HLEN + 6] ^= 0x5A;
            expectRefusalAnyIntent(
                &config, side, true, inner, length, overhead, kFakeTcpHeaderWireOversizedInner, "oversized inner");

            length = buildInner(inner, &flow, 100);
            inner[10] ^= 0x5A;
            expectRefusalAnyIntent(&config,
                                   side,
                                   true,
                                   inner,
                                   length,
                                   overhead - 1U,
                                   kFakeTcpHeaderWireMissingHeadroom,
                                   "missing headroom");
            expectRefusalAnyIntent(
                &config, side, true, inner, length - 1U, overhead, kFakeTcpHeaderWireMalformedInner, "truncated inner");
            expectRefusalAnyIntent(
                &config, side, true, inner, length + 3U, overhead, kFakeTcpHeaderWireMalformedInner, "trailing bytes");
            expectRefusalAnyIntent(
                &config, side, true, inner, IP_HLEN - 1U, overhead, kFakeTcpHeaderWireMalformedInner, "short inner");
            expectRefusalAnyIntent(
                &config, side, true, inner, 0, overhead, kFakeTcpHeaderWireMalformedInner, "empty inner");

            uint8_t ipv6[60] = {0x60, 0, 0, 0, 0, 20, kTestProtocolUdp, 64};
            expectRefusalAnyIntent(
                &config, side, true, ipv6, sizeof(ipv6), overhead, kFakeTcpHeaderWireMalformedInner, "IPv6 inner");

            uint8_t bad_ihl[64];
            memoryCopy(bad_ihl, inner, sizeof(bad_ihl));
            bad_ihl[0] = 0x44;
            expectRefusalAnyIntent(
                &config, side, true, bad_ihl, sizeof(bad_ihl), overhead, kFakeTcpHeaderWireMalformedInner, "IHL 4");
        }

        /* Decode refusals against a valid client carrier. */
        uint16_t       length         = buildInner(inner, &flow, 100);
        const uint32_t carrier_length = carrierOf(&config, kFakeTcpHeaderWireClient, inner, length, carrier);
        uint8_t        mutated[kTestPacketCapacity];

        const uint16_t fragment_fields[] = {0x2000, 0x0001, 0x4001, 0x6000};
        for (size_t f = 0; f < ARRAY_SIZE(fragment_fields); ++f)
        {
            memoryCopy(mutated, carrier, carrier_length);
            PUT_BE16(mutated + 6, fragment_fields[f]);
            oracleSetChecksums(mutated);
            expectRefusalAnyIntent(&config,
                                   kFakeTcpHeaderWireServer,
                                   false,
                                   mutated,
                                   carrier_length,
                                   0,
                                   kFakeTcpHeaderWireMalformedCarrier,
                                   "outer fragment");
        }

        memoryCopy(mutated, carrier, carrier_length);
        mutated[9] = kTestProtocolUdp;
        oracleSetChecksums(mutated);
        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireServer,
                               false,
                               mutated,
                               carrier_length,
                               0,
                               kFakeTcpHeaderWireMalformedCarrier,
                               "non-TCP carrier");

        static const uint8_t bad_offsets[] = {0x40, 0x00};
        for (size_t d = 0; d < ARRAY_SIZE(bad_offsets); ++d)
        {
            memoryCopy(mutated, carrier, carrier_length);
            mutated[IP_HLEN + 12] = bad_offsets[d];
            oracleSetChecksums(mutated);
            expectRefusalAnyIntent(&config,
                                   kFakeTcpHeaderWireServer,
                                   false,
                                   mutated,
                                   carrier_length,
                                   0,
                                   kFakeTcpHeaderWireMalformedCarrier,
                                   "TCP data offset below 20 bytes");
        }

        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireServer,
                               false,
                               carrier,
                               carrier_length - 1U,
                               0,
                               kFakeTcpHeaderWireMalformedCarrier,
                               "truncated carrier");
        memoryCopy(mutated, carrier, carrier_length);
        mutated[carrier_length] = 0;
        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireServer,
                               false,
                               mutated,
                               carrier_length + 1U,
                               0,
                               kFakeTcpHeaderWireMalformedCarrier,
                               "carrier with trailing bytes");
        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireServer,
                               false,
                               carrier,
                               IP_HLEN + TCP_HLEN - 1U,
                               0,
                               kFakeTcpHeaderWireMalformedCarrier,
                               "carrier shorter than its headers");
    }

    /* A carrier over 1500 bytes with otherwise valid fields. */
    faketcpheader_wire_config_t config = baseConfig();
    const test_flow_t           flow   = udpFlow(9100);
    const uint16_t              big    = buildInner(inner, &flow, 1500 - 40 + 1);
    uint32_t carrier_length = buildOptionCarrier(carrier, inner, big, config.client_port, config.server_port, 0);
    require(carrier_length == 1505, "oversized carrier fixture length");
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           carrier_length,
                           0,
                           kFakeTcpHeaderWireMalformedCarrier,
                           "carrier over 1500 bytes");

    /* Inner framing inside an otherwise valid carrier. */
    const uint16_t length = buildInner(inner, &flow, 90);
    PUT_BE16(inner + 2, (uint16_t) (length - 1U));
    carrier_length = buildOptionCarrier(carrier, inner, length, config.client_port, config.server_port, 0);
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           carrier_length,
                           0,
                           kFakeTcpHeaderWireInnerFraming,
                           "inner total length mismatch");
    carrier_length = buildOptionCarrier(carrier, inner, 0, config.client_port, config.server_port, 0);
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           carrier_length,
                           0,
                           kFakeTcpHeaderWireInnerFraming,
                           "empty carrier payload");
    carrier[IP_HLEN + 4 + 12] = 0xF0;
    oracleSetChecksums(carrier);
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           carrier_length,
                           0,
                           kFakeTcpHeaderWireMalformedCarrier,
                           "TCP data offset beyond the segment");
    uint8_t ipv6[48] = {0x60, 0, 0, 0, 0, 8, kTestProtocolUdp, 64};
    carrier_length   = buildOptionCarrier(carrier, ipv6, sizeof(ipv6), config.client_port, config.server_port, 0);
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           carrier_length,
                           0,
                           kFakeTcpHeaderWireInnerFraming,
                           "IPv6 carrier payload");
}

/* ---- Settings --------------------------------------------------------------------------------- */

static bool loadSettingsText(const char *text, faketcpheader_wire_config_t *out)
{
    cJSON *settings = cJSON_Parse(text);
    require(settings != NULL, "settings fixture JSON failed to parse");
    const bool loaded = faketcpheaderWireLoadSettings(settings, "FakeTcpHeaderTest", out);
    cJSON_Delete(settings);
    return loaded;
}

static void requireSettingsRejected(const char *text)
{
    faketcpheader_wire_config_t config;
    faketcpheader_wire_config_t sentinel;
    memset(&config, 0xA5, sizeof(config));
    memoryCopy(&sentinel, &config, sizeof(config));
    if (loadSettingsText(text, &config))
    {
        testRequireFailedAt(TEST_FAILURE_EXIT, text, "invalid settings were accepted", __FILE__, __LINE__);
    }
    requireBytes(&config, &sentinel, sizeof(config), "rejected settings changed the output");
}

static faketcpheader_wire_config_t requireSettingsLoaded(const char *text)
{
    faketcpheader_wire_config_t config = {0};
    if (! loadSettingsText(text, &config))
    {
        testRequireFailedAt(TEST_FAILURE_EXIT, text, "valid settings were rejected", __FILE__, __LINE__);
    }
    return config;
}

static void requireDefaults(const faketcpheader_wire_config_t *config)
{
    require(config->server_port == 40000 && config->client_port == 40001 && config->client_port_count == 16 &&
                config->sequence == 0 && config->acknowledgment == 0 && config->window == 65535 &&
                config->urgent_pointer == 0 && config->options_length == 0,
            "default settings changed");
}

static void testSettings(void)
{
    faketcpheader_wire_config_t config = {0};
    require(faketcpheaderWireLoadSettings(NULL, "FakeTcpHeaderTest", &config), "absent settings were rejected");
    requireDefaults(&config);
    config = requireSettingsLoaded("{}");
    requireDefaults(&config);

    config = requireSettingsLoaded("{\"server-port\":1,\"client-port\":2,\"client-port-count\":1,\"sequence\":0,"
                                   "\"acknowledgment\":0,\"window\":0,\"urgent-pointer\":0,\"options\":\"\"}");
    require(config.server_port == 1 && config.client_port == 2 && config.client_port_count == 1 && config.window == 0 &&
                config.options_length == 0,
            "lower edges were not loaded");

    config = requireSettingsLoaded(
        "{\"server-port\":65535,\"client-port\":63488,\"client-port-count\":1024,\"sequence\":4294967295,"
        "\"acknowledgment\":4294967295,\"window\":65535,\"urgent-pointer\":65535,"
        "\"options\":\"000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627\"}");
    require(config.server_port == 65535 && config.client_port == 63488 && config.client_port_count == 1024 &&
                config.sequence == UINT32_MAX && config.acknowledgment == UINT32_MAX && config.window == 65535 &&
                config.urgent_pointer == 65535 && config.options_length == 40,
            "upper edges were not loaded");
    for (uint8_t i = 0; i < 40; ++i)
    {
        require(config.options[i] == i, "options were not decoded verbatim");
    }

    config = requireSettingsLoaded("{\"client-port\":1,\"client-port-count\":1,\"server-port\":65535}");
    require(config.client_port == 1, "client-port 1 was not loaded");
    config = requireSettingsLoaded("{\"client-port\":65535,\"client-port-count\":1}");
    require(config.client_port == 65535 && config.client_port_count == 1, "client-port 65535 was not loaded");
    config = requireSettingsLoaded("{\"client-port\":65530,\"client-port-count\":6}");
    require(config.client_port_count == 6, "range ending at 65535 was not loaded");
    config = requireSettingsLoaded("{\"server-port\":40017,\"client-port\":40001,\"client-port-count\":16}");
    require(config.server_port == 40017, "server-port just above the client range was rejected");
    config = requireSettingsLoaded("{\"server-port\":40000,\"client-port\":40001,\"client-port-count\":16}");
    require(config.server_port == 40000, "server-port just below the client range was rejected");
    config = requireSettingsLoaded("{\"options\":\"020405B4\"}");
    require(config.options_length == 4 && config.options[0] == 0x02 && config.options[3] == 0xB4,
            "four option bytes were not loaded");

    static const char *const rejected[] = {
        "[]",
        "null",
        "1",
        "\"settings\"",
        "{\"role\":\"client\"}",
        "{\"protocol-number\":6}",
        "{\"flags\":24}",
        "{\"mtu\":1500}",
        "{\"local-ipv4\":\"192.0.2.1\"}",
        "{\"peer-ipv4\":\"192.0.2.2\"}",
        "{\"local-port\":40001}",
        "{\"peer-port\":40000}",
        "{\"unknown\":1}",
        "{\"window\\u0000x\":1}",
        "{\"server-port\":0}",
        "{\"server-port\":65536}",
        "{\"client-port\":0}",
        "{\"client-port\":65536}",
        "{\"client-port-count\":0}",
        "{\"client-port-count\":1025}",
        "{\"sequence\":-1}",
        "{\"sequence\":4294967296}",
        "{\"acknowledgment\":-1}",
        "{\"acknowledgment\":4294967296}",
        "{\"window\":-1}",
        "{\"window\":65536}",
        "{\"urgent-pointer\":-1}",
        "{\"urgent-pointer\":65536}",
        "{\"server-port\":1.5}",
        "{\"client-port\":40001.0}",
        "{\"window\":1e3}",
        "{\"server-port\":\"40000\"}",
        "{\"client-port\":true}",
        "{\"client-port-count\":[16]}",
        "{\"sequence\":{}}",
        "{\"server-port\":null}",
        "{\"client-port\":null}",
        "{\"client-port-count\":null}",
        "{\"sequence\":null}",
        "{\"acknowledgment\":null}",
        "{\"window\":null}",
        "{\"urgent-pointer\":null}",
        "{\"options\":null}",
        "{\"options\":1234}",
        "{\"options\":\"0101010\"}",
        "{\"options\":\"0101\"}",
        "{\"options\":\"010101010101\"}",
        "{\"options\":\"0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243\"}",
        "{\"options\":\"zz010101\"}",
        "{\"options\":\"0x010101\"}",
        "{\"options\":\"0101 101\"}",
        "{\"options\":\"0101\\u00000101\"}",
        "{\"server-port\":40001}",
        "{\"server-port\":40008}",
        "{\"server-port\":40016}",
        "{\"server-port\":5,\"client-port\":5,\"client-port-count\":1}",
        "{\"client-port\":65530,\"client-port-count\":7}",
        "{\"client-port\":65535,\"client-port-count\":2}",
        "{\"client-port\":64513,\"client-port-count\":1024}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        requireSettingsRejected(rejected[i]);
    }
}

int main(void)
{
    testCaseSet("fake_tcp_header_wire_test");
    initWLibc();
    checkSumInit();

    testResultNames();
    testKnownAnswer();
    testChecksumOracle();
    testOuterFields();
    testPortMapping();
    testDecodePortRules();
    testOuterIntegrity();
    testIntentionalCorruption();
    testRepair();
    testOuterOptions();
    testLimitsAndRefusals();
    testSettings();
    return 0;
}

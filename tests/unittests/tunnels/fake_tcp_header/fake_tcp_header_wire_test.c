/*
 * Covers: single-IPv4 FakeTcpHeader wire layout, native TCP/UDP checksum normalization, bounds and settings.
 * Contract: insert/remove only fake TCP after the actual IHL; preserve native checksum residuals and current IPs.
 * Every refusal preserves bytes including headroom, cursor, length and checksum intent.
 * Cases: known answers; both protocols/orientations; IHL/options/alignment matrix; address composition;
 * corruption, repair and checksum-zero representations; native/carrier framing, fragments, limits and settings.
 * Setup: in-memory sbufs with an independent RFC 1071 serializer/checksum oracle. No production checksum or
 * serialization helper constructs expected bytes. The node fixture covers actual callbacks and IpOverrider.
 * CTest: waterwall.fake_tcp_header_wire_unit (Debug and Release).
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
};

static const faketcpheader_wire_side_t kSides[]     = {kFakeTcpHeaderWireClient, kFakeTcpHeaderWireServer};
static const uint8_t                   kProtocols[] = {6, 17};

static faketcpheader_wire_side_t peerSide(faketcpheader_wire_side_t side)
{
    return side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer : kFakeTcpHeaderWireClient;
}

/* Independent RFC 1071 byte-oriented checksum oracle. */
static uint32_t oracleAdd(uint32_t sum, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i + 1 < length; i += 2)
        sum += ((uint32_t) bytes[i] << 8) | bytes[i + 1];
    if (length % 2 != 0)
        sum += (uint32_t) bytes[length - 1] << 8;
    return sum;
}

static uint16_t oracleFold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t) sum;
}

static uint16_t headerLength(const uint8_t *p)
{
    return (uint16_t) ((p[0] & 15U) * 4U);
}
static uint16_t totalLength(const uint8_t *p)
{
    return GET_BE16(p + 2);
}
static uint16_t checksumOffset(uint8_t protocol)
{
    return protocol == 6 ? 16 : 6;
}
static uint16_t nativeLength(const uint8_t *native, uint16_t available, uint8_t protocol)
{
    return protocol == 17 ? GET_BE16(native + 4) : available;
}

static uint16_t oracleResidual(const uint8_t *native, uint16_t available, uint8_t protocol, const uint8_t *addresses)
{
    const uint16_t length = nativeLength(native, available, protocol);
    uint32_t       sum    = protocol + length;
    if (addresses != NULL)
        sum = oracleAdd(sum, addresses, 8);
    return oracleFold(oracleAdd(sum, native, length));
}

static void oracleIpChecksum(uint8_t *p)
{
    PUT_BE16(p + 10, 0);
    PUT_BE16(p + 10, (uint16_t) ~oracleFold(oracleAdd(0, p, headerLength(p))));
}

static void oracleSetTransport(uint8_t *native, uint16_t available, uint8_t protocol, const uint8_t *addresses)
{
    PUT_BE16(native + checksumOffset(protocol), 0);
    uint16_t value = (uint16_t) ~oracleResidual(native, available, protocol, addresses);
    if (protocol == 17 && value == 0)
        value = 0xffffU;
    PUT_BE16(native + checksumOffset(protocol), value);
}

static void oracleSetChecksums(uint8_t *p)
{
    oracleIpChecksum(p);
    oracleSetTransport(p + headerLength(p), (uint16_t) (totalLength(p) - headerLength(p)), p[9], p + 12);
}

static bool oracleIpValid(const uint8_t *p)
{
    return oracleFold(oracleAdd(0, p, headerLength(p))) == 0xffffU;
}
static bool oracleTransportValid(const uint8_t *p)
{
    return oracleResidual(p + headerLength(p), (uint16_t) (totalLength(p) - headerLength(p)), p[9], p + 12) == 0xffffU;
}

/* Preserve the original residual, rather than repairing transport data. */
static void oracleAdjustAddresses(uint8_t *native, uint8_t protocol, const uint8_t *old_ips, const uint8_t *new_ips)
{
    const uint16_t old = GET_BE16(native + checksumOffset(protocol));
    if (protocol == 17 && old == 0)
        return;
    uint32_t sum = (uint16_t) ~old;
    for (size_t i = 0; i < 8; i += 2)
    {
        sum += old_ips == NULL ? 0xffffU : (uint16_t) ~GET_BE16(old_ips + i);
        sum += new_ips == NULL ? 0 : GET_BE16(new_ips + i);
    }
    uint16_t value = (uint16_t) ~oracleFold(sum);
    if (protocol == 17 && value == 0)
        value = 0xffffU;
    PUT_BE16(native + checksumOffset(protocol), value);
}

static faketcpheader_wire_config_t baseConfig(uint8_t protocol)
{
    return (faketcpheader_wire_config_t) {.sequence          = 0x01020304U,
                                          .acknowledgment    = 0x0a0b0c0dU,
                                          .window            = 29200,
                                          .urgent_pointer    = 7,
                                          .server_port       = 40000,
                                          .client_port       = 40001,
                                          .client_port_count = 16,
                                          .payload_protocol  = protocol};
}

static void setOptions(faketcpheader_wire_config_t *config, uint8_t length)
{
    config->options_length = length;
    for (uint8_t i = 0; i < length; ++i)
        config->options[i] = (uint8_t) (0xc0U + i);
}

static uint16_t buildNative(uint8_t *out, uint8_t protocol, uint8_t ihl, uint16_t length)
{
    const uint16_t minimum = (uint16_t) (ihl + (protocol == 6 ? 24 : 8));
    require(length >= minimum && length <= kTestPacketCapacity, "bad native fixture length");
    memoryZero(out, length);
    out[0] = (uint8_t) (0x40U | ihl / 4U);
    out[1] = 0xab;
    PUT_BE16(out + 2, length);
    PUT_BE16(out + 4, 0x1234);
    PUT_BE16(out + 6, 0x4000);
    out[8] = 47;
    out[9] = protocol;
    PUT_BE32(out + 12, 0x0a000001U);
    PUT_BE32(out + 16, 0x0a000002U);
    for (uint8_t i = 20; i < ihl; ++i)
        out[i] = (uint8_t) (0x80U + i);
    uint8_t *native = out + ihl;
    PUT_BE16(native, 5000);
    PUT_BE16(native + 2, 53);
    if (protocol == 6)
    {
        PUT_BE32(native + 4, 0x87654321U);
        PUT_BE32(native + 8, 0xfedcba98U);
        native[12] = 0x60;
        native[13] = 0x19;
        PUT_BE16(native + 14, 12345);
        PUT_BE16(native + 18, 17);
        PUT_BE32(native + 20, 0x01010101U);
    }
    else
        PUT_BE16(native + 4, (uint16_t) (length - ihl));
    for (uint16_t i = minimum; i < length; ++i)
        out[i] = (uint8_t) (i * 37U + length);
    oracleSetChecksums(out);
    return length;
}

/* Expected single-IP carrier from native bytes, independent of production serialization and checksum helpers. */
static uint16_t oracleCarrier(uint8_t *out, const uint8_t *packet, const faketcpheader_wire_config_t *config,
                              faketcpheader_wire_side_t side, uint16_t index)
{
    const uint16_t h = headerLength(packet), f = (uint16_t) (20U + config->options_length);
    const uint16_t length = totalLength(packet);
    memoryCopy(out, packet, h);
    memoryZero(out + h, f);
    memoryCopy(out + h + f, packet + h, length - h);
    oracleAdjustAddresses(out + h + f, config->payload_protocol, packet + 12, NULL);
    out[9] = 6;
    PUT_BE16(out + 2, (uint16_t) (length + f));
    uint8_t *tcp = out + h;
    PUT_BE16(tcp, side == kFakeTcpHeaderWireClient ? config->client_port + index : config->server_port);
    PUT_BE16(tcp + 2, side == kFakeTcpHeaderWireClient ? config->server_port : config->client_port + index);
    PUT_BE32(tcp + 4, config->sequence);
    PUT_BE32(tcp + 8, config->acknowledgment);
    tcp[12] = (uint8_t) ((f / 4U) << 4);
    tcp[13] = 0x18;
    PUT_BE16(tcp + 14, config->window);
    PUT_BE16(tcp + 18, config->urgent_pointer);
    memoryCopy(tcp + 20, config->options, config->options_length);
    oracleSetChecksums(out);
    return (uint16_t) (length + f);
}

static sbuf_t *makeBuffer(const uint8_t *bytes, uint32_t length, uint32_t headroom)
{
    sbuf_t *buf = sbufCreateWithPadding(headroom + length + 1U, 0);
    require(sbufGetLeftCapacity(buf) == 0, "fixture starts with unexpected headroom");
    sbufSetLength(buf, headroom + length);
    memset(sbufGetMutablePtr(buf), 0xa5, headroom + length);
    sbufShiftRight(buf, headroom);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    return buf;
}
static const uint8_t *bufferBytes(const sbuf_t *buf)
{
    return sbufGetRawPtr(buf);
}

static sbuf_t *encodeOk(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side,
                        const uint8_t *packet, uint32_t length, uint32_t headroom, bool repair)
{
    sbuf_t *buf = makeBuffer(packet, length, headroom);
    sbufSetRecalculateChecksum(buf, repair);
    requireResult(faketcpheaderWireEncode(config, side, buf), kFakeTcpHeaderWireOk, "valid native packet refused");
    require(! sbufGetRecalculateChecksum(buf), "encode did not consume checksum intent");
    return buf;
}
static void decodeOk(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side, sbuf_t *buf,
                     const uint8_t *expected, uint32_t length)
{
    requireResult(faketcpheaderWireDecode(config, side, buf), kFakeTcpHeaderWireOk, "valid carrier refused");
    require(! sbufGetRecalculateChecksum(buf), "decode did not consume checksum intent");
    requireResult(sbufGetLength(buf), length, "decoded length");
    if (expected != NULL)
        requireBytes(bufferBytes(buf), expected, length, "decoded native bytes");
}
static void expectRefusal(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side, bool encode,
                          const uint8_t *bytes, uint32_t length, uint32_t headroom, bool repair,
                          faketcpheader_wire_result_t expected, const char *message)
{
    sbuf_t *buf = makeBuffer(bytes, length, headroom);
    sbufSetRecalculateChecksum(buf, repair);
    uint8_t before[2 * kTestPacketCapacity];
    require(length + headroom <= sizeof(before), "oversized refusal fixture");
    const uint8_t *cursor = bufferBytes(buf);
    memoryCopy(before, cursor - headroom, length + headroom);
    requireResult(encode ? faketcpheaderWireEncode(config, side, buf) : faketcpheaderWireDecode(config, side, buf),
                  expected,
                  message);
    require(bufferBytes(buf) == cursor && sbufGetLength(buf) == length && sbufGetLeftCapacity(buf) == headroom,
            "refusal changed cursor/length/headroom");
    require(sbufGetRecalculateChecksum(buf) == repair, "refusal consumed checksum intent");
    requireBytes(cursor - headroom, before, length + headroom, "refusal changed bytes/headroom");
    sbufDestroy(buf);
}
static void expectRefusalAnyIntent(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side,
                                   bool encode, const uint8_t *bytes, uint32_t length, uint32_t headroom,
                                   faketcpheader_wire_result_t expected, const char *message)
{
    expectRefusal(config, side, encode, bytes, length, headroom, false, expected, message);
    expectRefusal(config, side, encode, bytes, length, headroom, true, expected, message);
}

static void testResultNames(void)
{
    const faketcpheader_wire_result_t results[] = {kFakeTcpHeaderWireOk,
                                                   kFakeTcpHeaderWireMalformedNative,
                                                   kFakeTcpHeaderWireNativeProtocol,
                                                   kFakeTcpHeaderWireFragmented,
                                                   kFakeTcpHeaderWireOversizedNative,
                                                   kFakeTcpHeaderWireMissingHeadroom,
                                                   kFakeTcpHeaderWireNativeRepairFailed,
                                                   kFakeTcpHeaderWireMalformedCarrier,
                                                   kFakeTcpHeaderWireCarrierPorts,
                                                   kFakeTcpHeaderWireCarrierChecksum,
                                                   kFakeTcpHeaderWireNativeFraming};
    for (size_t i = 0; i < ARRAY_SIZE(results); ++i)
    {
        const char *name = faketcpheaderWireResultName(results[i]);
        require(name != NULL && name[0] != '\0', "result has no diagnostic");
        for (size_t j = 0; j < i; ++j)
            require(strcmp(name, faketcpheaderWireResultName(results[j])) != 0, "result diagnostics collide");
    }
}

/* Fixed known answers calculated independently from network-byte-order field values. */
static const uint8_t kKnownNative6[]   = {0x46, 0xab, 0x00, 0x33, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xe2, 0x0a,
                                          0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x13, 0x88,
                                          0x00, 0x35, 0x87, 0x65, 0x43, 0x21, 0xfe, 0xdc, 0xba, 0x98, 0x60, 0x19, 0x30,
                                          0x39, 0xe2, 0x5a, 0x00, 0x11, 0x01, 0x01, 0x01, 0x01, 0x6b, 0x61, 0x74};
static const uint8_t kKnownCarrier60[] = {
    0x46, 0xab, 0x00, 0x4b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xca, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00,
    0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18,
    0x72, 0x10, 0xc5, 0x12, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x13, 0x88, 0x00, 0x35, 0x87, 0x65, 0x43, 0x21, 0xfe,
    0xdc, 0xba, 0x98, 0x60, 0x19, 0x30, 0x39, 0xf6, 0x5d, 0x00, 0x11, 0x01, 0x01, 0x01, 0x01, 0x6b, 0x61, 0x74};
static const uint8_t kKnownCarrier61[] = {
    0x46, 0xab, 0x00, 0x4b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xca, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00,
    0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18,
    0x72, 0x10, 0xc5, 0x12, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x13, 0x88, 0x00, 0x35, 0x87, 0x65, 0x43, 0x21, 0xfe,
    0xdc, 0xba, 0x98, 0x60, 0x19, 0x30, 0x39, 0xf6, 0x5d, 0x00, 0x11, 0x01, 0x01, 0x01, 0x01, 0x6b, 0x61, 0x74};
static const uint8_t kKnownNative17[]   = {0x46, 0xab, 0x00, 0x23, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x11, 0x21, 0xe7,
                                           0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01,
                                           0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0xf8, 0xb6, 0x6b, 0x61, 0x74};
static const uint8_t kKnownCarrier170[] = {0x46, 0xab, 0x00, 0x3b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xda,
                                           0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01,
                                           0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
                                           0x60, 0x18, 0x72, 0x10, 0xc5, 0x1d, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01,
                                           0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0x0c, 0xba, 0x6b, 0x61, 0x74};
static const uint8_t kKnownCarrier171[] = {0x46, 0xab, 0x00, 0x3b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xda,
                                           0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01,
                                           0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
                                           0x60, 0x18, 0x72, 0x10, 0xc5, 0x1d, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01,
                                           0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0x0c, 0xba, 0x6b, 0x61, 0x74};

static void testKnownAnswers(void)
{
    const struct
    {
        uint8_t                   protocol;
        faketcpheader_wire_side_t side;
        const uint8_t            *native;
        size_t                    length;
        const uint8_t            *carrier;
        size_t                    encoded;
    } cases[] = {
        {6, kFakeTcpHeaderWireClient, kKnownNative6, sizeof(kKnownNative6), kKnownCarrier60, sizeof(kKnownCarrier60)},
        {6, kFakeTcpHeaderWireServer, kKnownNative6, sizeof(kKnownNative6), kKnownCarrier61, sizeof(kKnownCarrier61)},
        {17,
         kFakeTcpHeaderWireClient,
         kKnownNative17,
         sizeof(kKnownNative17),
         kKnownCarrier170,
         sizeof(kKnownCarrier170)},
        {17,
         kFakeTcpHeaderWireServer,
         kKnownNative17,
         sizeof(kKnownNative17),
         kKnownCarrier171,
         sizeof(kKnownCarrier171)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        faketcpheader_wire_config_t config = baseConfig(cases[i].protocol);
        config.client_port_count           = 1;
        config.options_length              = 4;
        memset(config.options, 1, 4);
        sbuf_t *buf = encodeOk(&config, cases[i].side, cases[i].native, (uint32_t) cases[i].length, 24, false);
        requireResult(sbufGetLength(buf), cases[i].encoded, "known-answer length");
        requireBytes(bufferBytes(buf), cases[i].carrier, cases[i].encoded, "known-answer single-IP bytes");
        decodeOk(&config, peerSide(cases[i].side), buf, cases[i].native, (uint32_t) cases[i].length);
        sbufDestroy(buf);
    }
}

static void testWireAndMovement(void)
{
    const uint8_t ihls[] = {20, 24, 60}, options[] = {0, 4, 40};
    uint8_t       packet[kTestPacketCapacity], expected[kTestPacketCapacity];
    for (size_t p = 0; p < ARRAY_SIZE(kProtocols); ++p)
        for (size_t h = 0; h < ARRAY_SIZE(ihls); ++h)
            for (size_t o = 0; o < ARRAY_SIZE(options); ++o)
                for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
                {
                    faketcpheader_wire_config_t config = baseConfig(kProtocols[p]);
                    setOptions(&config, options[o]);
                    const uint16_t f       = (uint16_t) (20U + options[o]);
                    const uint16_t length  = buildNative(packet, kProtocols[p], ihls[h], (uint16_t) (ihls[h] + 43U));
                    const uint16_t index   = faketcpheaderWirePortIndex(&config, packet, length);
                    const uint16_t encoded = oracleCarrier(expected, packet, &config, kSides[s], index);
                    for (uint32_t alignment = 0; alignment < kTestAlignments; ++alignment)
                    {
                        sbuf_t *buf = encodeOk(&config, kSides[s], packet, length, f + alignment, false);
                        requireResult(sbufGetLength(buf), encoded, "single-header carrier length");
                        requireBytes(bufferBytes(buf), expected, encoded, "independent carrier serialization");
                        const uint8_t *carrier = bufferBytes(buf);
                        require(oracleIpValid(carrier) && oracleTransportValid(carrier),
                                "visible checksums fail oracle");
                        require(oracleResidual(carrier + ihls[h] + f, length - ihls[h], kProtocols[p], NULL) == 0xffffU,
                                "hidden native checksum was not normalized to zero addresses");
                        /* A peer's outgoing options do not control received data offset. */
                        faketcpheader_wire_config_t peer = config;
                        setOptions(&peer, options[(o + 1) % ARRAY_SIZE(options)]);
                        decodeOk(&peer, peerSide(kSides[s]), buf, packet, length);
                        sbufDestroy(buf);
                    }
                    expectRefusalAnyIntent(&config,
                                           kSides[s],
                                           true,
                                           packet,
                                           length,
                                           f - 1U,
                                           kFakeTcpHeaderWireMissingHeadroom,
                                           "one-byte-short headroom");
                }
}

static void testHeaderAndAddressComposition(void)
{
    uint8_t        packet[256], expected[256], addresses[8];
    const uint32_t source_cases[] = {0x0a000001U, 0, 0xc000020aU};
    const uint32_t dest_cases[]   = {0x0a000002U, 0, 0xc633640aU};
    for (size_t p = 0; p < ARRAY_SIZE(kProtocols); ++p)
        for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
            for (uint8_t ecn = 0; ecn < 4; ++ecn)
                for (size_t a = 0; a < ARRAY_SIZE(source_cases); ++a)
                    for (unsigned rewrite = 0; rewrite < 4; ++rewrite)
                    {
                        const faketcpheader_wire_config_t config = baseConfig(kProtocols[p]);
                        const uint16_t                    length = buildNative(packet, kProtocols[p], 60, 111);
                        PUT_BE32(packet + 12, source_cases[a]);
                        PUT_BE32(packet + 16, dest_cases[a]);
                        PUT_BE16(packet + 6, a % 2 ? 0 : 0x4000);
                        packet[1] = (uint8_t) (0xa8U | ecn);
                        oracleSetChecksums(packet);
                        sbuf_t  *buf     = encodeOk(&config, kSides[s], packet, length, 60, false);
                        uint8_t *carrier = sbufGetMutablePtr(buf);
                        memoryCopy(expected, packet, length);
                        memoryCopy(addresses, packet + 12, 8);
                        if (rewrite & 1U)
                            PUT_BE32(addresses, 0xcb007109U);
                        if (rewrite & 2U)
                            PUT_BE32(addresses + 4, 0xc6336407U);
                        memoryCopy(carrier + 12, addresses, 8);
                        memoryCopy(expected + 12, addresses, 8);
                        oracleAdjustAddresses(expected + 60, kProtocols[p], packet + 12, addresses);
                        /* Transit mutations must survive: this is the only IP header. */
                        carrier[8] -= 1;
                        carrier[1] ^= 3;
                        expected[8] -= 1;
                        expected[1] ^= 3;
                        oracleSetChecksums(carrier);
                        oracleIpChecksum(expected);
                        decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
                        require(oracleIpValid(bufferBytes(buf)) && oracleTransportValid(bufferBytes(buf)),
                                "restored native checksum does not use current addresses");
                        sbufDestroy(buf);
                    }
}

static void testCorruptionRepairAndZeros(void)
{
    uint8_t packet[128], expected[128], carrier[kTestPacketCapacity];
    for (size_t p = 0; p < ARRAY_SIZE(kProtocols); ++p)
        for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        {
            const faketcpheader_wire_config_t config = baseConfig(kProtocols[p]);
            const uint16_t                    h = 24, f = 20;
            const uint16_t                    length = buildNative(packet, kProtocols[p], h, 89);
            packet[h + checksumOffset(kProtocols[p])] ^= 0x5a;
            packet[10] ^= 0xa5;
            const uint16_t residual = oracleResidual(packet + h, length - h, kProtocols[p], packet + 12);
            require(residual != 0xffffU, "invalid native checksum fixture was valid");
            sbuf_t *buf = encodeOk(&config, kSides[s], packet, length, 60, false);
            require(oracleResidual(bufferBytes(buf) + h + f, length - h, kProtocols[p], NULL) == residual,
                    "normalization repaired native corruption");
            uint8_t *wire = sbufGetMutablePtr(buf);
            memoryCopy(expected, packet, length);
            PUT_BE32(wire + 12, 0xcb007101U);
            oracleAdjustAddresses(expected + h, kProtocols[p], expected + 12, wire + 12);
            memoryCopy(expected + 12, wire + 12, 8);
            oracleIpChecksum(expected);
            oracleSetChecksums(wire);
            decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
            require(oracleResidual(bufferBytes(buf) + h, length - h, kProtocols[p], bufferBytes(buf) + 12) == residual,
                    "address restoration repaired native corruption");
            sbufDestroy(buf);

            /* Repair native data before its checksum representation is normalized. */
            memoryCopy(expected, packet, length);
            oracleSetChecksums(expected);
            buf = encodeOk(&config, kSides[s], packet, length, 60, true);
            decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
            sbufDestroy(buf);

            /* Visible repair intent authorizes neither a hidden payload repair nor hidden checksum repair. */
            const uint16_t valid_length = buildNative(packet, kProtocols[p], h, 89);
            const uint16_t wire_length  = oracleCarrier(carrier, packet, &config, kSides[s], 3);
            carrier[h + f + 30] ^= 0x80;
            expectRefusal(&config,
                          peerSide(kSides[s]),
                          false,
                          carrier,
                          wire_length,
                          7,
                          false,
                          kFakeTcpHeaderWireCarrierChecksum,
                          "bad visible checksum");
            buf = makeBuffer(carrier, wire_length, 7);
            sbufSetRecalculateChecksum(buf, true);
            decodeOk(&config, peerSide(kSides[s]), buf, NULL, valid_length);
            require(! oracleTransportValid(bufferBytes(buf)), "carrier repair silently repaired hidden corruption");
            sbufDestroy(buf);

            /* Disabled UDP zero remains zero; TCP zero remains a participating checksum value. */
            buildNative(packet, kProtocols[p], h, 89);
            PUT_BE16(packet + h + checksumOffset(kProtocols[p]), 0);
            buf = encodeOk(&config, kSides[s], packet, length, 60, false);
            if (kProtocols[p] == 17)
                require(GET_BE16(bufferBytes(buf) + h + f + 6) == 0, "disabled UDP checksum enabled by normalization");
            else
                require(GET_BE16(bufferBytes(buf) + h + f + 16) != 0, "TCP zero mistaken for disabled checksum");
            decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
            sbufDestroy(buf);

            /* Choose a payload word that makes the normalized checksum arithmetic zero. */
            buildNative(packet, kProtocols[p], h, 90);
            uint8_t       *native    = packet + h;
            const uint16_t adjust_at = (uint16_t) (90 - h - 2);
            PUT_BE16(native + checksumOffset(kProtocols[p]), 0);
            PUT_BE16(native + adjust_at, 0);
            PUT_BE16(native + adjust_at, (uint16_t) ~oracleResidual(native, 90 - h, kProtocols[p], NULL));
            oracleSetTransport(native, 90 - h, kProtocols[p], packet + 12);
            buf                       = encodeOk(&config, kSides[s], packet, 90, 60, false);
            const uint16_t normalized = GET_BE16(bufferBytes(buf) + h + f + checksumOffset(kProtocols[p]));
            require(normalized == (kProtocols[p] == 17 ? 0xffffU : 0), "normalized arithmetic zero representation");
            decodeOk(&config, peerSide(kSides[s]), buf, NULL, 90);
            require(oracleTransportValid(bufferBytes(buf)), "zero-checksum restoration invalid");
            sbufDestroy(buf);
        }
}

static void testUdpPadding(void)
{
    uint8_t                           packet[100];
    const faketcpheader_wire_config_t config = baseConfig(17);
    buildNative(packet, 17, 24, sizeof(packet));
    PUT_BE16(packet + 24 + 4, 35); /* Trailing IP bytes are outside the UDP datagram checksum. */
    oracleSetChecksums(packet);
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        sbuf_t *buf = encodeOk(&config, kSides[s], packet, sizeof(packet), 60, false);
        require(oracleResidual(bufferBytes(buf) + 44, sizeof(packet) - 24, 17, NULL) == 0xffffU,
                "UDP normalization used padded IP payload length");
        decodeOk(&config, peerSide(kSides[s]), buf, packet, sizeof(packet));
        sbufDestroy(buf);
    }
}

static void testPortMapping(void)
{
    uint8_t        packet[100], reply[100];
    const uint16_t counts[] = {1, 2, 3, 16, 1024};
    for (size_t p = 0; p < ARRAY_SIZE(kProtocols); ++p)
        for (size_t c = 0; c < ARRAY_SIZE(counts); ++c)
        {
            faketcpheader_wire_config_t config = baseConfig(kProtocols[p]);
            config.client_port                 = 50000;
            config.client_port_count           = counts[c];
            for (unsigned i = 0; i < 32; ++i)
            {
                buildNative(packet, kProtocols[p], 20, sizeof(packet));
                PUT_BE16(packet + 20, (uint16_t) (1000 + i * 113));
                oracleSetChecksums(packet);
                memoryCopy(reply, packet, sizeof(reply));
                PUT_BE32(reply + 12, GET_BE32(packet + 16));
                PUT_BE32(reply + 16, GET_BE32(packet + 12));
                PUT_BE16(reply + 20, GET_BE16(packet + 22));
                PUT_BE16(reply + 22, GET_BE16(packet + 20));
                oracleSetChecksums(reply);
                const uint16_t index = faketcpheaderWirePortIndex(&config, packet, sizeof(packet));
                require(index < counts[c] && faketcpheaderWirePortIndex(&config, reply, sizeof(reply)) == index,
                        "reverse native flow did not retain carrier port index");
                for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
                {
                    sbuf_t *buf = encodeOk(&config, kSides[s], s == 0 ? packet : reply, sizeof(packet), 60, false);
                    const uint8_t *tcp = bufferBytes(buf) + 20;
                    require(GET_BE16(tcp + (s == 0 ? 0 : 2)) == config.client_port + index,
                            "carrier did not use native flow port mapping");
                    sbufDestroy(buf);
                }
            }
        }
}

static void testLimitsAndFraming(void)
{
    uint8_t       packet[kTestPacketCapacity], carrier[kTestPacketCapacity], bad[kTestPacketCapacity];
    const uint8_t options[] = {0, 40};
    for (size_t p = 0; p < ARRAY_SIZE(kProtocols); ++p)
        for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
            for (size_t o = 0; o < ARRAY_SIZE(options); ++o)
            {
                faketcpheader_wire_config_t config = baseConfig(kProtocols[p]);
                setOptions(&config, options[o]);
                const uint16_t f = (uint16_t) (20 + options[o]);
                require(faketcpheaderWireOverhead(&config) == f &&
                            faketcpheaderWireMaxNativeLength(&config) == 1500U - f,
                        "native MTU/overhead arithmetic");
                uint16_t length = buildNative(packet, kProtocols[p], 60, (uint16_t) (1500 - f));
                sbuf_t  *buf    = encodeOk(&config, kSides[s], packet, length, f, false);
                require(sbufGetLength(buf) == 1500 && sbufGetLeftCapacity(buf) == 0,
                        "exact carrier size/headroom limit");
                decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                sbufDestroy(buf);
                length = buildNative(packet, kProtocols[p], 20, (uint16_t) (1501 - f));
                expectRefusalAnyIntent(&config,
                                       kSides[s],
                                       true,
                                       packet,
                                       length,
                                       60,
                                       kFakeTcpHeaderWireOversizedNative,
                                       "one byte over final limit");
                const uint16_t large = oracleCarrier(carrier, packet, &config, kSides[s], 3);
                expectRefusalAnyIntent(&config,
                                       peerSide(kSides[s]),
                                       false,
                                       carrier,
                                       large,
                                       5,
                                       kFakeTcpHeaderWireMalformedCarrier,
                                       "oversized carrier");
                length                     = buildNative(packet, kProtocols[p], 20, 100);
                const uint16_t encoded     = oracleCarrier(carrier, packet, &config, kSides[s], 3);
                const uint16_t fragments[] = {0x2000, 0x2001, 0x0001};
                for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
                {
                    memoryCopy(bad, packet, length);
                    PUT_BE16(bad + 6, fragments[i]);
                    oracleIpChecksum(bad);
                    expectRefusalAnyIntent(&config,
                                           kSides[s],
                                           true,
                                           bad,
                                           length,
                                           60,
                                           kFakeTcpHeaderWireFragmented,
                                           "native first/middle/final fragment");
                    memoryCopy(bad, carrier, encoded);
                    PUT_BE16(bad + 6, fragments[i]);
                    oracleIpChecksum(bad);
                    expectRefusalAnyIntent(&config,
                                           peerSide(kSides[s]),
                                           false,
                                           bad,
                                           encoded,
                                           9,
                                           kFakeTcpHeaderWireFragmented,
                                           "carrier first/middle/final fragment");
                }
                /* Complete upstream-reassembled packets are accepted by the ordinary success matrix. */
                const uint16_t wrong_lengths[] = {0, 19, 99, 101};
                for (size_t i = 0; i < ARRAY_SIZE(wrong_lengths); ++i)
                    expectRefusalAnyIntent(&config,
                                           kSides[s],
                                           true,
                                           packet,
                                           wrong_lengths[i],
                                           60,
                                           kFakeTcpHeaderWireMalformedNative,
                                           "native truncation/trailing bytes");
                for (unsigned malformed = 0; malformed < 4; ++malformed)
                {
                    memoryCopy(bad, packet, length);
                    if (malformed == 0)
                        bad[0] = 0x60;
                    if (malformed == 1)
                        bad[0] = 0x44;
                    if (malformed == 2)
                        bad[0] = 0x4f; /* IHL leaves insufficient native TCP/UDP bytes below. */
                    if (malformed == 3)
                        PUT_BE16(bad + 2, 65535);
                    expectRefusalAnyIntent(&config,
                                           kSides[s],
                                           true,
                                           bad,
                                           malformed == 2 ? 60 : length,
                                           60,
                                           kFakeTcpHeaderWireMalformedNative,
                                           "native IP framing");
                }
                memoryCopy(bad, packet, length);
                bad[9] = kProtocols[1 - p];
                expectRefusalAnyIntent(&config,
                                       kSides[s],
                                       true,
                                       bad,
                                       length,
                                       60,
                                       kFakeTcpHeaderWireNativeProtocol,
                                       "native configured protocol mismatch");
                memoryCopy(bad, packet, length);
                bad[9] = 1;
                expectRefusalAnyIntent(&config,
                                       kSides[s],
                                       true,
                                       bad,
                                       length,
                                       60,
                                       kFakeTcpHeaderWireNativeProtocol,
                                       "unsupported native protocol");
                for (unsigned malformed = 0; malformed < 3; ++malformed)
                {
                    memoryCopy(bad, packet, length);
                    uint16_t malformed_length = length;
                    if (malformed == 0)
                    {
                        malformed_length = (uint16_t) (20 + (kProtocols[p] == 6 ? 19 : 7));
                        PUT_BE16(bad + 2, malformed_length);
                    }
                    else if (kProtocols[p] == 6)
                        bad[20 + 12] = malformed == 1 ? 0x40 : 0xf0;
                    else
                        PUT_BE16(bad + 20 + 4, malformed == 1 ? 7 : 81);
                    if (malformed == 2 && kProtocols[p] == 6)
                    {
                        malformed_length = 60;
                        PUT_BE16(bad + 2, malformed_length);
                    }
                    expectRefusalAnyIntent(&config,
                                           kSides[s],
                                           true,
                                           bad,
                                           malformed_length,
                                           60,
                                           kFakeTcpHeaderWireMalformedNative,
                                           "invalid native transport");
                    /* Construct malformed hidden native data with a valid visible fake checksum. */
                    const uint16_t malformed_wire = (uint16_t) (malformed_length + f);
                    memoryCopy(bad, carrier, 20 + f);
                    memoryCopy(bad + 20 + f, packet + 20, malformed_length - 20);
                    PUT_BE16(bad + 2, malformed_wire);
                    if (malformed != 0 && kProtocols[p] == 6)
                        bad[20 + f + 12] = malformed == 1 ? 0x40 : 0xf0;
                    if (malformed != 0 && kProtocols[p] == 17)
                        PUT_BE16(bad + 20 + f + 4, malformed == 1 ? 7 : 81);
                    oracleSetChecksums(bad);
                    expectRefusalAnyIntent(&config,
                                           peerSide(kSides[s]),
                                           false,
                                           bad,
                                           malformed_wire,
                                           11,
                                           kFakeTcpHeaderWireNativeFraming,
                                           "malformed hidden native data");
                }
                for (unsigned malformed = 0; malformed < 9; ++malformed)
                {
                    memoryCopy(bad, carrier, encoded + 1U);
                    uint16_t bad_length = encoded;
                    if (malformed == 0)
                        bad[0] = 0x44;
                    if (malformed == 1)
                        bad[9] = 17;
                    if (malformed == 2)
                        PUT_BE16(bad + 2, (uint16_t) (encoded - 1));
                    if (malformed == 3)
                        bad_length--;
                    if (malformed == 4)
                        bad_length++;
                    if (malformed == 5)
                        bad[20 + 12] = 0x40;
                    if (malformed == 6)
                    {
                        bad[20 + 12] = 0xf0;
                        bad_length   = 50;
                        PUT_BE16(bad + 2, bad_length);
                    }
                    if (malformed == 7)
                        bad[0] = 0x6f;
                    if (malformed == 8)
                        bad_length = 19;
                    expectRefusalAnyIntent(&config,
                                           peerSide(kSides[s]),
                                           false,
                                           bad,
                                           bad_length,
                                           13,
                                           kFakeTcpHeaderWireMalformedCarrier,
                                           "invalid carrier geometry");
                }
                /* No hidden native bytes; fake TCP geometry remains valid. */
                memoryCopy(bad, carrier, 20 + f);
                PUT_BE16(bad + 2, (uint16_t) (20 + f));
                oracleSetChecksums(bad);
                expectRefusalAnyIntent(&config,
                                       peerSide(kSides[s]),
                                       false,
                                       bad,
                                       20 + f,
                                       0,
                                       kFakeTcpHeaderWireNativeFraming,
                                       "missing hidden native transport");
                const uint16_t client_ports[] = {config.client_port,
                                                 (uint16_t) (config.client_port + 15),
                                                 (uint16_t) (config.client_port - 1),
                                                 (uint16_t) (config.client_port + 16)};
                for (size_t c = 0; c < ARRAY_SIZE(client_ports); ++c)
                {
                    memoryCopy(bad, carrier, encoded);
                    PUT_BE16(bad + 20 + (s == 0 ? 0 : 2), client_ports[c]);
                    oracleSetChecksums(bad);
                    if (c < 2)
                    {
                        buf = makeBuffer(bad, encoded, 0);
                        decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                        sbufDestroy(buf);
                    }
                    else
                        expectRefusalAnyIntent(&config,
                                               peerSide(kSides[s]),
                                               false,
                                               bad,
                                               encoded,
                                               0,
                                               kFakeTcpHeaderWireCarrierPorts,
                                               "client port range");
                }
                memoryCopy(bad, carrier, encoded);
                PUT_BE16(bad + 20 + (s == 0 ? 2 : 0), 39999);
                oracleSetChecksums(bad);
                expectRefusalAnyIntent(&config,
                                       peerSide(kSides[s]),
                                       false,
                                       bad,
                                       encoded,
                                       0,
                                       kFakeTcpHeaderWireCarrierPorts,
                                       "server port mismatch");
                expectRefusalAnyIntent(&config,
                                       kSides[s],
                                       false,
                                       carrier,
                                       encoded,
                                       0,
                                       kFakeTcpHeaderWireCarrierPorts,
                                       "own carrier direction accepted");
                const uint16_t corrupt_offsets[] = {10, 20 + 16};
                for (size_t c = 0; c < ARRAY_SIZE(corrupt_offsets); ++c)
                {
                    memoryCopy(bad, carrier, encoded);
                    bad[corrupt_offsets[c]] ^= 1;
                    expectRefusal(&config,
                                  peerSide(kSides[s]),
                                  false,
                                  bad,
                                  encoded,
                                  0,
                                  false,
                                  kFakeTcpHeaderWireCarrierChecksum,
                                  "invalid visible checksum");
                    buf = makeBuffer(bad, encoded, 0);
                    sbufSetRecalculateChecksum(buf, true);
                    decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                    sbufDestroy(buf);
                }
            }
}
/* ---- Settings --------------------------------------------------------------------------------- */

static bool loadSettingsText(const char *text, faketcpheader_wire_config_t *out)
{
    cJSON *settings = text != NULL ? cJSON_Parse(text) : NULL;
    require(text == NULL || settings != NULL, "settings fixture JSON failed to parse");
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
        testRequireFailedAt(TEST_FAILURE_EXIT,
                            text != NULL ? text : "NULL settings",
                            "invalid settings were accepted",
                            __FILE__,
                            __LINE__);
    }
    requireBytes(&config, &sentinel, sizeof(config), "rejected settings changed the output");
}

static faketcpheader_wire_config_t requireSettingsLoaded(const char *text)
{
    faketcpheader_wire_config_t config = {0};
    if (! loadSettingsText(text, &config))
    {
        testRequireFailedAt(TEST_FAILURE_EXIT,
                            text != NULL ? text : "NULL settings",
                            "valid settings were rejected",
                            __FILE__,
                            __LINE__);
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
    requireSettingsRejected(NULL);
    requireSettingsRejected("{}");
    config = requireSettingsLoaded("{\"payload-protocol\":6}");
    require(config.payload_protocol == 6, "native TCP setting was not loaded");
    requireDefaults(&config);
    config = requireSettingsLoaded("{\"payload-protocol\":17}");
    require(config.payload_protocol == 17, "native UDP setting was not loaded");
    requireDefaults(&config);

    config = requireSettingsLoaded(
        "{\"payload-protocol\":17,\"server-port\":1,\"client-port\":2,\"client-port-count\":1,\"sequence\":0,"
        "\"acknowledgment\":0,\"window\":0,\"urgent-pointer\":0,\"options\":\"\"}");
    require(config.server_port == 1 && config.client_port == 2 && config.client_port_count == 1 && config.window == 0 &&
                config.options_length == 0,
            "lower edges were not loaded");

    config = requireSettingsLoaded(
        "{\"payload-protocol\":17,\"server-port\":65535,\"client-port\":63488,\"client-port-count\":1024,\"sequence\":"
        "4294967295,"
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

    config = requireSettingsLoaded(
        "{\"payload-protocol\":17,\"client-port\":1,\"client-port-count\":1,\"server-port\":65535}");
    require(config.client_port == 1, "client-port 1 was not loaded");
    config = requireSettingsLoaded("{\"payload-protocol\":17,\"client-port\":65535,\"client-port-count\":1}");
    require(config.client_port == 65535 && config.client_port_count == 1, "client-port 65535 was not loaded");
    config = requireSettingsLoaded("{\"payload-protocol\":17,\"client-port\":65530,\"client-port-count\":6}");
    require(config.client_port_count == 6, "range ending at 65535 was not loaded");
    config = requireSettingsLoaded(
        "{\"payload-protocol\":17,\"server-port\":40017,\"client-port\":40001,\"client-port-count\":16}");
    require(config.server_port == 40017, "server-port just above the client range was rejected");
    config = requireSettingsLoaded(
        "{\"payload-protocol\":17,\"server-port\":40000,\"client-port\":40001,\"client-port-count\":16}");
    require(config.server_port == 40000, "server-port just below the client range was rejected");
    config = requireSettingsLoaded("{\"payload-protocol\":17,\"options\":\"020405B4\"}");
    require(config.options_length == 4 && config.options[0] == 0x02 && config.options[3] == 0xB4,
            "four option bytes were not loaded");

    static const char *const rejected[] = {
        "{\"payload-protocol\":null}",
        "{\"payload-protocol\":6.5}",
        "{\"payload-protocol\":6.0}",
        "{\"payload-protocol\":6e0}",
        "{\"payload-protocol\":7}",
        "{\"payload-protocol\":16}",
        "{\"window\":1}",
        "{\"payload-protocol\":\"17\"}",
        "{\"payload-protocol\":true}",
        "{\"payload-protocol\":false}",
        "{\"payload-protocol\":-1}",
        "{\"payload-protocol\":0}",
        "{\"payload-protocol\":1}",
        "{\"payload-protocol\":256}",
        "{\"payload-protocol\":4294967296}",
        "[]",
        "null",
        "1",
        "\"settings\"",
        "{\"payload-protocol\":17,\"role\":\"client\"}",
        "{\"payload-protocol\":17,\"protocol-number\":6}",
        "{\"payload-protocol\":17,\"flags\":24}",
        "{\"payload-protocol\":17,\"mtu\":1500}",
        "{\"payload-protocol\":17,\"local-ipv4\":\"192.0.2.1\"}",
        "{\"payload-protocol\":17,\"peer-ipv4\":\"192.0.2.2\"}",
        "{\"payload-protocol\":17,\"local-port\":40001}",
        "{\"payload-protocol\":17,\"peer-port\":40000}",
        "{\"payload-protocol\":17,\"unknown\":1}",
        "{\"payload-protocol\":17,\"window\\u0000x\":1}",
        "{\"payload-protocol\":17,\"server-port\":0}",
        "{\"payload-protocol\":17,\"server-port\":65536}",
        "{\"payload-protocol\":17,\"client-port\":0}",
        "{\"payload-protocol\":17,\"client-port\":65536}",
        "{\"payload-protocol\":17,\"client-port-count\":0}",
        "{\"payload-protocol\":17,\"client-port-count\":1025}",
        "{\"payload-protocol\":17,\"sequence\":-1}",
        "{\"payload-protocol\":17,\"sequence\":4294967296}",
        "{\"payload-protocol\":17,\"acknowledgment\":-1}",
        "{\"payload-protocol\":17,\"acknowledgment\":4294967296}",
        "{\"payload-protocol\":17,\"window\":-1}",
        "{\"payload-protocol\":17,\"window\":65536}",
        "{\"payload-protocol\":17,\"urgent-pointer\":-1}",
        "{\"payload-protocol\":17,\"urgent-pointer\":65536}",
        "{\"payload-protocol\":17,\"server-port\":1.5}",
        "{\"payload-protocol\":17,\"client-port\":40001.0}",
        "{\"payload-protocol\":17,\"window\":1e3}",
        "{\"payload-protocol\":17,\"server-port\":\"40000\"}",
        "{\"payload-protocol\":17,\"client-port\":true}",
        "{\"payload-protocol\":17,\"client-port-count\":[16]}",
        "{\"payload-protocol\":17,\"sequence\":{}}",
        "{\"payload-protocol\":17,\"server-port\":null}",
        "{\"payload-protocol\":17,\"client-port\":null}",
        "{\"payload-protocol\":17,\"client-port-count\":null}",
        "{\"payload-protocol\":17,\"sequence\":null}",
        "{\"payload-protocol\":17,\"acknowledgment\":null}",
        "{\"payload-protocol\":17,\"window\":null}",
        "{\"payload-protocol\":17,\"urgent-pointer\":null}",
        "{\"payload-protocol\":17,\"options\":null}",
        "{\"payload-protocol\":17,\"options\":1234}",
        "{\"payload-protocol\":17,\"options\":\"0101010\"}",
        "{\"payload-protocol\":17,\"options\":\"0101\"}",
        "{\"payload-protocol\":17,\"options\":\"010101010101\"}",
        "{\"payload-protocol\":17,\"options\":"
        "\"0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243\"}",
        "{\"payload-protocol\":17,\"options\":\"zz010101\"}",
        "{\"payload-protocol\":17,\"options\":\"0x010101\"}",
        "{\"payload-protocol\":17,\"options\":\"0101 101\"}",
        "{\"payload-protocol\":17,\"options\":\"0101\\u00000101\"}",
        "{\"payload-protocol\":17,\"server-port\":40001}",
        "{\"payload-protocol\":17,\"server-port\":40008}",
        "{\"payload-protocol\":17,\"server-port\":40016}",
        "{\"payload-protocol\":17,\"server-port\":5,\"client-port\":5,\"client-port-count\":1}",
        "{\"payload-protocol\":17,\"client-port\":65530,\"client-port-count\":7}",
        "{\"payload-protocol\":17,\"client-port\":65535,\"client-port-count\":2}",
        "{\"payload-protocol\":17,\"client-port\":64513,\"client-port-count\":1024}",
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
    TEST_RUN_CASE(testResultNames);
    TEST_RUN_CASE(testKnownAnswers);
    TEST_RUN_CASE(testWireAndMovement);
    TEST_RUN_CASE(testHeaderAndAddressComposition);
    TEST_RUN_CASE(testCorruptionRepairAndZeros);
    TEST_RUN_CASE(testUdpPadding);
    TEST_RUN_CASE(testPortMapping);
    TEST_RUN_CASE(testLimitsAndFraming);
    TEST_RUN_CASE(testSettings);
    return 0;
}

/*
 * Covers: single-IPv4 FakeTcpHeader protocol tag, TCP/UDP normalization, ICMP/opaque carriage, bounds and settings.
 * Contract: insert/remove fake TCP and the protocol byte after the actual IHL; preserve native checksum residuals and
 * current IPs. Every refusal preserves bytes including headroom, cursor, length and checksum intent. Cases: known
 * answers; both protocols/orientations; IHL/options/alignment matrix; address composition; corruption, repair and
 * checksum-zero representations; native/carrier framing, fragments, limits and settings; per-port sequence progression,
 * wrap, numeric/random-node/random-port seeds, disabled mode, independent fixed/random ACK modes, and four concurrent
 * encoders reserving nonoverlapping sequence intervals and independent ACK counters with wrap, fixed or random ACKs.
 * Setup: in-memory sbufs with an independent RFC 1071 serializer/checksum oracle. No production checksum or
 * serialization helper constructs expected bytes. The node fixture covers actual callbacks and IpOverrider. CTest:
 * waterwall.fake_tcp_header_wire_unit (Debug and Release). Every refusal also preserves the outgoing sequence counters.
 * A Linux linker wrapper verifies exact random draws for ACK cases, including zero/MAX and no draws on rejection.
 */
#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

#include "test_assert.h"
#include "wthread.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#define requireResult(actual, expected, message)                                                                       \
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, (uintmax_t) (actual), (uintmax_t) (expected), message)
#define requireBytes(actual, expected, size, message)                                                                  \
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, actual, expected, size, message)

/* Only ACK-specific cases replace the RNG; ordinary and concurrent coverage use the real generator. */
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
static bool     deterministic_random;
static uint32_t random_draws;

uint32_t __real_fastRand32(void);
uint32_t __wrap_fastRand32(void);

static uint32_t expectedRandomDraw(uint32_t index)
{
    if (index == 0)
        return 0;
    if (index == 1)
        return UINT32_MAX;
    return 0x3579bdf0U + index * 0x10203041U;
}

uint32_t __wrap_fastRand32(void)
{
    return deterministic_random ? expectedRandomDraw(random_draws++) : __real_fastRand32();
}
#endif

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
    return protocol == 6 ? 16 : protocol == 17 ? 6 : 2;
}
static uint16_t nativeLength(const uint8_t *native, uint16_t available, uint8_t protocol)
{
    return protocol == 17 ? GET_BE16(native + 4) : available;
}

static uint16_t oracleResidual(const uint8_t *native, uint16_t available, uint8_t protocol, const uint8_t *addresses)
{
    const uint16_t length = nativeLength(native, available, protocol);
    uint32_t       sum    = protocol == 1 ? 0 : protocol + length;
    if (protocol != 1 && addresses != NULL)
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
    if (p[9] == 1 || p[9] == 6 || p[9] == 17)
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

static faketcpheader_wire_config_t baseConfig(void)
{
    return (faketcpheader_wire_config_t) {.sequence_mode      = kFakeTcpHeaderFieldNumeric,
                                          .sequence           = 0x01020304U,
                                          .acknowledgment     = 0x0a0b0c0dU,
                                          .window             = 29200,
                                          .urgent_pointer     = 7,
                                          .server_port        = 40000,
                                          .client_port        = 40001,
                                          .client_port_count  = 16,
                                          .increment_sequence = false};
}

static void setOptions(faketcpheader_wire_config_t *config, uint8_t length)
{
    config->options_length = length;
    for (uint8_t i = 0; i < length; ++i)
        config->options[i] = (uint8_t) (0xc0U + i);
}

static uint16_t buildNative(uint8_t *out, uint8_t protocol, uint8_t ihl, uint16_t length)
{
    const uint16_t minimum = (uint16_t) (ihl + (protocol == 6 ? 24 : protocol == 1 || protocol == 17 ? 8 : 0));
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
    if (protocol == 6 || protocol == 17)
    {
        PUT_BE16(native, 5000);
        PUT_BE16(native + 2, 53);
    }
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
    else if (protocol == 17)
        PUT_BE16(native + 4, (uint16_t) (length - ihl));
    else if (protocol == 1)
    {
        native[0] = 8; /* Echo request, no IPv4-address pseudo-header. */
        PUT_BE16(native + 4, 0x1234);
        PUT_BE16(native + 6, 7);
    }
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
    out[h + f] = packet[9];
    memoryCopy(out + h + f + 1, packet + h, length - h);
    if (packet[9] == 6 || packet[9] == 17)
        oracleAdjustAddresses(out + h + f + 1, packet[9], packet + 12, NULL);
    out[9] = 6;
    PUT_BE16(out + 2, (uint16_t) (length + f + 1));
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
    return (uint16_t) (length + f + 1);
}

static sbuf_t *makeBuffer(const uint8_t *bytes, uint32_t length, uint32_t headroom)
{
    sbuf_t *buf = sbufCreateWithPadding(headroom + length, 0);
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
    requireResult(
        faketcpheaderWireEncode(config, NULL, side, buf), kFakeTcpHeaderWireOk, "valid native packet refused");
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
    faketcpheader_wire_config_t advancing = *config;
    advancing.increment_sequence          = true;
    advancing.increment_acknowledgment    = true;
    atomic_u32_t sequences[2 * kFakeTcpHeaderWireMaxClientPortCount];
    faketcpheaderWireInitState(&advancing, sequences);
    requireResult(encode ? faketcpheaderWireEncode(&advancing, sequences, side, buf)
                         : faketcpheaderWireDecode(config, side, buf),
                  expected,
                  message);
    require(bufferBytes(buf) == cursor && sbufGetLength(buf) == length && sbufGetLeftCapacity(buf) == headroom,
            "refusal changed cursor/length/headroom");
    require(sbufGetRecalculateChecksum(buf) == repair, "refusal consumed checksum intent");
    requireBytes(cursor - headroom, before, length + headroom, "refusal changed bytes/headroom");
    for (uint16_t i = 0; i < config->client_port_count; ++i)
    {
        requireResult(atomicLoadU32Relaxed(&sequences[i]), config->sequence, "refusal advanced a sequence counter");
        requireResult(atomicLoadU32Relaxed(&sequences[config->client_port_count + i]),
                      config->acknowledgment,
                      "refusal advanced an ACK counter");
    }
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
    0x46, 0xab, 0x00, 0x4c, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xc9, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00,
    0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18,
    0x72, 0x10, 0xdf, 0xf0, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x06, 0x13, 0x88, 0x00, 0x35, 0x87, 0x65, 0x43, 0x21,
    0xfe, 0xdc, 0xba, 0x98, 0x60, 0x19, 0x30, 0x39, 0xf6, 0x5d, 0x00, 0x11, 0x01, 0x01, 0x01, 0x01, 0x6b, 0x61, 0x74,
};
static const uint8_t kKnownCarrier61[] = {
    0x46, 0xab, 0x00, 0x4c, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xc9, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00,
    0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18,
    0x72, 0x10, 0xdf, 0xf0, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x06, 0x13, 0x88, 0x00, 0x35, 0x87, 0x65, 0x43, 0x21,
    0xfe, 0xdc, 0xba, 0x98, 0x60, 0x19, 0x30, 0x39, 0xf6, 0x5d, 0x00, 0x11, 0x01, 0x01, 0x01, 0x01, 0x6b, 0x61, 0x74,
};
static const uint8_t kKnownNative17[]   = {0x46, 0xab, 0x00, 0x23, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x11, 0x21, 0xe7,
                                           0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01,
                                           0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0xf8, 0xb6, 0x6b, 0x61, 0x74};
static const uint8_t kKnownCarrier170[] = {
    0x46, 0xab, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xd9, 0x0a, 0x00, 0x00,
    0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02,
    0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18, 0x72, 0x10, 0xd0, 0x00, 0x00, 0x07, 0x01,
    0x01, 0x01, 0x01, 0x11, 0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0x0c, 0xba, 0x6b, 0x61, 0x74,
};
static const uint8_t kKnownCarrier171[] = {
    0x46, 0xab, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xd9, 0x0a, 0x00, 0x00,
    0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02,
    0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18, 0x72, 0x10, 0xd0, 0x00, 0x00, 0x07, 0x01,
    0x01, 0x01, 0x01, 0x11, 0x13, 0x88, 0x00, 0x35, 0x00, 0x0b, 0x0c, 0xba, 0x6b, 0x61, 0x74,
};

static const uint8_t kKnownNative1[] = {
    0x46, 0xab, 0x00, 0x24, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x01, 0x21, 0xf6, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0x06, 0x63, 0x12, 0x34, 0x00, 0x07, 0x6b, 0x61, 0x74, 0x00,
};
static const uint8_t kKnownCarrier1_0[] = {
    0x46, 0xab, 0x00, 0x3d, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xd8, 0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04,
    0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18, 0x72, 0x10, 0xc3, 0xff, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x08, 0x00, 0x06, 0x63, 0x12, 0x34, 0x00, 0x07, 0x6b, 0x61, 0x74, 0x00,
};
static const uint8_t kKnownCarrier1_1[] = {
    0x46, 0xab, 0x00, 0x3d, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xd8, 0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04,
    0x0a, 0x0b, 0x0c, 0x0d, 0x60, 0x18, 0x72, 0x10, 0xc3, 0xff, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x08, 0x00, 0x06, 0x63, 0x12, 0x34, 0x00, 0x07, 0x6b, 0x61, 0x74, 0x00,
};
static const uint8_t kKnownNative0[] = {
    0x46, 0xab, 0x00, 0x1b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x00, 0x22, 0x00, 0x0a, 0x00,
    0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00, 0xff, 0x6b,
};
static const uint8_t kKnownCarrier0_0[] = {
    0x46, 0xab, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xe1, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xc5, 0x9c, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0xff, 0x6b,
};
static const uint8_t kKnownCarrier0_1[] = {
    0x46, 0xab, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xe1, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xc5, 0x9c, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0xff, 0x6b,
};
static const uint8_t kKnownNative255[] = {
    0x46, 0xab, 0x00, 0x1b, 0x12, 0x34, 0x40, 0x00, 0x2f, 0xff, 0x21, 0x01, 0x0a, 0x00,
    0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00, 0xff, 0x6b,
};
static const uint8_t kKnownCarrier255_0[] = {
    0x46, 0xab, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xe1, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x41, 0x9c, 0x40, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xc6, 0x9b, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0xff, 0x00, 0xff, 0x6b,
};
static const uint8_t kKnownCarrier255_1[] = {
    0x46, 0xab, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x2f, 0x06, 0x21, 0xe1, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x9c, 0x40, 0x9c, 0x41, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x60, 0x18, 0x72, 0x10, 0xc6, 0x9b, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0xff, 0x00, 0xff, 0x6b,
};

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
        {1, kFakeTcpHeaderWireClient, kKnownNative1, sizeof(kKnownNative1), kKnownCarrier1_0, sizeof(kKnownCarrier1_0)},
        {1, kFakeTcpHeaderWireServer, kKnownNative1, sizeof(kKnownNative1), kKnownCarrier1_1, sizeof(kKnownCarrier1_1)},
        {0, kFakeTcpHeaderWireClient, kKnownNative0, sizeof(kKnownNative0), kKnownCarrier0_0, sizeof(kKnownCarrier0_0)},
        {0, kFakeTcpHeaderWireServer, kKnownNative0, sizeof(kKnownNative0), kKnownCarrier0_1, sizeof(kKnownCarrier0_1)},
        {255,
         kFakeTcpHeaderWireClient,
         kKnownNative255,
         sizeof(kKnownNative255),
         kKnownCarrier255_0,
         sizeof(kKnownCarrier255_0)},
        {255,
         kFakeTcpHeaderWireServer,
         kKnownNative255,
         sizeof(kKnownNative255),
         kKnownCarrier255_1,
         sizeof(kKnownCarrier255_1)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        faketcpheader_wire_config_t config = baseConfig();
        config.client_port_count           = 1;
        config.options_length              = 4;
        memset(config.options, 1, 4);
        sbuf_t *buf = encodeOk(&config, cases[i].side, cases[i].native, (uint32_t) cases[i].length, 25, false);
        requireResult(sbufGetLength(buf), cases[i].encoded, "known-answer length");
        requireBytes(bufferBytes(buf), cases[i].carrier, cases[i].encoded, "known-answer single-IP bytes");
        decodeOk(&config, peerSide(cases[i].side), buf, cases[i].native, (uint32_t) cases[i].length);
        sbufDestroy(buf);
    }
}

static void testWireAndMovement(void)
{
    const uint8_t protocols[] = {6, 17, 1, 0, 255, 253};
    const uint8_t ihls[] = {20, 24, 60}, options[] = {0, 4, 40};
    uint8_t       packet[kTestPacketCapacity], expected[kTestPacketCapacity];
    for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
        for (size_t h = 0; h < ARRAY_SIZE(ihls); ++h)
            for (size_t o = 0; o < ARRAY_SIZE(options); ++o)
                for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
                {
                    faketcpheader_wire_config_t config = baseConfig();
                    setOptions(&config, options[o]);
                    const uint16_t overhead = (uint16_t) (21U + options[o]);
                    const uint16_t length   = buildNative(packet, protocols[p], ihls[h], (uint16_t) (ihls[h] + 43U));
                    const uint16_t index    = faketcpheaderWirePortIndex(&config, packet, length);
                    const uint16_t encoded  = oracleCarrier(expected, packet, &config, kSides[s], index);
                    for (uint32_t alignment = 0; alignment < kTestAlignments; ++alignment)
                    {
                        sbuf_t *buf = encodeOk(&config, kSides[s], packet, length, overhead + alignment, false);
                        requireResult(sbufGetLength(buf), encoded, "single-header carrier length");
                        requireBytes(bufferBytes(buf), expected, encoded, "independent carrier serialization");
                        const uint8_t *carrier = bufferBytes(buf);
                        require(oracleIpValid(carrier) && oracleTransportValid(carrier),
                                "visible checksums fail oracle");
                        require(carrier[ihls[h] + overhead - 1] == protocols[p],
                                "protocol tag is not after actual fake TCP header");
                        require((uint16_t) ((carrier[ihls[h] + 12] >> 4U) * 4U) == overhead - 1,
                                "protocol tag counted in TCP data offset");
                        if (protocols[p] == 6 || protocols[p] == 17)
                            require(oracleResidual(
                                        carrier + ihls[h] + overhead, length - ihls[h], protocols[p], NULL) == 0xffffU,
                                    "hidden native checksum was not normalized to zero addresses");
                        else
                            requireBytes(carrier + ihls[h] + overhead,
                                         packet + ihls[h],
                                         length - ihls[h],
                                         "ICMP/opaque body changed while encoding");
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
                                           overhead - 1U,
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
                        const faketcpheader_wire_config_t config = baseConfig();
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
            const faketcpheader_wire_config_t config = baseConfig();
            const uint16_t                    h = 24, overhead = 21;
            const uint16_t                    length = buildNative(packet, kProtocols[p], h, 89);
            packet[h + checksumOffset(kProtocols[p])] ^= 0x5a;
            packet[10] ^= 0xa5;
            const uint16_t residual = oracleResidual(packet + h, length - h, kProtocols[p], packet + 12);
            require(residual != 0xffffU, "invalid native checksum fixture was valid");
            sbuf_t *buf = encodeOk(&config, kSides[s], packet, length, 60, false);
            require(oracleResidual(bufferBytes(buf) + h + overhead, length - h, kProtocols[p], NULL) == residual,
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
            carrier[h + overhead + 30] ^= 0x80;
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
                require(GET_BE16(bufferBytes(buf) + h + overhead + 6) == 0,
                        "disabled UDP checksum enabled by normalization");
            else
                require(GET_BE16(bufferBytes(buf) + h + overhead + 16) != 0, "TCP zero mistaken for disabled checksum");
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
            const uint16_t normalized = GET_BE16(bufferBytes(buf) + h + overhead + checksumOffset(kProtocols[p]));
            require(normalized == (kProtocols[p] == 17 ? 0xffffU : 0), "normalized arithmetic zero representation");
            decodeOk(&config, peerSide(kSides[s]), buf, NULL, 90);
            require(oracleTransportValid(bufferBytes(buf)), "zero-checksum restoration invalid");
            sbufDestroy(buf);
        }
}

static void testUdpPadding(void)
{
    uint8_t                           packet[100];
    const faketcpheader_wire_config_t config = baseConfig();
    buildNative(packet, 17, 24, sizeof(packet));
    PUT_BE16(packet + 24 + 4, 35); /* Trailing IP bytes are outside the UDP datagram checksum. */
    oracleSetChecksums(packet);
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        sbuf_t *buf = encodeOk(&config, kSides[s], packet, sizeof(packet), 60, false);
        require(oracleResidual(bufferBytes(buf) + 45, sizeof(packet) - 24, 17, NULL) == 0xffffU,
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
            faketcpheader_wire_config_t config = baseConfig();
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

static void testSequenceProgression(void)
{
    const uint8_t protocols[] = {6, 17, 1, 253};
    const uint8_t ihls[] = {20, 24, 60}, options[] = {0, 4, 40};
    uint8_t       packet[256], expected[256];
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        faketcpheader_wire_config_t config = baseConfig();
        config.increment_sequence          = true;
        config.client_port_count           = 1;
        config.sequence                    = UINT32_MAX - 17U;
        atomic_u32_t sequences[1];
        faketcpheaderWireInitState(&config, sequences);
        uint32_t next = config.sequence;
        for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
            for (size_t h = 0; h < ARRAY_SIZE(ihls); ++h)
                for (size_t o = 0; o < ARRAY_SIZE(options); ++o)
                {
                    setOptions(&config, options[o]);
                    const uint16_t length = buildNative(packet, protocols[p], ihls[h], (uint16_t) (ihls[h] + 43U));
                    if (protocols[p] == 17)
                    {
                        /* Bytes beyond the UDP length still consume outer TCP sequence space. */
                        PUT_BE16(packet + ihls[h] + 4, 11);
                        oracleSetChecksums(packet);
                    }
                    faketcpheader_wire_config_t oracle = config;
                    oracle.sequence                    = next;
                    const uint16_t encoded             = oracleCarrier(expected, packet, &oracle, kSides[s], 0);
                    sbuf_t        *buf                 = makeBuffer(packet, length, faketcpheaderWireOverhead(&config));
                    sbufSetRecalculateChecksum(buf, (p + h + o) % 2 != 0);
                    requireResult(faketcpheaderWireEncode(&config, sequences, kSides[s], buf),
                                  kFakeTcpHeaderWireOk,
                                  "incrementing encoder refused valid packet");
                    requireBytes(
                        bufferBytes(buf), expected, encoded, "sequence/checksum differs from independent oracle");
                    next += 44U;
                    requireResult(
                        atomicLoadU32Relaxed(sequences), next, "sequence counted IP or fake TCP header bytes");
                    decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                    requireResult(atomicLoadU32Relaxed(sequences), next, "decode changed outgoing sequence");
                    sbufDestroy(buf);
                }

        /* An empty opaque native body still contributes its one protocol byte. */
        const uint16_t length = buildNative(packet, 253, 20, 20);
        sbuf_t        *buf    = makeBuffer(packet, length, 61);
        requireResult(faketcpheaderWireEncode(&config, sequences, kSides[s], buf),
                      kFakeTcpHeaderWireOk,
                      "empty opaque packet refused");
        requireResult(GET_BE32(bufferBytes(buf) + 24), next, "empty body sequence");
        requireResult(atomicLoadU32Relaxed(sequences), next + 1U, "protocol byte did not consume sequence space");
        require(oracleIpValid(bufferBytes(buf)) && oracleTransportValid(bufferBytes(buf)), "sequence broke checksum");
        sbufDestroy(buf);

        config.increment_sequence = false;
        faketcpheaderWireInitState(&config, NULL);
        for (unsigned i = 0; i < 3; ++i)
        {
            buf = encodeOk(&config, kSides[s], packet, length, 61, false);
            requireResult(GET_BE32(bufferBytes(buf) + 24), config.sequence, "disabled mode advanced sequence");
            requireResult(GET_BE32(bufferBytes(buf) + 28), config.acknowledgment, "disabled mode changed ACK");
            require(oracleTransportValid(bufferBytes(buf)), "fixed sequence broke checksum");
            sbufDestroy(buf);
        }
    }
}

static void testSequencePortIsolation(void)
{
    uint8_t packet[80];
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
    {
        faketcpheader_wire_config_t config = baseConfig();
        config.increment_sequence          = true;
        config.client_port_count           = 3;
        atomic_u32_t sequences[3];
        uint32_t     next[3] = {config.sequence, config.sequence, config.sequence};
        unsigned     seen[3] = {0};
        faketcpheaderWireInitState(&config, sequences);
        for (unsigned flow = 0; flow < 64; ++flow)
        {
            buildNative(packet, 17, 20, sizeof(packet));
            PUT_BE16(packet + 20, (uint16_t) (5000U + flow));
            oracleSetChecksums(packet);
            const uint16_t index = faketcpheaderWirePortIndex(&config, packet, sizeof(packet));
            sbuf_t        *buf   = makeBuffer(packet, sizeof(packet), 61);
            requireResult(faketcpheaderWireEncode(&config, sequences, kSides[s], buf),
                          kFakeTcpHeaderWireOk,
                          "port isolation fixture encode");
            const uint8_t *tcp = bufferBytes(buf) + 20;
            requireResult(GET_BE16(tcp + (s == 0 ? 0 : 2)), config.client_port + index, "selected client port changed");
            requireResult(GET_BE32(tcp + 4), next[index], "colliding flows did not share their port counter");
            requireResult(GET_BE32(tcp + 8), config.acknowledgment, "sequence progression changed ACK");
            next[index] += 61U;
            ++seen[index];
            for (unsigned i = 0; i < ARRAY_SIZE(next); ++i)
                requireResult(atomicLoadU32Relaxed(&sequences[i]), next[i], "another port's counter was changed");
            require(oracleTransportValid(bufferBytes(buf)), "per-port sequence broke checksum");
            sbufDestroy(buf);
        }
        for (unsigned i = 0; i < ARRAY_SIZE(seen); ++i)
            require(seen[i] > 1, "fixture did not exercise independent ports and colliding flows");
    }
}

static void testRandomSequenceModes(void)
{
    const faketcpheader_field_mode_t modes[] = {kFakeTcpHeaderFieldRandomNode, kFakeTcpHeaderFieldRandomPort};
    uint8_t                          packet[80], expected[160];
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (size_t m = 0; m < ARRAY_SIZE(modes); ++m)
            for (unsigned increment = 0; increment < 2; ++increment)
            {
                faketcpheader_wire_config_t config = baseConfig();
                config.sequence_mode               = modes[m];
                config.increment_sequence          = increment != 0;
                config.client_port_count           = 3;
                atomic_u32_t  sequences[3];
                atomic_u32_t *state = faketcpheaderWireNeedsSequences(&config) ? sequences : NULL;
                faketcpheaderWireInitState(&config, state);
                uint32_t next[3];
                unsigned seen[3] = {0};
                for (unsigned i = 0; i < ARRAY_SIZE(next); ++i)
                {
                    next[i] = state != NULL ? atomicLoadU32Relaxed(&state[i]) : config.sequence;
                    if (config.sequence_mode == kFakeTcpHeaderFieldRandomNode)
                        requireResult(next[i], config.sequence, "random_node did not share one starting value");
                }
                /* Observe generated seeds, then check exact progression without assuming random values differ. */
                for (unsigned flow = 0; flow < 64; ++flow)
                {
                    buildNative(packet, 17, 20, sizeof(packet));
                    PUT_BE16(packet + 20, (uint16_t) (5000U + flow));
                    oracleSetChecksums(packet);
                    const uint16_t              index  = faketcpheaderWirePortIndex(&config, packet, sizeof(packet));
                    faketcpheader_wire_config_t oracle = config;
                    oracle.sequence                    = next[index];
                    const uint16_t encoded             = oracleCarrier(expected, packet, &oracle, kSides[s], index);
                    sbuf_t        *buf                 = makeBuffer(packet, sizeof(packet), 61);
                    requireResult(faketcpheaderWireEncode(&config, state, kSides[s], buf),
                                  kFakeTcpHeaderWireOk,
                                  "random sequence fixture encode");
                    requireBytes(bufferBytes(buf), expected, encoded, "random sequence or carrier checksum changed");
                    if (increment != 0)
                        next[index] += 61U;
                    ++seen[index];
                    decodeOk(&config, peerSide(kSides[s]), buf, packet, sizeof(packet));
                    sbufDestroy(buf);
                    if (state != NULL)
                        for (unsigned i = 0; i < ARRAY_SIZE(next); ++i)
                            requireResult(atomicLoadU32Relaxed(&state[i]),
                                          next[i],
                                          "random mode changed another port or a fixed seed");
                }
                for (unsigned i = 0; i < ARRAY_SIZE(seen); ++i)
                    require(seen[i] > 1, "random mode fixture did not exercise all port slots repeatedly");

                /* Refusals must neither draw replacement seeds nor consume byte intervals. */
                sbuf_t *buf = makeBuffer(packet, 1, 61);
                requireResult(faketcpheaderWireEncode(&config, state, kSides[s], buf),
                              kFakeTcpHeaderWireMalformedNative,
                              "random mode accepted malformed input");
                if (state != NULL)
                    for (unsigned i = 0; i < ARRAY_SIZE(next); ++i)
                        requireResult(atomicLoadU32Relaxed(&state[i]), next[i], "refusal changed a random sequence");
                else
                    requireResult(config.sequence, next[0], "refusal changed the fixed node seed");
                sbufDestroy(buf);
            }
}

static void testAcknowledgmentModes(void)
{
    const faketcpheader_field_mode_t sequence_modes[] = {
        kFakeTcpHeaderFieldNumeric, kFakeTcpHeaderFieldRandomNode, kFakeTcpHeaderFieldRandomPort};
    const faketcpheader_field_mode_t acknowledgment_modes[] = {kFakeTcpHeaderFieldNumeric,
                                                               kFakeTcpHeaderFieldRandomNode,
                                                               kFakeTcpHeaderFieldRandomPort,
                                                               kFakeTcpHeaderFieldRandomPacket};
    uint8_t                          packet[80], expected[160];
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (size_t q = 0; q < ARRAY_SIZE(sequence_modes); ++q)
            for (size_t a = 0; a < ARRAY_SIZE(acknowledgment_modes); ++a)
                for (unsigned increment = 0; increment < 2; ++increment)
                    for (unsigned ack_increment = 0;
                         ack_increment < (acknowledgment_modes[a] == kFakeTcpHeaderFieldRandomPacket ? 1U : 2U);
                         ++ack_increment)
                    {
                        faketcpheader_wire_config_t config = baseConfig();
                        config.sequence_mode               = sequence_modes[q];
                        config.acknowledgment_mode         = acknowledgment_modes[a];
                        config.increment_sequence          = increment != 0;
                        config.increment_acknowledgment    = ack_increment != 0;
                        config.acknowledgment              = UINT32_MAX - 1U;
                        config.client_port_count           = 3;
                        const bool seq_storage             = faketcpheaderWireNeedsSequences(&config);
                        const bool ack_random_port = config.acknowledgment_mode == kFakeTcpHeaderFieldRandomPort;
                        const bool ack_storage     = config.increment_acknowledgment || ack_random_port;
                        require(faketcpheaderWireNeedsAcknowledgments(&config) == ack_storage,
                                "ACK storage requirement does not match selected mode and increment flag");
                        const unsigned ack_offset     = seq_storage ? config.client_port_count : 0;
                        const unsigned expected_count = config.client_port_count * (seq_storage + ack_storage);
                        requireResult(faketcpheaderWireStateCount(&config), expected_count, "incorrect ACK state size");
                        atomic_u32_t  values[6];
                        atomic_u32_t *state = expected_count != 0 ? values : NULL;
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                        deterministic_random = true;
                        random_draws         = 0;
#endif
                        faketcpheaderWireInitState(&config, state);
                        uint32_t next[3], acknowledgments[3];
                        for (unsigned i = 0; i < 3; ++i)
                        {
                            next[i] = seq_storage ? atomicLoadU32Relaxed(&state[i]) : config.sequence;
                            acknowledgments[i] =
                                ack_storage ? atomicLoadU32Relaxed(&state[ack_offset + i]) : config.acknowledgment;
                            if (config.acknowledgment_mode == kFakeTcpHeaderFieldNumeric ||
                                config.acknowledgment_mode == kFakeTcpHeaderFieldRandomNode)
                                requireResult(acknowledgments[i],
                                              config.acknowledgment,
                                              "ACK counter did not use configured starting value");
                        }
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                        const unsigned seq_draws = config.sequence_mode == kFakeTcpHeaderFieldRandomNode   ? 1U
                                                   : config.sequence_mode == kFakeTcpHeaderFieldRandomPort ? 3U
                                                                                                           : 0U;
                        const unsigned ack_draws = config.acknowledgment_mode == kFakeTcpHeaderFieldRandomNode ? 1U
                                                   : ack_random_port                                           ? 3U
                                                                                                               : 0U;
                        requireResult(
                            random_draws, seq_draws + ack_draws, "initialization drew the wrong number of seeds");
                        for (unsigned i = 0; i < 3; ++i)
                        {
                            if (config.sequence_mode != kFakeTcpHeaderFieldNumeric)
                                requireResult(
                                    next[i],
                                    expectedRandomDraw(config.sequence_mode == kFakeTcpHeaderFieldRandomPort ? i : 0),
                                    "sequence initialization used the wrong draw");
                            if (config.acknowledgment_mode == kFakeTcpHeaderFieldRandomNode || ack_random_port)
                                requireResult(acknowledgments[i],
                                              expectedRandomDraw(seq_draws + (ack_random_port ? i : 0)),
                                              "ACK did not draw independently from sequence");
                        }
#endif
                        faketcpheader_wire_config_t initialized;
                        memoryCopy(&initialized, &config, sizeof(config));
                        unsigned seen[3] = {0};
                        for (unsigned flow = 0; flow < 64; ++flow)
                        {
                            buildNative(packet, 17, 20, sizeof(packet));
                            PUT_BE16(packet + 20, (uint16_t) (5000U + flow));
                            oracleSetChecksums(packet);
                            const uint16_t index = faketcpheaderWirePortIndex(&config, packet, sizeof(packet));
                            sbuf_t        *buf   = makeBuffer(packet, sizeof(packet), 61);
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                            const uint32_t draws_before = random_draws;
#endif
                            requireResult(faketcpheaderWireEncode(&config, state, kSides[s], buf),
                                          kFakeTcpHeaderWireOk,
                                          "ACK mode refused valid native packet");
                            faketcpheader_wire_config_t oracle = config;
                            oracle.sequence                    = next[index];
                            oracle.acknowledgment              = acknowledgments[index];
                            if (config.acknowledgment_mode == kFakeTcpHeaderFieldRandomPacket)
                            {
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                                oracle.acknowledgment = expectedRandomDraw(draws_before);
#else
                                oracle.acknowledgment = GET_BE32(bufferBytes(buf) + 28);
#endif
                            }
                            const uint16_t encoded = oracleCarrier(expected, packet, &oracle, kSides[s], index);
                            requireBytes(bufferBytes(buf),
                                         expected,
                                         encoded,
                                         "ACK field or dependent checksum differs from oracle");
                            if (config.increment_sequence)
                                next[index] += 61U;
                            if (config.increment_acknowledgment)
                                ++acknowledgments[index];
                            ++seen[index];
                            /* Decode must not interpret the ACK using its own independently configured value or mode.
                             */
                            faketcpheader_wire_config_t peer = config;
                            peer.acknowledgment_mode         = kFakeTcpHeaderFieldNumeric;
                            peer.acknowledgment              = ~oracle.acknowledgment;
                            decodeOk(&peer, peerSide(kSides[s]), buf, packet, sizeof(packet));
                            sbufDestroy(buf);
                            for (unsigned i = 0; i < 3; ++i)
                            {
                                if (seq_storage)
                                    requireResult(atomicLoadU32Relaxed(&state[i]),
                                                  next[i],
                                                  "ACK mode changed sequence progression");
                                if (ack_storage)
                                    requireResult(atomicLoadU32Relaxed(&state[ack_offset + i]),
                                                  acknowledgments[i],
                                                  "ACK progression changed another port, used the wrong step, or "
                                                  "advanced on decode");
                            }
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                            requireResult(random_draws,
                                          draws_before +
                                              (config.acknowledgment_mode == kFakeTcpHeaderFieldRandomPacket),
                                          "encode or decode consumed an unexpected random draw");
#endif
                        }
                        for (unsigned i = 0; i < 3; ++i)
                            require(seen[i] > 1, "ACK fixture did not exercise every client port repeatedly");
                        requireBytes(
                            &config, &initialized, sizeof(config), "packet processing modified field configuration");

                        /* A rejected packet cannot advance sequence state, replace fixed ACKs or draw a packet ACK. */
                        for (unsigned refusal = 0; refusal < 3; ++refusal)
                        {
                            buildNative(packet, 17, 20, sizeof(packet));
                            if (refusal == 1)
                                PUT_BE16(packet + 6, 0x2000);
                            const uint32_t length   = refusal == 0 ? 1U : sizeof(packet);
                            const uint32_t headroom = refusal == 2 ? 0U : 61U;
                            sbuf_t        *buf      = makeBuffer(packet, length, headroom);
                            sbufSetRecalculateChecksum(buf, true);
                            const uint8_t *before_cursor = bufferBytes(buf);
                            uint8_t        before[sizeof(packet) + 61];
                            memoryCopy(before, before_cursor - headroom, length + headroom);
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                            const uint32_t draws_before = random_draws;
#endif
                            const faketcpheader_wire_result_t result = refusal == 0 ? kFakeTcpHeaderWireMalformedNative
                                                                       : refusal == 1
                                                                           ? kFakeTcpHeaderWireFragmented
                                                                           : kFakeTcpHeaderWireMissingHeadroom;
                            requireResult(faketcpheaderWireEncode(&config, state, kSides[s], buf),
                                          result,
                                          "ACK mode accepted invalid native packet");
                            require(bufferBytes(buf) == before_cursor && sbufGetLength(buf) == length &&
                                        sbufGetLeftCapacity(buf) == headroom && sbufGetRecalculateChecksum(buf),
                                    "ACK refusal changed buffer geometry or checksum intent");
                            requireBytes(before_cursor - headroom,
                                         before,
                                         length + headroom,
                                         "ACK refusal changed packet bytes");
                            for (unsigned i = 0; i < 3; ++i)
                            {
                                if (seq_storage)
                                    requireResult(
                                        atomicLoadU32Relaxed(&state[i]), next[i], "refusal advanced sequence state");
                                if (ack_storage)
                                    requireResult(atomicLoadU32Relaxed(&state[ack_offset + i]),
                                                  acknowledgments[i],
                                                  "refusal advanced or changed a per-port ACK");
                            }
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                            requireResult(random_draws, draws_before, "refusal drew a random ACK");
#endif
                            sbufDestroy(buf);
                        }
#if FAKE_TCP_HEADER_RANDOM_FIXTURE
                        deterministic_random = false;
#endif
                    }
}

enum
{
    kSequenceThreads          = 4,
    kSequencePacketsPerThread = 128,
    kSequencePayloadLength    = 40,
};

typedef struct sequence_thread_s
{
    const faketcpheader_wire_config_t *config;
    atomic_u32_t                      *sequences;
    faketcpheader_wire_side_t          side;
    wsem_t                            *ready;
    wsem_t                            *start;
    sbuf_t                            *packets[kSequencePacketsPerThread];
} sequence_thread_t;

static WTHREAD_ROUTINE(encodeConcurrentPackets)
{
    sequence_thread_t *task = userdata;
    discard            semaphorePost(task->ready);
    discard            semaphoreWait(task->start);
    for (unsigned i = 0; i < kSequencePacketsPerThread; ++i)
        requireResult(faketcpheaderWireEncode(task->config, task->sequences, task->side, task->packets[i]),
                      kFakeTcpHeaderWireOk,
                      "concurrent encoder refused valid packet");
    frandThreadCleanup();
    return 0;
}

static void testConcurrentSequences(void)
{
    const faketcpheader_field_mode_t ack_modes[] = {kFakeTcpHeaderFieldNumeric,
                                                    kFakeTcpHeaderFieldRandomNode,
                                                    kFakeTcpHeaderFieldRandomPort,
                                                    kFakeTcpHeaderFieldRandomPacket};
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (size_t a = 0; a < ARRAY_SIZE(ack_modes); ++a)
            for (unsigned ack_increment = 0;
                 ack_increment < (ack_modes[a] == kFakeTcpHeaderFieldRandomPacket ? 1U : 2U);
                 ++ack_increment)
            {
                faketcpheader_wire_config_t config = baseConfig();
                config.increment_sequence          = true;
                config.increment_acknowledgment    = ack_increment != 0;
                config.acknowledgment              = UINT32_MAX - 3U;
                config.acknowledgment_mode         = ack_modes[a];
                config.client_port_count           = 1;
                atomic_u32_t sequences[2];
                faketcpheaderWireInitState(&config, sequences);
                const uint32_t acknowledgment = faketcpheaderWireNeedsAcknowledgments(&config)
                                                    ? atomicLoadU32Relaxed(&sequences[1])
                                                    : config.acknowledgment;
                uint8_t        packet[20 + kSequencePayloadLength - 1];
                buildNative(packet, 17, 20, sizeof(packet));
                wsem_t ready, start;
                semaphoreInit(&ready, 0);
                semaphoreInit(&start, 0);
                sequence_thread_t tasks[kSequenceThreads];
                wthread_t         threads[kSequenceThreads];
                for (unsigned t = 0; t < kSequenceThreads; ++t)
                {
                    tasks[t] = (sequence_thread_t) {
                        .config = &config, .sequences = sequences, .side = kSides[s], .ready = &ready, .start = &start};
                    for (unsigned p = 0; p < kSequencePacketsPerThread; ++p)
                        tasks[t].packets[p] = makeBuffer(packet, sizeof(packet), 61);
                    requireResult(threadCreate(&threads[t], encodeConcurrentPackets, &tasks[t]),
                                  kWThreadErrorNone,
                                  "failed to create sequence encoder thread");
                }
                for (unsigned t = 0; t < kSequenceThreads; ++t)
                    discard semaphoreWait(&ready);
                for (unsigned t = 0; t < kSequenceThreads; ++t)
                    discard semaphorePost(&start);
                for (unsigned t = 0; t < kSequenceThreads; ++t)
                    requireResult(threadJoin(threads[t]), 0, "failed to join sequence encoder thread");

                bool seen[kSequenceThreads * kSequencePacketsPerThread]     = {false};
                bool ack_seen[kSequenceThreads * kSequencePacketsPerThread] = {false};
                for (unsigned t = 0; t < kSequenceThreads; ++t)
                    for (unsigned p = 0; p < kSequencePacketsPerThread; ++p)
                    {
                        sbuf_t        *buf     = tasks[t].packets[p];
                        const uint8_t *carrier = bufferBytes(buf);
                        const uint32_t offset  = GET_BE32(carrier + 24) - config.sequence;
                        require(offset % kSequencePayloadLength == 0, "concurrent sequence interval is misaligned");
                        const uint32_t slot = offset / kSequencePayloadLength;
                        require(slot < ARRAY_SIZE(seen) && ! seen[slot], "concurrent sequence intervals overlap");
                        seen[slot] = true;
                        if (config.increment_acknowledgment)
                        {
                            const uint32_t ack_slot = GET_BE32(carrier + 28) - acknowledgment;
                            require(ack_slot < ARRAY_SIZE(ack_seen) && ! ack_seen[ack_slot],
                                    "concurrent ACK counters repeated or skipped a value");
                            ack_seen[ack_slot] = true;
                        }
                        else if (config.acknowledgment_mode != kFakeTcpHeaderFieldRandomPacket)
                            requireResult(GET_BE32(carrier + 28), acknowledgment, "concurrent encoding changed ACK");
                        require(oracleIpValid(carrier) && oracleTransportValid(carrier),
                                "concurrent sequence broke checksum");
                        sbufDestroy(buf);
                    }
                requireResult(atomicLoadU32Relaxed(sequences),
                              config.sequence + kSequenceThreads * kSequencePacketsPerThread * kSequencePayloadLength,
                              "concurrent encoders lost sequence increments");
                if (faketcpheaderWireNeedsAcknowledgments(&config))
                    requireResult(atomicLoadU32Relaxed(&sequences[1]),
                                  acknowledgment + (config.increment_acknowledgment
                                                        ? kSequenceThreads * kSequencePacketsPerThread
                                                        : 0U),
                                  "concurrent encoders lost ACK increments or changed a fixed value");
                semaphoreDestroy(&ready);
                semaphoreDestroy(&start);
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
                faketcpheader_wire_config_t config = baseConfig();
                setOptions(&config, options[o]);
                const uint16_t overhead = (uint16_t) (21 + options[o]);
                require(faketcpheaderWireOverhead(&config) == overhead &&
                            faketcpheaderWireMaxNativeLength(&config) == 1500U - overhead,
                        "native MTU/overhead arithmetic");
                uint16_t length = buildNative(packet, kProtocols[p], 60, (uint16_t) (1500 - overhead));
                sbuf_t  *buf    = encodeOk(&config, kSides[s], packet, length, overhead, false);
                require(sbufGetLength(buf) == 1500 && sbufGetLeftCapacity(buf) == 0,
                        "exact carrier size/headroom limit");
                decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                sbufDestroy(buf);
                length = buildNative(packet, kProtocols[p], 20, (uint16_t) (1501 - overhead));
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
                    const uint16_t malformed_wire = (uint16_t) (malformed_length + overhead);
                    memoryCopy(bad, carrier, 20 + overhead);
                    memoryCopy(bad + 20 + overhead, packet + 20, malformed_length - 20);
                    PUT_BE16(bad + 2, malformed_wire);
                    if (malformed != 0 && kProtocols[p] == 6)
                        bad[20 + overhead + 12] = malformed == 1 ? 0x40 : 0xf0;
                    if (malformed != 0 && kProtocols[p] == 17)
                        PUT_BE16(bad + 20 + overhead + 4, malformed == 1 ? 7 : 81);
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
                memoryCopy(bad, carrier, 20 + overhead);
                PUT_BE16(bad + 2, (uint16_t) (20 + overhead));
                oracleSetChecksums(bad);
                expectRefusalAnyIntent(&config,
                                       peerSide(kSides[s]),
                                       false,
                                       bad,
                                       20 + overhead,
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

static void testAllProtocolBytes(void)
{
    uint8_t                     packet[128], expected[256], carrier[256];
    faketcpheader_wire_config_t config = baseConfig();
    setOptions(&config, 4);
    require(kFakeTcpHeaderWireRequiredPaddingLeft == 61 && faketcpheaderWireTcpHeaderLength(&config) == 24 &&
                faketcpheaderWireOverhead(&config) == 25,
            "maximum padding/header/metadata contract");
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (unsigned p = 0; p <= UINT8_MAX; ++p)
            for (unsigned body = 0; body < 3; ++body)
            {
                const bool     known = p == 1 || p == 6 || p == 17;
                const uint16_t length =
                    buildNative(packet, (uint8_t) p, 20, known ? 63 : (uint16_t) (20 + (body == 2 ? 17 : body)));
                const uint16_t wire_length = oracleCarrier(
                    expected, packet, &config, kSides[s], faketcpheaderWirePortIndex(&config, packet, length));
                sbuf_t *buf = encodeOk(&config, kSides[s], packet, length, 25, false);
                requireBytes(bufferBytes(buf), expected, wire_length, "protocol-byte independent oracle");
                require(bufferBytes(buf)[44] == p, "protocol byte value was not preserved");
                decodeOk(&config, peerSide(kSides[s]), buf, packet, length);
                sbufDestroy(buf);
            }

    /* Odd native body with exactly the advertised headroom and no tail capacity. */
    const uint16_t length = buildNative(packet, 255, 20, 39);
    sbuf_t        *buf    = makeBuffer(packet, length, 25);
    require(sbufGetTailCapacity(buf) == 0, "no-tail-space fixture has spare tail space");
    requireResult(faketcpheaderWireEncode(&config, NULL, kFakeTcpHeaderWireClient, buf),
                  kFakeTcpHeaderWireOk,
                  "protocol tag needed spare tail space");
    require(sbufGetLeftCapacity(buf) == 0 && sbufGetTailCapacity(buf) == 0, "framing changed end of occupied storage");
    decodeOk(&config, kFakeTcpHeaderWireServer, buf, packet, length);
    sbufDestroy(buf);

    /* A tag-only carrier is accepted only for an opaque protocol, including zero. */
    buildNative(packet, 0, 20, 20);
    const uint16_t encoded = oracleCarrier(carrier, packet, &config, kFakeTcpHeaderWireClient, 0);
    for (unsigned p = 0; p <= UINT8_MAX; ++p)
    {
        memoryCopy(expected, carrier, encoded);
        expected[44] = (uint8_t) p;
        oracleSetChecksums(expected);
        if (p == 1 || p == 6 || p == 17)
            expectRefusalAnyIntent(&config,
                                   kFakeTcpHeaderWireServer,
                                   false,
                                   expected,
                                   encoded,
                                   3,
                                   kFakeTcpHeaderWireNativeFraming,
                                   "tag-only known protocol accepted");
        else
        {
            buf = makeBuffer(expected, encoded, 3);
            decodeOk(&config, kFakeTcpHeaderWireServer, buf, NULL, 20);
            require(bufferBytes(buf)[9] == p, "tag-only opaque protocol lost");
            sbufDestroy(buf);
        }
    }
    PUT_BE16(carrier + 2, (uint16_t) (encoded - 1));
    oracleSetChecksums(carrier);
    expectRefusalAnyIntent(&config,
                           kFakeTcpHeaderWireServer,
                           false,
                           carrier,
                           encoded - 1,
                           0,
                           kFakeTcpHeaderWireNativeFraming,
                           "carrier without metadata accepted");

    buildNative(packet, 255, 20, 39);
    const uint16_t tampered_length = oracleCarrier(carrier, packet, &config, kFakeTcpHeaderWireClient, 0);
    carrier[44] ^= 1;
    expectRefusal(&config,
                  kFakeTcpHeaderWireServer,
                  false,
                  carrier,
                  tampered_length,
                  0,
                  false,
                  kFakeTcpHeaderWireCarrierChecksum,
                  "tag omitted from visible checksum coverage");

    /* Known-protocol truncations are measured after removing the tag. */
    const uint8_t protocols[] = {1, 6, 17};
    for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
    {
        const uint16_t minimum = protocols[p] == 6 ? 20 : 8;
        buildNative(packet, 255, 20, (uint16_t) (20 + minimum - 1));
        packet[9] = protocols[p];
        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireClient,
                               true,
                               packet,
                               20 + minimum - 1,
                               25,
                               kFakeTcpHeaderWireMalformedNative,
                               "truncated known native accepted");
        const uint16_t malformed = oracleCarrier(carrier, packet, &config, kFakeTcpHeaderWireClient, 0);
        expectRefusalAnyIntent(&config,
                               kFakeTcpHeaderWireServer,
                               false,
                               carrier,
                               malformed,
                               0,
                               kFakeTcpHeaderWireNativeFraming,
                               "tag counted toward native minimum header");
    }
}

static void testIcmpAndOpaqueRepair(void)
{
    const uint8_t                     protocols[] = {1, 0, 255, 136, 51};
    uint8_t                           packet[128], expected[128], carrier[256];
    const faketcpheader_wire_config_t config = baseConfig();
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
            for (unsigned kind = 0; kind < 3; ++kind)
            {
                const uint16_t h = 24, length = 89;
                buildNative(packet, protocols[p], h, length);
                if (protocols[p] == 1)
                {
                    packet[h]     = kind == 0 ? 8 : kind == 1 ? 0 : 3;
                    packet[h + 1] = kind == 2 ? 1 : 0;
                    if (kind == 2)
                    {
                        /* An error quote remains bytes; no embedded-address translation. */
                        packet[h + 8] = 0x45;
                        PUT_BE32(packet + h + 20, 0xc0000201U);
                        PUT_BE32(packet + h + 24, 0xc6336402U);
                    }
                    oracleSetChecksums(packet);
                    packet[h + 2] ^= 0x5a;
                }
                packet[10] ^= 0xa5;
                memoryCopy(expected, packet, length);
                oracleIpChecksum(expected);
                sbuf_t  *buf  = encodeOk(&config, kSides[s], packet, length, 21, false);
                uint8_t *wire = sbufGetMutablePtr(buf);
                requireBytes(wire + h + 21, packet + h, length - h, "normal encoding changed ICMP/opaque body");
                PUT_BE32(wire + 12, 0xcb007101U);
                PUT_BE32(wire + 16, 0xcb007102U);
                memoryCopy(expected + 12, wire + 12, 8);
                oracleIpChecksum(expected);
                oracleSetChecksums(wire);
                decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
                requireBytes(bufferBytes(buf) + h, packet + h, length - h, "address rewrite changed ICMP/opaque body");
                sbufDestroy(buf);

                /* Native repair applies full known-protocol repair or IPv4-only opaque repair. */
                memoryCopy(expected, packet, length);
                oracleSetChecksums(expected);
                buf = encodeOk(&config, kSides[s], packet, length, 21, true);
                decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
                sbufDestroy(buf);

                const uint16_t wire_length = oracleCarrier(carrier, packet, &config, kSides[s], 0);
                carrier[10] ^= 1;
                carrier[h + 16] ^= 2;
                memoryCopy(expected, packet, length);
                oracleIpChecksum(expected);
                buf = makeBuffer(carrier, wire_length, 5);
                sbufSetRecalculateChecksum(buf, true);
                decodeOk(&config, peerSide(kSides[s]), buf, expected, length);
                requireBytes(
                    bufferBytes(buf) + h, packet + h, length - h, "carrier request repaired hidden ICMP/opaque bytes");
                sbufDestroy(buf);
            }
}

static void testFragmentAdmission(void)
{
    const uint8_t                     protocols[]       = {6, 17, 1, 255};
    const uint16_t                    fragment_fields[] = {0x2000, 0x2001, 0x0001, 0x4000};
    uint8_t                           packet[128], carrier[256], bad[256];
    const faketcpheader_wire_config_t config = baseConfig();
    for (size_t s = 0; s < ARRAY_SIZE(kSides); ++s)
        for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
        {
            const uint16_t length  = buildNative(packet, protocols[p], 20, 89);
            const uint16_t encoded = oracleCarrier(carrier, packet, &config, kSides[s], 0);
            for (size_t f = 0; f < ARRAY_SIZE(fragment_fields); ++f)
                for (unsigned repair = 0; repair < 2; ++repair)
                {
                    memoryCopy(bad, packet, length);
                    PUT_BE16(bad + 6, fragment_fields[f]);
                    oracleIpChecksum(bad);
                    if (f == 3)
                    {
                        sbuf_t *buf = encodeOk(&config, kSides[s], bad, length, 21, repair != 0);
                        sbufSetRecalculateChecksum(buf, repair != 0);
                        decodeOk(&config, peerSide(kSides[s]), buf, bad, length);
                        require(GET_BE16(bufferBytes(buf) + 6) == 0x4000, "DF was not preserved");
                        sbufDestroy(buf);
                        continue;
                    }
                    expectRefusal(&config,
                                  kSides[s],
                                  true,
                                  bad,
                                  length,
                                  21,
                                  repair != 0,
                                  kFakeTcpHeaderWireFragmented,
                                  "fragmented native admitted");
                    /* A first fragment may not even contain the native header. */
                    PUT_BE16(bad + 2, 21);
                    oracleIpChecksum(bad);
                    expectRefusal(&config,
                                  kSides[s],
                                  true,
                                  bad,
                                  21,
                                  21,
                                  repair != 0,
                                  kFakeTcpHeaderWireFragmented,
                                  "native fragment parsed before refusal");
                    memoryCopy(bad, carrier, encoded);
                    PUT_BE16(bad + 6, fragment_fields[f]);
                    oracleIpChecksum(bad);
                    expectRefusal(&config,
                                  peerSide(kSides[s]),
                                  false,
                                  bad,
                                  encoded,
                                  7,
                                  repair != 0,
                                  kFakeTcpHeaderWireFragmented,
                                  "fragmented carrier admitted");
                    PUT_BE16(bad + 2, 21);
                    oracleIpChecksum(bad);
                    expectRefusal(&config,
                                  peerSide(kSides[s]),
                                  false,
                                  bad,
                                  21,
                                  7,
                                  repair != 0,
                                  kFakeTcpHeaderWireFragmented,
                                  "carrier fragment parsed before refusal");
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
                config->sequence_mode == kFakeTcpHeaderFieldRandomPort && config->sequence == 0 &&
                config->acknowledgment_mode == kFakeTcpHeaderFieldNumeric && config->acknowledgment == 0 &&
                config->window == 65535 && config->urgent_pointer == 0 && config->options_length == 0 &&
                config->increment_sequence && ! config->increment_acknowledgment,
            "default settings changed");
}

static void testSettings(void)
{
    faketcpheader_wire_config_t config = {0};
    config                             = requireSettingsLoaded(NULL);
    requireDefaults(&config);
    config = requireSettingsLoaded("{}");
    requireDefaults(&config);
    config = requireSettingsLoaded("{\"increment-sequence\":true}");
    requireDefaults(&config);
    config = requireSettingsLoaded("{\"increment-acknowledgment\":false}");
    requireDefaults(&config);
    config = requireSettingsLoaded("{\"increment-acknowledgment\":true,\"sequence\":123,\"increment-sequence\":false}");
    require(config.increment_acknowledgment && ! config.increment_sequence &&
                config.acknowledgment_mode == kFakeTcpHeaderFieldNumeric && config.acknowledgment == 0 &&
                ! faketcpheaderWireNeedsSequences(&config) && faketcpheaderWireNeedsAcknowledgments(&config) &&
                faketcpheaderWireStateCount(&config) == 16,
            "ACK-only progression did not reserve its own counter block");
    config = requireSettingsLoaded("{\"increment-sequence\":false,\"sequence\":123}");
    require(! config.increment_sequence && config.sequence_mode == kFakeTcpHeaderFieldNumeric && config.sequence == 123,
            "fixed sequence settings were not loaded");
    config = requireSettingsLoaded("{\"increment-sequence\":false}");
    require(! config.increment_sequence && config.sequence_mode == kFakeTcpHeaderFieldRandomPort &&
                faketcpheaderWireNeedsSequences(&config),
            "fixed default random_port lost its per-port storage");
    const struct
    {
        const char                *name;
        faketcpheader_field_mode_t mode;
    } modes[] = {{"random_node", kFakeTcpHeaderFieldRandomNode}, {"random_port", kFakeTcpHeaderFieldRandomPort}};
    for (size_t i = 0; i < ARRAY_SIZE(modes); ++i)
        for (unsigned increment = 0; increment < 2; ++increment)
        {
            char json[128];
            snprintf(json,
                     sizeof(json),
                     "{\"sequence\":\"%s\",\"increment-sequence\":%s}",
                     modes[i].name,
                     increment ? "true" : "false");
            config = requireSettingsLoaded(json);
            require(config.sequence_mode == modes[i].mode && config.increment_sequence == (increment != 0) &&
                        config.sequence == 0,
                    "random sequence settings were not parsed without generating a seed");
            require(faketcpheaderWireNeedsSequences(&config) ==
                        (increment != 0 || modes[i].mode == kFakeTcpHeaderFieldRandomPort),
                    "sequence mode needs wrong storage");
        }
    const struct
    {
        const char                *name;
        faketcpheader_field_mode_t mode;
    } ack_modes[] = {{"random_node", kFakeTcpHeaderFieldRandomNode},
                     {"random_port", kFakeTcpHeaderFieldRandomPort},
                     {"random_packet", kFakeTcpHeaderFieldRandomPacket}};
    for (size_t a = 0; a < ARRAY_SIZE(ack_modes); ++a)
        for (unsigned increment = 0; increment < 2; ++increment)
        {
            char json[160];
            snprintf(json,
                     sizeof(json),
                     "{\"acknowledgment\":\"%s\",\"sequence\":123,\"increment-sequence\":%s}",
                     ack_modes[a].name,
                     increment ? "true" : "false");
            config = requireSettingsLoaded(json);
            require(config.acknowledgment_mode == ack_modes[a].mode && config.acknowledgment == 0 &&
                        config.sequence_mode == kFakeTcpHeaderFieldNumeric && config.sequence == 123 &&
                        config.increment_sequence == (increment != 0) && ! config.increment_acknowledgment,
                    "ACK mode changed sequence settings or generated randomness while parsing");
            requireResult(faketcpheaderWireStateCount(&config),
                          16U * (increment + (ack_modes[a].mode == kFakeTcpHeaderFieldRandomPort)),
                          "ACK mode allocated the wrong state count");
            snprintf(json, sizeof(json), "{\"acknowledgment\":\"%s\"}", ack_modes[a].name);
            config = requireSettingsLoaded(json);
            require(config.acknowledgment_mode == ack_modes[a].mode && config.acknowledgment == 0 &&
                        config.sequence_mode == kFakeTcpHeaderFieldRandomPort && config.increment_sequence &&
                        ! config.increment_acknowledgment,
                    "ACK mode changed the default sequence behavior");
            snprintf(json,
                     sizeof(json),
                     "{\"acknowledgment\":\"%s\",\"increment-acknowledgment\":true,"
                     "\"sequence\":123,\"increment-sequence\":%s}",
                     ack_modes[a].name,
                     increment ? "true" : "false");
            if (ack_modes[a].mode == kFakeTcpHeaderFieldRandomPacket)
                requireSettingsRejected(json);
            else
            {
                config = requireSettingsLoaded(json);
                require(config.increment_acknowledgment && config.acknowledgment_mode == ack_modes[a].mode &&
                            config.increment_sequence == (increment != 0) &&
                            faketcpheaderWireStateCount(&config) == 16U * (increment + 1U),
                        "ACK progression changed sequence admission or omitted its counter block");
            }
        }
    config = requireSettingsLoaded("{\"acknowledgment\":\"random_packet\",\"increment-acknowledgment\":false}");
    require(! config.increment_acknowledgment && config.acknowledgment_mode == kFakeTcpHeaderFieldRandomPacket,
            "explicitly disabled ACK progression refused random_packet");
    requireSettingsRejected("{\"payload-protocol\":6}");
    requireSettingsRejected("{\"payload-protocol\":17}");

    config = requireSettingsLoaded("{\"server-port\":1,\"client-port\":2,\"sequence\":0,"
                                   "\"acknowledgment\":0,\"window\":0,\"urgent-pointer\":0,\"options\":\"\"}");
    require(config.server_port == 1 && config.client_port == 2 && config.client_port_count == 1 && config.window == 0 &&
                config.options_length == 0 && config.sequence_mode == kFakeTcpHeaderFieldNumeric &&
                config.sequence == 0 && config.acknowledgment_mode == kFakeTcpHeaderFieldNumeric &&
                config.acknowledgment == 0,
            "lower edges were not loaded");

    config = requireSettingsLoaded(
        "{\"server-port\":65535,\"client-port-range\":[63488,64511],\"sequence\":"
        "4294967295,"
        "\"acknowledgment\":4294967295,\"window\":65535,\"urgent-pointer\":65535,"
        "\"options\":\"000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F2021222324252627\"}");
    require(config.server_port == 65535 && config.client_port == 63488 && config.client_port_count == 1024 &&
                config.sequence_mode == kFakeTcpHeaderFieldNumeric && config.sequence == UINT32_MAX &&
                config.acknowledgment_mode == kFakeTcpHeaderFieldNumeric && config.acknowledgment == UINT32_MAX &&
                config.window == 65535 && config.urgent_pointer == 65535 && config.options_length == 40,
            "upper edges were not loaded");
    for (uint8_t i = 0; i < 40; ++i)
    {
        require(config.options[i] == i, "options were not decoded verbatim");
    }

    config = requireSettingsLoaded("{\"client-port\":40001}");
    require(config.client_port == 40001 && config.client_port_count == 1,
            "explicit client-port did not replace the default range with one port");
    config = requireSettingsLoaded("{\"client-port\":1,\"server-port\":65535}");
    require(config.client_port == 1 && config.client_port_count == 1, "client-port 1 was not loaded");
    config = requireSettingsLoaded("{\"client-port\":65535}");
    require(config.client_port == 65535 && config.client_port_count == 1, "client-port 65535 was not loaded");
    config = requireSettingsLoaded("{\"client-port-range\":[1,1]}");
    require(config.client_port == 1 && config.client_port_count == 1, "singleton client range was not loaded");
    config = requireSettingsLoaded("{\"client-port-range\":[65535,65535]}");
    require(config.client_port == 65535 && config.client_port_count == 1, "maximum singleton range was not loaded");
    config = requireSettingsLoaded("{\"client-port-range\":[65530,65535]}");
    require(config.client_port == 65530 && config.client_port_count == 6,
            "inclusive range ending at 65535 was not loaded");
    config = requireSettingsLoaded("{\"client-port-range\":[64512,65535]}");
    require(config.client_port == 64512 && config.client_port_count == 1024,
            "maximum range ending at 65535 was not loaded");
    config = requireSettingsLoaded("{\"server-port\":40017,\"client-port-range\":[40001,40016]}");
    require(config.server_port == 40017, "server-port just above the client range was rejected");
    config = requireSettingsLoaded("{\"server-port\":40000,\"client-port-range\":[40001,40016]}");
    require(config.server_port == 40000, "server-port just below the client range was rejected");
    config = requireSettingsLoaded("{\"server-port\":40002,\"client-port\":40001}");
    require(config.server_port == 40002 && config.client_port_count == 1,
            "scalar client-port incorrectly retained the default range");
    config = requireSettingsLoaded("{\"options\":\"020405B4\"}");
    require(config.options_length == 4 && config.options[0] == 0x02 && config.options[3] == 0xB4,
            "four option bytes were not loaded");

    static const char *const rejected[] = {
        "{\"increment-sequence\":null}",
        "{\"increment-sequence\":0}",
        "{\"increment-sequence\":1}",
        "{\"increment-sequence\":\"true\"}",
        "{\"increment-sequence\":[]}",
        "{\"increment-sequence\":{}}",
        "{\"increment-acknowledgment\":null}",
        "{\"increment-acknowledgment\":0}",
        "{\"increment-acknowledgment\":1}",
        "{\"increment-acknowledgment\":\"true\"}",
        "{\"increment-acknowledgment\":[]}",
        "{\"increment-acknowledgment\":{}}",
        "{\"increment-acknowledgment\":true,\"acknowledgment\":\"random_packet\"}",
        "{\"payload-protocol\":null}",
        "{\"payload-protocol\":6.5}",
        "{\"payload-protocol\":6.0}",
        "{\"payload-protocol\":6e0}",
        "{\"payload-protocol\":7}",
        "{\"payload-protocol\":16}",
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
        "{\"client-port\":-1}",
        "{\"client-port\":65536}",
        "{\"client-port-count\":0}",
        "{\"client-port-count\":1}",
        "{\"client-port-count\":16}",
        "{\"client-port-count\":1025}",
        "{\"client-port-range\":null}",
        "{\"client-port-range\":40001}",
        "{\"client-port-range\":\"40001-40016\"}",
        "{\"client-port-range\":true}",
        "{\"client-port-range\":{}}",
        "{\"client-port-range\":[]}",
        "{\"client-port-range\":[40001]}",
        "{\"client-port-range\":[40001,40002,40003]}",
        "{\"client-port-range\":[null,40016]}",
        "{\"client-port-range\":[40001,null]}",
        "{\"client-port-range\":[true,40016]}",
        "{\"client-port-range\":[40001,false]}",
        "{\"client-port-range\":[\"40001\",40016]}",
        "{\"client-port-range\":[40001,\"40016\"]}",
        "{\"client-port-range\":[{},40016]}",
        "{\"client-port-range\":[40001,[]]}",
        "{\"client-port-range\":[40001.5,40016]}",
        "{\"client-port-range\":[40001,40016.5]}",
        "{\"client-port-range\":[40001.0,40016]}",
        "{\"client-port-range\":[40001,40016.0]}",
        "{\"client-port-range\":[40001e0,40016]}",
        "{\"client-port-range\":[40001,40016e0]}",
        "{\"client-port-range\":[0,16]}",
        "{\"client-port-range\":[-1,16]}",
        "{\"client-port-range\":[65530,65536]}",
        "{\"client-port-range\":[65536,65536]}",
        "{\"client-port-range\":[40016,40001]}",
        "{\"client-port-range\":[64511,65535]}",
        "{\"client-port-range\":[1,65535]}",
        "{\"client-port\":40001,\"client-port-range\":[40001,40016]}",
        "{\"client-port-range\":[40001,40016],\"client-port\":40001}",
        "{\"client-port\":null,\"client-port-range\":[40001,40016]}",
        "{\"client-port\":40001,\"client-port-range\":null}",
        "{\"client-port\":null,\"client-port-range\":null}",
        "{\"sequence\":\"random_fixed\"}",
        "{\"sequence\":\"random_con\"}",
        "{\"sequence\":\"random_always\"}",
        "{\"sequence\":\"random_packet\"}",
        "{\"sequence\":\"RANDOM_PORT\"}",
        "{\"sequence\":\" random_port\"}",
        "{\"sequence\":\"random_node \"}",
        "{\"sequence\":\"random_node\\u0000extra\"}",
        "{\"sequence\":\"random_port\\u0000extra\"}",
        "{\"sequence\":\"123\"}",
        "{\"sequence\":\"\"}",
        "{\"sequence\":true}",
        "{\"sequence\":false}",
        "{\"sequence\":[]}",
        "{\"sequence\":1.0}",
        "{\"sequence\":1.5}",
        "{\"sequence\":1e0}",
        "{\"sequence\":-1}",
        "{\"sequence\":4294967296}",
        "{\"acknowledgment\":-1}",
        "{\"acknowledgment\":4294967296}",
        "{\"acknowledgment\":1.0}",
        "{\"acknowledgment\":1.5}",
        "{\"acknowledgment\":1e0}",
        "{\"acknowledgment\":true}",
        "{\"acknowledgment\":false}",
        "{\"acknowledgment\":[]}",
        "{\"acknowledgment\":{}}",
        "{\"acknowledgment\":\"123\"}",
        "{\"acknowledgment\":\"\"}",
        "{\"acknowledgment\":\"random_fixed\"}",
        "{\"acknowledgment\":\"random_con\"}",
        "{\"acknowledgment\":\"random_always\"}",
        "{\"acknowledgment\":\"RANDOM_PACKET\"}",
        "{\"acknowledgment\":\" random_node\"}",
        "{\"acknowledgment\":\"random_port \"}",
        "{\"acknowledgment\":\"random_node\\u0000extra\"}",
        "{\"acknowledgment\":\"random_port\\u0000extra\"}",
        "{\"acknowledgment\":\"random_packet\\u0000extra\"}",
        "{\"window\":-1}",
        "{\"window\":65536}",
        "{\"urgent-pointer\":-1}",
        "{\"urgent-pointer\":65536}",
        "{\"server-port\":1.5}",
        "{\"client-port\":40001.0}",
        "{\"client-port\":40001.5}",
        "{\"client-port\":40001e0}",
        "{\"client-port\":\"40001\"}",
        "{\"client-port\":[40001]}",
        "{\"client-port\":[40001,40016]}",
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
        "{\"options\":"
        "\"0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243\"}",
        "{\"options\":\"zz010101\"}",
        "{\"options\":\"0x010101\"}",
        "{\"options\":\"0101 101\"}",
        "{\"options\":\"0101\\u00000101\"}",
        "{\"server-port\":40001}",
        "{\"server-port\":40008}",
        "{\"server-port\":40016}",
        "{\"server-port\":5,\"client-port\":5}",
        "{\"server-port\":40001,\"client-port-range\":[40001,40016]}",
        "{\"server-port\":40008,\"client-port-range\":[40001,40016]}",
        "{\"server-port\":40016,\"client-port-range\":[40001,40016]}",
        "{\"server-port\":65535,\"client-port-range\":[64512,65535]}",
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
    /* Settings are pure parsing: even random defaults must work before RNG startup. */
    TEST_RUN_CASE(testSettings);
    require(globalstateInitializeSecureRandom(), "OS random source unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    TEST_RUN_CASE(testResultNames);
    TEST_RUN_CASE(testKnownAnswers);
    TEST_RUN_CASE(testWireAndMovement);
    TEST_RUN_CASE(testHeaderAndAddressComposition);
    TEST_RUN_CASE(testCorruptionRepairAndZeros);
    TEST_RUN_CASE(testUdpPadding);
    TEST_RUN_CASE(testPortMapping);
    TEST_RUN_CASE(testSequenceProgression);
    TEST_RUN_CASE(testSequencePortIsolation);
    TEST_RUN_CASE(testRandomSequenceModes);
    TEST_RUN_CASE(testAcknowledgmentModes);
    TEST_RUN_CASE(testConcurrentSequences);
    TEST_RUN_CASE(testLimitsAndFraming);
    TEST_RUN_CASE(testAllProtocolBytes);
    TEST_RUN_CASE(testIcmpAndOpaqueRepair);
    TEST_RUN_CASE(testFragmentAdmission);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}

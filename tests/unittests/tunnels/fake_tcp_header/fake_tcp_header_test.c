/*
 * Covers: UDP/fake-TCP byte conversion, independent checksum oracle, custom
 * headers, bounds/refusal, configuration and existing IpManipulator flag reuse.
 * CTest: waterwall.fake_tcp_header_unit
 * No OS raw socket or throughput behavior is implied by this component fixture.
 */
#include "FakeTcpHeader/structure.h"
#include "test_assert.h"
#include "wchecksum.h"

#ifdef TEST_FAKE_TCP_FLAGS
#include "IpManipulator/structure.h"
#include "tricks/tcpbitchange/trick.h"
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t oracleSum(const uint8_t *p, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2)
        sum += ((uint32_t) p[i] << 8) | (i + 1 < length ? p[i + 1] : 0);
    return sum;
}

static bool oracleValid(const uint8_t *p, size_t length, bool pseudo)
{
    const size_t ihl = (p[0] & 15U) * 4U;
    uint32_t sum = pseudo ? oracleSum(p + 12, 8) + p[9] + (uint32_t) (length - ihl) + oracleSum(p + ihl, length - ihl)
                          : oracleSum(p, ihl);
    while (sum >> 16)
        sum = (sum & 65535U) + (sum >> 16);
    return sum == 65535U;
}

static faketcpheader_tstate_t configuration(void)
{
    faketcpheader_tstate_t config  = {.protocol = 6, .local_port = 40001, .peer_port = 40000, .mtu = 1500};
    const uint8_t          local[] = {192, 0, 2, 10}, peer[] = {198, 51, 100, 10};
    memoryCopy(&config.local_ipv4, local, 4);
    memoryCopy(&config.peer_ipv4, peer, 4);
    return config;
}

static faketcpheader_tstate_t reverseConfiguration(faketcpheader_tstate_t config)
{
    const uint32_t address = config.local_ipv4;
    const uint16_t port    = config.local_port;
    config.local_ipv4      = config.peer_ipv4;
    config.peer_ipv4       = address;
    config.local_port      = config.peer_port;
    config.peer_port       = port;
    return config;
}

static sbuf_t *udpPacket(uint16_t payload, uint8_t ip_options, uint16_t padding, bool shifted)
{
    const uint16_t ihl   = (uint16_t) (IP_HLEN + ip_options);
    const uint16_t total = (uint16_t) (ihl + UDP_HLEN + payload);
    sbuf_t        *buf   = sbufCreateWithPadding(total + 1U, padding);
    sbufSetLength(buf, total + (shifted ? 1U : 0U));
    if (shifted)
        sbufShiftRight(buf, 1);
    uint8_t *p = sbufGetMutablePtr(buf);
    memoryZero(p, total);
    p[0]  = (uint8_t) (0x40U | (ihl / 4U));
    p[1]  = 0x2e;
    p[2]  = (uint8_t) (total >> 8);
    p[3]  = (uint8_t) total;
    p[4]  = 0x12;
    p[5]  = 0x34;
    p[6]  = 0x40; /* DF survives both conversions. */
    p[8]  = 64;
    p[9]  = IPPROTO_UDP;
    p[12] = 192;
    p[13] = 0;
    p[14] = 2;
    p[15] = 10;
    p[16] = 198;
    p[17] = 51;
    p[18] = 100;
    p[19] = 10;
    for (unsigned int i = IP_HLEN; i < ihl; ++i)
        p[i] = 1;
    p[ihl]     = 0xa0;
    p[ihl + 1] = 0x01;
    p[ihl + 2] = 0x1f;
    p[ihl + 3] = 0x90;
    p[ihl + 4] = (uint8_t) ((payload + UDP_HLEN) >> 8);
    p[ihl + 5] = (uint8_t) (payload + UDP_HLEN);
    for (unsigned int i = 0; i < payload; ++i)
        p[ihl + UDP_HLEN + i] = (uint8_t) (i * 37U);
    require(calcFullPacketChecksum(p, total), "could not prepare UDP fixture");
    return buf;
}

static void roundtrip(uint16_t payload, uint8_t ip_options, uint8_t tcp_options, uint8_t protocol, bool shifted)
{
    faketcpheader_tstate_t config = configuration();
    config.protocol               = protocol;
    config.sequence               = UINT32_MAX;
    config.acknowledgment         = 0x10203040;
    config.window                 = 12345;
    config.urgent_pointer         = 42;
    config.options_length         = tcp_options;
    memset(config.options, 1, sizeof(config.options));
    sbuf_t        *buf             = udpPacket(payload, ip_options, kFakeTcpHeaderPadding, shifted);
    const uint32_t original_length = sbufGetLength(buf);
    uint8_t        original[kMaxAllowedPacketLength];
    memoryCopy(original, sbufGetRawPtr(buf), original_length);
    const uint16_t ihl             = IP_HLEN;
    const uint16_t header          = (uint16_t) (TCP_HLEN + tcp_options);
    const uint8_t *payload_address = sbufGetRawPtr(buf);
    require(faketcpheaderEncode(&config, buf), "UDP encoding failed");
    const uint8_t *p = sbufGetRawPtr(buf);
    require(p[9] == protocol && read16(p + 2) == sbufGetLength(buf), "incorrect IP protocol or total length");
    require(p + ihl + header == payload_address, "encoding copied the application payload");
    require(oracleValid(p, sbufGetLength(buf), false) && oracleValid(p, sbufGetLength(buf), true),
            "encoded checksums failed independent oracle");
    require(read16(p + ihl) == 40001 && read16(p + ihl + 2) == 40000, "carrier ports changed");
    require(read16(p + ihl + 4) == 65535 && read16(p + ihl + 6) == 65535 && read16(p + ihl + 8) == 0x1020 &&
                read16(p + ihl + 10) == 0x3040 && read16(p + ihl + 14) == 12345 && read16(p + ihl + 18) == 42 &&
                p[ihl + 12] == (header / 4U) << 4 && p[ihl + 13] == 0,
            "custom header fields or default flags changed");
    require(memoryEqual(p + ihl + TCP_HLEN, config.options, tcp_options), "TCP options changed");
    faketcpheader_tstate_t receiver = reverseConfiguration(config);
    receiver.options_length         = 0;
    require(faketcpheaderDecode(&receiver, buf), "carrier decoding failed with a different receive template");
    require(sbufGetLength(buf) == original_length && memoryEqual(sbufGetRawPtr(buf), original, original_length),
            "roundtrip changed IPv4/UDP headers or datagram payload");
    require(! sbufGetRecalculateChecksum(buf), "checksum request leaked through conversion");
    sbufDestroy(buf);
}

static void requireRefused(const faketcpheader_tstate_t *config, sbuf_t *buf, bool encode)
{
    uint8_t        original[2048];
    const uint32_t length = sbufGetLength(buf), cursor = buf->curpos;
    const bool     repair = sbufGetRecalculateChecksum(buf);
    require(length <= sizeof(original), "bad refusal fixture");
    memoryCopy(original, sbufGetRawPtr(buf), length);
    require(! (encode ? faketcpheaderEncode(config, buf) : faketcpheaderDecode(config, buf)),
            "invalid packet was accepted");
    require(sbufGetLength(buf) == length && buf->curpos == cursor && sbufGetRecalculateChecksum(buf) == repair &&
                memoryEqual(original, sbufGetRawPtr(buf), length),
            "refusal mutated packet or metadata");
    sbufDestroy(buf);
}

static void testRejections(void)
{
    faketcpheader_tstate_t config = configuration();
    requireRefused(&config, udpPacket(1, 0, 0, false), true);
    requireRefused(&config, udpPacket(1433, 0, kFakeTcpHeaderPadding, false), true);
    requireRefused(&config, udpPacket(1, 0, kFakeTcpHeaderPadding, false), false);
    for (unsigned int which = 0; which < 10; ++which)
    {
        sbuf_t  *buf = udpPacket(5, 0, kFakeTcpHeaderPadding, false);
        uint8_t *p   = sbufGetMutablePtr(buf);
        switch (which)
        {
        case 0:
            p[0] = 0x65;
            break;
        case 1:
            p[0] = 0x44;
            break;
        case 2:
            p[3]++;
            break;
        case 3:
            p[6] |= 0x20;
            break;
        case 4:
            p[7] = 1;
            break;
        case 5:
            p[25]--;
            break;
        case 6:
            p[10] ^= 1;
            break;
        case 7:
            p[28] ^= 1;
            break;
        case 8:
            sbufSetLength(buf, 10);
            break;
        case 9:
            p[25] = 7;
            sbufSetRecalculateChecksum(buf, true);
            break;
        }
        requireRefused(&config, buf, true);
    }
    for (unsigned int which = 0; which < 6; ++which)
    {
        sbuf_t *buf = udpPacket(5, 0, kFakeTcpHeaderPadding, false);
        require(faketcpheaderEncode(&config, buf), "encoding refusal fixture failed");
        faketcpheader_tstate_t receiver = reverseConfiguration(config);
        uint8_t               *p        = sbufGetMutablePtr(buf);
        switch (which)
        {
        case 0:
            p[32] = 0x40;
            break;
        case 1:
            p[32] = 0xf0;
            break;
        case 2:
            p[9] = 253;
            break;
        case 3:
            p[40] ^= 1;
            break;
        case 4:
            p[6] |= 0x20;
            break;
        case 5:
            sbufSetLength(buf, 39);
            break;
        }
        requireRefused(&receiver, buf, false);
    }
}

static void testChecksumIntent(void)
{
    faketcpheader_tstate_t config = configuration();
    sbuf_t                *buf    = udpPacket(7, 0, kFakeTcpHeaderPadding, false);
    uint8_t               *p      = sbufGetMutablePtr(buf);
    p[26] = p[27] = 0; /* IPv4 UDP permits a disabled checksum. */
    require(faketcpheaderEncode(&config, buf), "disabled UDP checksum was rejected");
    p = sbufGetMutablePtr(buf);
    p[24] ^= 0x80;
    sbufSetRecalculateChecksum(buf, true);
    faketcpheader_tstate_t receiver = reverseConfiguration(config);
    require(faketcpheaderDecode(&receiver, buf), "pending carrier checksum repair was not honored");
    p = sbufGetMutablePtr(buf);
    require(read16(p + 26) == 0 && ! sbufGetRecalculateChecksum(buf), "disabled inner UDP checksum changed");
    p[28] ^= 1;
    sbufSetRecalculateChecksum(buf, true);
    require(faketcpheaderEncode(&config, buf), "pending UDP checksum repair was not honored");
    require(oracleValid(sbufGetRawPtr(buf), sbufGetLength(buf), true), "dirty UDP became invalid carrier");
    sbufDestroy(buf);
}

static void testConfiguration(void)
{
    const char *const valid[] = {
        "{}",
        "{\"role\":\"server\",\"protocol-number\":6,\"options\":\"01010101\"}",
        "{\"sequence\":4294967295,\"acknowledgment\":4294967295,\"window\":65535,\"urgent-pointer\":65535}",
        "{\"protocol-number\":0,\"options\":\"\"}",
        "{\"protocol-number\":255,\"window\":0}"};
    const char *const invalid[] = {"[]",
                                   "null",
                                   "{\"role\":null}",
                                   "{\"role\":\"other\"}",
                                   "{\"protocol-number\":256}",
                                   "{\"protocol-number\":-1}",
                                   "{\"protocol-number\":6.5}",
                                   "{\"protocol-number\":true}",
                                   "{\"protocol-number\":null}",
                                   "{\"sequence\":4294967296}",
                                   "{\"window\":65536}",
                                   "{\"urgent-pointer\":-1}",
                                   "{\"options\":null}",
                                   "{\"options\":\"00\"}",
                                   "{\"options\":\"zzzzzzzz\"}",
                                   "{\"flags\":2}",
                                   "{\"local-port\":0}",
                                   "{\"peer-port\":65536}",
                                   "{\"mtu\":107}",
                                   "{\"mtu\":1501}",
                                   "{\"mtu\":108,\"options\":\"01010101\"}",
                                   "{\"role\":\"client\\u0000server\"}"};
    for (size_t i = 0; i < ARRAY_SIZE(valid) + ARRAY_SIZE(invalid); ++i)
    {
        const bool expected = i < ARRAY_SIZE(valid);
        cJSON     *settings = cJSON_Parse(expected ? valid[i] : invalid[i - ARRAY_SIZE(valid)]);
        require(settings != NULL, "configuration fixture JSON failed");
        if (cJSON_IsObject(settings))
        {
            cJSON_AddStringToObject(settings, "local-ipv4", "192.0.2.10");
            cJSON_AddStringToObject(settings, "peer-ipv4", "198.51.100.10");
        }
        node_t    node = {.node_settings_json = settings};
        tunnel_t *t    = faketcpheaderCreate(&node);
        require((t != NULL) == expected, "configuration acceptance mismatch");
        if (t != NULL)
        {
            const faketcpheader_tstate_t *state = tunnelGetState(t);
            if (i == 0)
                require(state->protocol == 6 && ! state->server && state->window == 65535 && state->options_length == 0,
                        "default configuration changed");
            if (i == 1)
                require(state->server && state->options_length == 4, "server role or options not loaded");
            faketcpheaderDestroy(t, wwLifecycleStartupRollback());
        }
        cJSON_Delete(settings);
    }
    const char *const addresses[] = {"{}",
                                     "{\"local-ipv4\":\"192.0.2.10\"}",
                                     "{\"local-ipv4\":\"127.0.0.1\",\"peer-ipv4\":\"198.51.100.10\"}",
                                     "{\"local-ipv4\":\"192.0.2.10\",\"peer-ipv4\":\"224.0.0.1\"}"};
    for (size_t i = 0; i < ARRAY_SIZE(addresses); ++i)
    {
        cJSON *settings = cJSON_Parse(addresses[i]);
        node_t node     = {.node_settings_json = settings};
        require(faketcpheaderCreate(&node) == NULL, "invalid/missing carrier address accepted");
        cJSON_Delete(settings);
    }
}

static void testInnerPackets(void)
{
    faketcpheader_tstate_t config = configuration(), receiver = reverseConfiguration(config);
    for (unsigned int kind = 0; kind < 3; ++kind)
    {
        sbuf_t  *buf = udpPacket(33, 0, kFakeTcpHeaderPadding, false);
        uint8_t *p   = sbufGetMutablePtr(buf);
        if (kind == 0)
        {
            p[9] = IPPROTO_TCP;
            memoryZero(p + 20, 20);
            p[32] = 0x50;
            p[33] = TCP_SYN;
        }
        else
        {
            p[6] = kind == 1 ? 0x20 : 0;
            p[7] = kind == 1 ? 0 : 3;
        }
        require(calcFullPacketChecksum(p, sbufGetLength(buf)), "inner fixture checksum failed");
        const uint32_t length = sbufGetLength(buf);
        uint8_t        original[128];
        memoryCopy(original, p, length);
        require(faketcpheaderEncode(&config, buf) && faketcpheaderDecode(&receiver, buf),
                "inner TCP or IPv4 fragment was rejected");
        require(length == sbufGetLength(buf) && memoryEqual(original, sbufGetRawPtr(buf), length),
                "inner TCP/fragment tuple or bytes changed");
        sbufDestroy(buf);
    }
    config.options_length = 4;
    requireRefused(&config, udpPacket(1429, 0, kFakeTcpHeaderPadding, false), true);
    for (unsigned int field = 0; field < 4; ++field)
    {
        sbuf_t *buf = udpPacket(1, 0, kFakeTcpHeaderPadding, false);
        require(faketcpheaderEncode(&config, buf), "endpoint refusal fixture failed");
        sbufGetMutablePtr(buf)[field < 2 ? 12 + field * 4 : 20 + (field - 2) * 2] ^= 1;
        sbufSetRecalculateChecksum(buf, true);
        requireRefused(&receiver, buf, false);
    }
    sbuf_t *buf = udpPacket(1, 0, kFakeTcpHeaderPadding, false);
    require(faketcpheaderEncode(&config, buf), "inner corruption fixture failed");
    sbufGetMutablePtr(buf)[44 + 28] ^= 1;
    sbufSetRecalculateChecksum(buf, true);
    requireRefused(&receiver, buf, false);
}

#ifdef TEST_FAKE_TCP_FLAGS
static void testExistingFlags(void)
{
    faketcpheader_tstate_t config = configuration();
    sbuf_t                *buf    = udpPacket(9, 0, kFakeTcpHeaderPadding, false);
    require(faketcpheaderEncode(&config, buf), "flag fixture encoding failed");
    tunnel_t *flags = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    ipmanipulator_tstate_t *state  = tunnelGetState(flags);
    state->up_tcp_bit_syn_action   = kDvsOn;
    state->up_tcp_bit_ack_action   = kDvsOn;
    state->down_tcp_bit_fin_action = kDvsOn;
    line_t line                    = {0};
    tcpbitchangetrickUpStreamPayload(flags, &line, &buf);
    require(buf != NULL && sbufGetMutablePtr(buf)[33] == (TCP_SYN | TCP_ACK), "existing upstream flags did not apply");
    tcpbitchangetrickDownStreamPayload(flags, &line, &buf);
    require(buf != NULL && sbufGetMutablePtr(buf)[33] == (TCP_SYN | TCP_ACK | TCP_FIN),
            "existing downstream flags did not apply");
    require(oracleValid(sbufGetRawPtr(buf), sbufGetLength(buf), true), "existing flag edit broke carrier checksum");
    faketcpheader_tstate_t receiver = reverseConfiguration(config);
    require(faketcpheaderDecode(&receiver, buf), "custom flags prevented UDP restoration");
    sbufDestroy(buf);
    memoryFreeAligned(flags);
}
#endif

int main(void)
{
    testCaseSet("fake_tcp_header_test");
    roundtrip(0, 0, 0, 6, false);
    roundtrip(1, 0, 4, 6, true);
    roundtrip(513, 40, 40, 6, true);
    roundtrip(1432, 0, 0, 6, false);
    roundtrip(1428, 0, 4, 6, false);
    roundtrip(100, 4, 0, 253, false);
    roundtrip(100, 0, 0, 0, false);
    roundtrip(100, 0, 0, 255, false);
    testRejections();
    testChecksumIntent();
    testConfiguration();
    testInnerPackets();
#ifdef TEST_FAKE_TCP_FLAGS
    testExistingFlags();
#endif
    return 0;
}

#include "rtmp_credit.h"
#include "rtmp_wire.h"

#include "test_assert.h"

#include <string.h>

static void testU29(void)
{
    static const struct
    {
        uint32_t value;
        size_t   length;
        uint8_t  wire[4];
    } cases[] = {{0, 1, {0}},
                 {1, 1, {1}},
                 {3, 1, {3}},
                 {127, 1, {0x7f}},
                 {129, 2, {0x81, 0x01}},
                 {16383, 2, {0xff, 0x7f}},
                 {16385, 3, {0x81, 0x80, 0x01}},
                 {32769, 3, {0x82, 0x80, 0x01}},
                 {131073, 3, {0x88, 0x80, 0x01}},
                 {2097151, 3, {0xff, 0xff, 0x7f}},
                 {2097153, 4, {0x80, 0xc0, 0x80, 0x01}},
                 {536870911, 4, {0xff, 0xff, 0xff, 0xff}}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        uint8_t  encoded[4];
        uint32_t number = 0;
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, rtmpU29Encode(cases[i].value, encoded), cases[i].length, "U29 size");
        TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, encoded, cases[i].wire, cases[i].length, "U29 encoding");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                        rtmpU29Decode(cases[i].wire, cases[i].length, &number),
                        cases[i].length,
                        "U29 read size");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, number, cases[i].value, "U29 roundtrip");
        TEST_EQUAL_SIZE(
            TEST_FAILURE_EXIT, rtmpU29Decode(cases[i].wire, cases[i].length - 1, &number), 0, "accepted truncated U29");
    }
}

static const uint8_t golden[] = {
    0x00, 0x02, 0x00, 0x07, 'w', 'w', '.', 'd', 'a', 't', 'a', 0x11, 0x0c, 0x09, 0x00, 0x01, 0xfe, 0xff};

static void requireRejected(const uint8_t *body, size_t len)
{
    const uint8_t *decoded = NULL;
    size_t         n       = 0;
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpWireDecode(body, len, &decoded, &n), "accepted invalid envelope");
}

static void testEnvelope(void)
{
    static uint8_t      data[65537];
    static uint8_t      body[65553];
    static const size_t sizes[]   = {0, 1, 63, 64, 8191, 8192, 16384, 65536};
    const uint8_t      *decoded   = NULL;
    size_t              n         = 0;
    const uint8_t       fixture[] = {0x00, 0x01, 0xfe, 0xff};
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    rtmpWireEncode(fixture, sizeof(fixture), body, sizeof(body)),
                    sizeof(golden),
                    "golden body size");
    TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, body, golden, sizeof(golden), "golden body");

    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = (uint8_t) i;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        size_t len      = rtmpWireEncode(data, sizes[i], body, sizeof(body));
        size_t overhead = (sizes[i] < 64) ? 14 : (sizes[i] < 8192) ? 15 : 16;
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, len, sizes[i] + overhead, "ByteArray framing size");
        TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpWireDecode(body, len, &decoded, &n), "ByteArray decode");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, n, sizes[i], "decoded size");
        TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, decoded, data, n, "decoded bytes");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, rtmpWireEncode(data, sizes[i], body, len - 1), 0, "output capacity");
    }
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT,
                    rtmpWireEncode(data, sizeof(data), body, sizeof(body)),
                    0,
                    "encoded a body above the maximum");
}

static void testMalformed(void)
{
    uint8_t body[sizeof(golden) + 1];
    for (size_t i = 0; i < sizeof(golden); ++i)
        requireRejected(golden, i);
    for (size_t i = 0; i < 13; ++i)
    {
        memcpy(body, golden, sizeof(golden));
        body[i] ^= 1;
        requireRejected(body, sizeof(golden));
    }

    memcpy(body, golden, sizeof(golden));
    body[13] &= 0xfe;
    requireRejected(body, sizeof(golden)); /* Reference. */

    memcpy(body, golden, sizeof(golden));
    body[sizeof(golden)] = 0x05;
    requireRejected(body, sizeof(body)); /* Trailing AMF value. */

    memmove(body + 14, body + 13, sizeof(golden) - 13);
    body[13] = 0x80;
    requireRejected(body, sizeof(body)); /* Noncanonical U29. */

    body[13] = 0x88;
    body[14] = 0x80;
    body[15] = 0x03;
    requireRejected(body, 16); /* Advertised application length 65,537. */
}

static void testCredit(void)
{
    rtmp_credit_t credit = {0};
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&credit, 64 * 1024, 0), "minimum hard window");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditCanSend(&credit, 56 * 1024, true), "exact data credit threshold");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditCanSend(&credit, 56 * 1024 + 1, true), "data spent control reserve");
    rtmpCreditCommit(&credit, 56 * 1024);
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditCanSend(&credit, 8 * 1024, false), "urgent output reserve");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditCanSend(&credit, 8 * 1024 + 1, false), "control exceeded hard window");
    rtmpCreditCommit(&credit, 8 * 1024);
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditReceiveAck(&credit, 16 * 1024), "valid partial ACK");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditCanSend(&credit, 8 * 1024, true), "ACK failed to release data credit");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditReceiveAck(&credit, 16 * 1024), "duplicate ACK rejected");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditReceiveAck(&credit, 16 * 1024 - 1), "stale ACK rejected");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, credit.acknowledged, 16 * 1024, "duplicate or stale ACK granted credit");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditReceiveAck(&credit, 64 * 1024 + 1), "future ACK granted credit");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditSetBandwidth(&credit, 64 * 1024 - 1, 0), "tiny window accepted");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditSetBandwidth(&credit, 0x80000000, 0), "ambiguous window accepted");

    rtmp_credit_t bandwidth = {0};
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&bandwidth, 96 * 1024, 0), "hard window");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&bandwidth, 128 * 1024, 2), "dynamic after hard");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, bandwidth.window, 128 * 1024, "dynamic after hard failed to replace window");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&bandwidth, 96 * 1024, 1), "soft window");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&bandwidth, 128 * 1024, 1), "looser soft window");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditSetBandwidth(&bandwidth, 64 * 1024, 2), "dynamic after soft");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, bandwidth.window, 96 * 1024, "soft/dynamic window rule");
    rtmpCreditCommit(&bandwidth, 80 * 1024);
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpCreditSetBandwidth(&bandwidth, 64 * 1024, 0),
                 "shrink under outstanding credit accepted");

    rtmp_credit_t rollover = {.committed = UINT64_C(0x100000006), .acknowledged = UINT64_C(0xfffffffe)};
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditReceiveAck(&rollover, 5), "ACK wrap");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, rollover.acknowledged, UINT64_C(0x100000005), "incorrect ACK wrap");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpCreditReceiveAck(&rollover, UINT32_MAX), "stale ACK across wrap rejected");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, rollover.acknowledged, UINT64_C(0x100000005), "stale ACK granted credit");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpCreditReceiveAck(&rollover, 7), "future ACK after wrap accepted");
}

int main(void)
{
    TEST_RUN_CASE(testU29);
    TEST_RUN_CASE(testEnvelope);
    TEST_RUN_CASE(testMalformed);
    TEST_RUN_CASE(testCredit);
    return 0;
}

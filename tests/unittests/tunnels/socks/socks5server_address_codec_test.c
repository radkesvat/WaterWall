/*
 * Covers: socks5server address codec; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: vector
 * Checks: Assertion labels include: requirement failed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5server_address_codec_unit
 */
#include "Socks5Server/address_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_assert.h"

#define CHECK(c) TEST_REQUIRE(TEST_FAILURE_EXIT, c, "requirement failed")

static void vector(const uint8_t *wire, size_t length, size_t address_length, uint16_t port)
{
    socks5_address_t result, original;
    memset(&original, 0xa5, sizeof(original));
    for (size_t i = 0; i < length; ++i)
    {
        memcpy(&result, &original, sizeof(result));
        CHECK(socks5AddressDecode(wire, i, &result) == kSocks5AddressNeedMore);
        CHECK(memcmp(&result, &original, sizeof(result)) == 0);
    }
    CHECK(socks5AddressDecode(wire, length, &result) == kSocks5AddressComplete);
    CHECK(result.kind == wire[0] && result.length == address_length && result.port == port &&
          result.consumed == length);
    CHECK(memcmp(result.bytes, wire + (wire[0] == 3 ? 2 : 1), address_length) == 0);
    uint8_t encoded[300], untouched[300];
    memset(encoded, 0x5a, sizeof(encoded));
    memcpy(untouched, encoded, sizeof(encoded));
    size_t written = 1000;
    CHECK(! socks5AddressEncode(&result, encoded, length - 1, &written));
    CHECK(written == 1000 && memcmp(encoded, untouched, sizeof(encoded)) == 0);
    CHECK(socks5AddressEncodedLength(&result) == length);
    CHECK(socks5AddressEncode(&result, encoded, length, &written));
    CHECK(written == length && memcmp(encoded, wire, length) == 0 && encoded[length] == 0x5a);
    CHECK(socks5AddressDecode(encoded, sizeof(encoded), &result) == kSocks5AddressComplete &&
          result.consumed == length);
    result.length = 256;
    memset(encoded, 0x5a, sizeof(encoded));
    written = 1000;
    CHECK(! socks5AddressEncode(&result, encoded, sizeof(encoded), &written));
    CHECK(written == 1000 && memcmp(encoded, untouched, sizeof(encoded)) == 0);
}
int main(void)
{
    testCaseSet("socks5server_address_codec_test");
    const uint8_t ipv4[]   = {1, 192, 0, 2, 5, 0x12, 0x34};
    const uint8_t ipv6[]   = {4, 0x20, 1, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xff, 0xff};
    const uint8_t domain[] = {3, 1, 'x', 0, 0};
    vector(ipv4, sizeof(ipv4), 4, 0x1234);
    vector(ipv6, sizeof(ipv6), 16, 65535);
    vector(domain, sizeof(domain), 1, 0);
    uint8_t maximum[259] = {3, 255};
    memset(maximum + 2, 'd', 255);
    maximum[257] = 0;
    maximum[258] = 1;
    vector(maximum, sizeof(maximum), 255, 1);
    const uint8_t bad[][2] = {{3, 0}, {2, 1}, {255, 1}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
    {
        socks5_address_t out, before;
        memset(&before, 0x5a, sizeof(before));
        memcpy(&out, &before, sizeof(out));
        CHECK(socks5AddressDecode(bad[i], 2, &out) == kSocks5AddressInvalid);
        CHECK(memcmp(&out, &before, sizeof(out)) == 0);
    }
    puts("SOCKS5 address codec vectors passed");
    return 0;
}

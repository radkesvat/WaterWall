/*
 * Covers: wsocket validation; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testValidCases, testInvalidCases, testImmutability, testNumericAddresses,
 * testResolverFallback. On Linux, getaddrinfo is wrapped to refuse resolution,
 * proving numeric parsing works independently of DNS and configured IP families.
 * Checks: Assertion labels include: <null>; writable IPv4 endpoint was rejected; verifyIPPort modified a
 * valid IPv4 input; writable IPv6 endpoint was rejected
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.wsocket_validation_unit
 */
#include "wsocket.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

#if defined(WW_TEST_WRAP_GETADDRINFO)
static unsigned resolver_calls;

int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **result);
int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **result)
{
    (void) host;
    (void) service;
    (void) hints;
    ++resolver_calls;
    *result = NULL;
    return EAI_NONAME;
}
#endif

static void testNumericAddresses(void)
{
    const struct
    {
        const char *text;
        int         family;
    } cases[] = {{"127.0.0.1", AF_INET},
                 {"::1", AF_INET6},
                 {"2001:db8:1122:3344:5566:7788:99aa:bbcc", AF_INET6},
                 {"::ffff:192.0.2.1", AF_INET6}};

    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        sockaddr_u address  = {0};
        sockaddr_u expected = {0};
        void      *expected_ip =
            cases[i].family == AF_INET ? (void *) &expected.sin.sin_addr : (void *) &expected.sin6.sin6_addr;
        require(inet_pton(cases[i].family, cases[i].text, expected_ip) == 1, "invalid numeric address fixture");
        memorySet(&address, 0xa5, sizeof(address));
        require(resolveAddr(cases[i].text, &address) == 0, "numeric address required resolution");
        if (cases[i].family == AF_INET6)
        {
            require(address.sin6.sin6_port == 0 && address.sin6.sin6_flowinfo == 0 && address.sin6.sin6_scope_id == 0,
                    "numeric IPv6 address retained uninitialized metadata");
#if defined(OS_DARWIN) || defined(OS_BSD)
            require(address.sin6.sin6_len == sizeof(address.sin6), "numeric IPv6 address length changed");
#endif
        }
        require(sockaddrSetIpAddressPort(&address, cases[i].text, 4321) == 0, "numeric address required resolution");
        require(address.sa.sa_family == cases[i].family, "numeric address family changed");
        require(sockaddrPort(&address) == 4321, "numeric address port changed");
        const void *actual_ip =
            cases[i].family == AF_INET ? (const void *) &address.sin.sin_addr : (const void *) &address.sin6.sin6_addr;
        const size_t length =
            cases[i].family == AF_INET ? sizeof(address.sin.sin_addr) : sizeof(address.sin6.sin6_addr);
        require(memoryEqual(actual_ip, expected_ip, length), "numeric address bytes changed");
    }
#if defined(WW_TEST_WRAP_GETADDRINFO)
    require(resolver_calls == 0, "numeric address reached getaddrinfo");
#endif
}

#if defined(WW_TEST_WRAP_GETADDRINFO)
static void testResolverFallback(void)
{
    const char *cases[] = {"example.invalid", "fe80::1%lo", "2001:db8::invalid"};
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        sockaddr_u     address = {0};
        const unsigned before  = resolver_calls;
        require(resolveAddr(cases[i], &address) == EAI_NONAME, "resolver error was not preserved");
        require(resolver_calls == before + 1, "nonliteral address skipped resolver fallback");
    }
}
#endif

static void expectValid(const char *value)
{
    if (! verifyIPPort(value))
    {
        fprintf(stderr, "expected valid ip:port was rejected: %s\n", value != NULL ? value : "<null>");
        exit(1);
    }
}

static void expectInvalid(const char *value)
{
    if (verifyIPPort(value))
    {
        fprintf(stderr, "expected invalid ip:port was accepted: %s\n", value != NULL ? value : "<null>");
        exit(1);
    }
}

static void testValidCases(void)
{
    expectValid("127.0.0.1:0");
    expectValid("127.0.0.1:1");
    expectValid("0.0.0.0:0");
    expectValid("255.255.255.255:65535");
    expectValid("[::1]:443");
    expectValid("[2001:db8::1]:65535");

    // Leading-zero decimal ports remain entirely numeric and stay in range.
    expectValid("127.0.0.1:00080");
    expectValid("[::1]:00000");
}

static void testInvalidCases(void)
{
    // NULL and empty.
    expectInvalid(NULL);
    expectInvalid("");

    // Missing host or port.
    expectInvalid(":80");
    expectInvalid("127.0.0.1:");
    expectInvalid("[]:443");
    expectInvalid("[::1]:");

    // Missing separator.
    expectInvalid("127.0.0.1");
    expectInvalid("[::1]");

    // Hostname plus port.
    expectInvalid("example.com:80");
    expectInvalid("localhost:80");

    // Unbracketed IPv6 plus port.
    expectInvalid("::1:443");
    expectInvalid("2001:db8::1:65535");

    // Bracketed IPv4.
    expectInvalid("[127.0.0.1]:80");

    // Unmatched, nested, or misplaced brackets.
    expectInvalid("[::1:443");
    expectInvalid("[[::1]]:443");
    expectInvalid("127.0.0.1]:80");
    expectInvalid("[::1]443");
    expectInvalid("[::1] :443");

    // More than one separator in the IPv4 form.
    expectInvalid("1.2.3.4:80:90");

    // Non-canonical or partially consumed IP presentation forms. The lenient lwIP
    // text parsers accept several of these (trailing junk, shorthand, hex); strict
    // inet_pton() validation must reject them all.
    expectInvalid("127.0.0.1 junk:80");
    expectInvalid("127.1:80");
    expectInvalid("0x7f000001:80");
    expectInvalid("[2001:db8::1 junk]:80");
    expectInvalid("[2001:db8::1junk]:80");

    // Malformed ports.
    expectInvalid("127.0.0.1:-1");
    expectInvalid("127.0.0.1:+1");
    expectInvalid("127.0.0.1: 80");
    expectInvalid("127.0.0.1:abc");
    expectInvalid("127.0.0.1:80abc");
    expectInvalid("127.0.0.1:80 81");
    expectInvalid("127.0.0.1:65536");
    expectInvalid("127.0.0.1:99999999999999");

    // Overlong host text (longer than INET6_ADDRSTRLEN can represent).
    {
        char overlong[64];
        overlong[0] = '[';
        memorySet(overlong + 1, 'a', 50);
        memoryCopy(overlong + 51, "]:443", sizeof("]:443"));
        expectInvalid(overlong);
    }
}

static void testImmutability(void)
{
    // 1. A writable buffer must be byte-for-byte unchanged after a successful parse.
    {
        char       writable[] = "127.0.0.1:443";
        const char snapshot[] = "127.0.0.1:443";
        require(verifyIPPort(writable), "writable IPv4 endpoint was rejected");
        require(memoryEqual(writable, snapshot, sizeof(snapshot)), "verifyIPPort modified a valid IPv4 input");
    }

    // 2. A writable IPv6 buffer must also be unchanged.
    {
        char       writable[] = "[2001:db8::1]:65535";
        const char snapshot[] = "[2001:db8::1]:65535";
        require(verifyIPPort(writable), "writable IPv6 endpoint was rejected");
        require(memoryEqual(writable, snapshot, sizeof(snapshot)), "verifyIPPort modified a valid IPv6 input");
    }

    // 3. Immutability must hold on a failed parse as well.
    {
        char       writable[] = "127.0.0.1:70000";
        const char snapshot[] = "127.0.0.1:70000";
        require(! verifyIPPort(writable), "out-of-range port was accepted");
        require(memoryEqual(writable, snapshot, sizeof(snapshot)), "verifyIPPort modified an invalid input");
    }

    // 4. String literals must never be written to; a write would trap here.
    require(verifyIPPort("127.0.0.1:443"), "IPv4 string literal was rejected");
    require(verifyIPPort("[::1]:443"), "IPv6 string literal was rejected");
    require(! verifyIPPort("::1:443"), "unbracketed IPv6 string literal was accepted");
}

int main(void)
{
    testCaseSet("wsocket_validation_test");
    testValidCases();
    testInvalidCases();
    testImmutability();
    TEST_RUN_CASE(testNumericAddresses);
#if defined(WW_TEST_WRAP_GETADDRINFO)
    TEST_RUN_CASE(testResolverFallback);
#endif
    return 0;
}

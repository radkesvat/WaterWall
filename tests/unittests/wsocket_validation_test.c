#include "wsocket.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

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
    testValidCases();
    testInvalidCases();
    testImmutability();
    return 0;
}

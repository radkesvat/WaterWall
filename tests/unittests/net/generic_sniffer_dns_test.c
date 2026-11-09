/*
 * Covers: genericsnifferSniffDnsQuery accept/reject vectors.
 * Setup: Deterministic in-memory DNS, TLS and HTTP payload bytes; no lines, workers or sockets.
 * Cases: testAcceptsRealQueries, testAcceptsBoundaryNames, testRejectsHeaderViolations,
 * testRejectsQuestionViolations, testTruncatedPrefixesAreMissing, testRejectsOtherProtocols,
 * testPseudoRandomInputIsDecided
 * Checks: Assertion labels name each vector, e.g. "glibc A query", "QR=1 response", "label longer than 63".
 * Limits: Validates the sniffer function only; Router rule matching is covered by the Router suites.
 * CTest: waterwall.generic_sniffer_dns_unit
 */
#include "generic_sniffer.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kTestDnsBufferBytes = 600
};

// glibc-style "example.com A", RD=1, QDCOUNT=1.
static const uint8_t kQueryA[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',
    'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
};

// dig/c-ares-style "www.example.com AAAA", RD=1 AD=1, ARCOUNT=1 with an EDNS OPT record (UDP 1232).
static const uint8_t kQueryAaaaEdns[] = {
    0xab, 0xcd, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 'w',  'w',
    'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00,
    0x1c, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void putHeader(uint8_t *p, uint8_t flags_hi, uint8_t flags_lo, uint16_t qdcount)
{
    memorySet(p, 0, 12);
    p[0] = 0x55;
    p[1] = 0xaa;
    p[2] = flags_hi;
    p[3] = flags_lo;
    p[4] = (uint8_t) (qdcount >> 8U);
    p[5] = (uint8_t) (qdcount & 0xffU);
}

// Writes labels of the given lengths ('a' filled), a root label and QTYPE/QCLASS; returns total length.
static uint32_t buildQuery(uint8_t *p, const uint8_t *label_lens, uint32_t label_count, uint16_t qclass)
{
    putHeader(p, 0x01, 0x00, 1);
    uint32_t off = 12;
    for (uint32_t i = 0; i < label_count; ++i)
    {
        p[off++] = label_lens[i];
        memorySet(p + off, 'a', label_lens[i]);
        off += label_lens[i];
    }
    p[off++] = 0x00;
    p[off++] = 0x00;
    p[off++] = 0x01;
    p[off++] = (uint8_t) (qclass >> 8U);
    p[off++] = (uint8_t) (qclass & 0xffU);
    return off;
}

static generic_sniffer_result_t sniff(const uint8_t *p, uint32_t n)
{
    return genericsnifferSniffDnsQuery(p, n);
}

static void testAcceptsRealQueries(void)
{
    require(sniff(kQueryA, sizeof(kQueryA)) == kGenericSnifferFound, "glibc A query");
    require(sniff(kQueryAaaaEdns, sizeof(kQueryAaaaEdns)) == kGenericSnifferFound, "AAAA query with EDNS OPT");

    // Only the question is required: the trailing OPT record may be cut off.
    require(sniff(kQueryAaaaEdns, 33) == kGenericSnifferFound, "AAAA question without additional section");

    uint8_t buf[kTestDnsBufferBytes];

    // ". NS" priming query: root-only QNAME.
    putHeader(buf, 0x00, 0x00, 1);
    buf[12] = 0x00;
    buf[13] = 0x00;
    buf[14] = 0x02;
    buf[15] = 0x00;
    buf[16] = 0x01;
    require(sniff(buf, 17) == kGenericSnifferFound, "root NS query");

    // mDNS-style query: TC set, QU bit in QCLASS, several questions.
    static const uint8_t one_label[] = {5};
    uint32_t             n           = buildQuery(buf, one_label, 1, 0x8001);
    buf[2]                           = 0x02; // TC
    buf[5]                           = 3;    // QDCOUNT
    require(sniff(buf, n) == kGenericSnifferFound, "mDNS QU query with TC and QDCOUNT=3");

    static const uint16_t classes[] = {1, 3, 4, 254, 255};
    for (uint32_t i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i)
    {
        n = buildQuery(buf, one_label, 1, classes[i]);
        require(sniff(buf, n) == kGenericSnifferFound, "known QCLASS accepted");
    }

    n      = buildQuery(buf, one_label, 1, 1);
    buf[5] = (uint8_t) kGenericSnifferDnsMaxQuestions;
    require(sniff(buf, n) == kGenericSnifferFound, "QDCOUNT at the bound");
}

static void testAcceptsBoundaryNames(void)
{
    uint8_t buf[kTestDnsBufferBytes];

    static const uint8_t label63[] = {63};
    require(sniff(buf, buildQuery(buf, label63, 1, 1)) == kGenericSnifferFound, "63-byte label");

    // 3 * (1 + 63) + (1 + 61) + root = 255 encoded bytes.
    static const uint8_t name255[] = {63, 63, 63, 61};
    require(sniff(buf, buildQuery(buf, name255, 4, 1)) == kGenericSnifferFound, "255-byte encoded name");
}

static void testRejectsHeaderViolations(void)
{
    uint8_t buf[sizeof(kQueryA)];

    require(sniff(kQueryA, 0) == kGenericSnifferNeedMore, "empty input asks for more");
    require(sniff(kQueryA, 11) == kGenericSnifferMissing, "short header");
    require(sniff(kQueryA, 12) == kGenericSnifferMissing, "header without question");

    memoryCopy(buf, kQueryA, sizeof(buf));
    buf[2] = 0x81;
    buf[3] = 0x80;
    require(sniff(buf, sizeof(buf)) == kGenericSnifferMissing, "QR=1 response");

    static const uint8_t opcodes[] = {1, 2, 4, 5, 6, 15};
    for (uint32_t i = 0; i < sizeof(opcodes); ++i)
    {
        memoryCopy(buf, kQueryA, sizeof(buf));
        buf[2] = (uint8_t) (0x01U | (uint8_t) (opcodes[i] << 3U));
        require(sniff(buf, sizeof(buf)) == kGenericSnifferMissing, "non-standard opcode");
    }

    memoryCopy(buf, kQueryA, sizeof(buf));
    buf[5] = 0;
    require(sniff(buf, sizeof(buf)) == kGenericSnifferMissing, "QDCOUNT=0");

    buf[5] = (uint8_t) (kGenericSnifferDnsMaxQuestions + 1);
    require(sniff(buf, sizeof(buf)) == kGenericSnifferMissing, "QDCOUNT above the bound");

    buf[4] = 0xff;
    buf[5] = 0xff;
    require(sniff(buf, sizeof(buf)) == kGenericSnifferMissing, "QDCOUNT=65535");
}

static void testRejectsQuestionViolations(void)
{
    uint8_t buf[kTestDnsBufferBytes];

    static const uint8_t label64[] = {64};
    require(sniff(buf, buildQuery(buf, label64, 1, 1)) == kGenericSnifferMissing, "label longer than 63");

    static const uint8_t name256[] = {63, 63, 63, 62};
    require(sniff(buf, buildQuery(buf, name256, 4, 1)) == kGenericSnifferMissing, "encoded name longer than 255");

    static const uint8_t name_long[] = {63, 63, 63, 63, 63, 63};
    require(sniff(buf, buildQuery(buf, name_long, 6, 1)) == kGenericSnifferMissing, "far too long name");

    // Compression pointer to offset 12 as the whole QNAME, and after a first label.
    putHeader(buf, 0x01, 0x00, 1);
    static const uint8_t pointer_only[] = {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01};
    memoryCopy(buf + 12, pointer_only, sizeof(pointer_only));
    require(sniff(buf, 12 + sizeof(pointer_only)) == kGenericSnifferMissing, "compression pointer QNAME");

    static const uint8_t label_then_pointer[] = {0x03, 'w', 'w', 'w', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01};
    memoryCopy(buf + 12, label_then_pointer, sizeof(label_then_pointer));
    require(sniff(buf, 12 + sizeof(label_then_pointer)) == kGenericSnifferMissing, "compression pointer in QNAME");

    // Reserved (0x40) and extended (0x80) label types.
    static const uint8_t reserved[] = {0x41, 'a', 0x00, 0x00, 0x01, 0x00, 0x01};
    memoryCopy(buf + 12, reserved, sizeof(reserved));
    require(sniff(buf, 12 + sizeof(reserved)) == kGenericSnifferMissing, "0x40 label type");
    buf[12] = 0x81;
    require(sniff(buf, 12 + sizeof(reserved)) == kGenericSnifferMissing, "0x80 label type");

    static const uint8_t  one_label[]   = {5};
    static const uint16_t bad_classes[] = {0, 2, 5, 0x00fe + 2, 0x8000, 0x1234};
    for (uint32_t i = 0; i < sizeof(bad_classes) / sizeof(bad_classes[0]); ++i)
    {
        require(sniff(buf, buildQuery(buf, one_label, 1, bad_classes[i])) == kGenericSnifferMissing,
                "unknown QCLASS rejected");
    }
}

static void testTruncatedPrefixesAreMissing(void)
{
    // Every prefix that ends before QTYPE+QCLASS is complete is a malformed datagram, never NeedMore.
    for (uint32_t n = 1; n < 29; ++n)
    {
        require(sniff(kQueryA, n) == kGenericSnifferMissing, "truncated A query prefix");
    }
    require(sniff(kQueryA, 29) == kGenericSnifferFound, "complete A question");

    uint8_t buf[sizeof(kQueryA)];
    memoryCopy(buf, kQueryA, sizeof(buf));
    require(sniff(buf, 25) == kGenericSnifferMissing, "name without QTYPE/QCLASS");
    require(sniff(buf, 27) == kGenericSnifferMissing, "QTYPE without QCLASS");
    require(sniff(buf, 20) == kGenericSnifferMissing, "name ends inside a label");
}

static void testRejectsOtherProtocols(void)
{
    // TLS 1.2 record + ClientHello prefix; record length 0x0200 makes the DNS view QR=0, OPCODE=0, QDCOUNT=1.
    uint8_t tls[80];
    memorySet(tls, 0, sizeof(tls));
    static const uint8_t tls_prefix[] = {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03};
    memoryCopy(tls, tls_prefix, sizeof(tls_prefix));
    for (uint32_t i = sizeof(tls_prefix); i < sizeof(tls); ++i)
    {
        tls[i] = (uint8_t) (0x9dU * i + 0x31U);
    }
    require(sniff(tls, sizeof(tls)) == kGenericSnifferMissing, "TLS ClientHello prefix");

    static const char *const http[] = {
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /dns-query HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "CONNECT example.com:443 HTTP/1.1\r\n\r\n",
    };
    for (uint32_t i = 0; i < sizeof(http) / sizeof(http[0]); ++i)
    {
        require(sniff((const uint8_t *) http[i], (uint32_t) stringLength(http[i])) == kGenericSnifferMissing,
                "HTTP request prefix");
    }

    static const uint8_t bittorrent[] = {19,  'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r',
                                         'o', 't', 'o', 'c', 'o', 'l', 0,   0,   0,   0,   0,   0,   0,   0};
    require(sniff(bittorrent, sizeof(bittorrent)) == kGenericSnifferMissing, "BitTorrent handshake");

    // DNS over TCP carries a 2-byte length prefix; it is not a datagram query.
    uint8_t tcp_dns[2 + sizeof(kQueryA)];
    tcp_dns[0] = 0x00;
    tcp_dns[1] = (uint8_t) sizeof(kQueryA);
    memoryCopy(tcp_dns + 2, kQueryA, sizeof(kQueryA));
    require(sniff(tcp_dns, sizeof(tcp_dns)) == kGenericSnifferMissing, "length-prefixed TCP DNS");
}

static void testPseudoRandomInputIsDecided(void)
{
    // Every prefix of pseudo-random bytes is decided without reading past payload_len.
    uint8_t  buf[512];
    uint32_t state = 0x2545f491U;
    uint32_t found = 0;
    for (uint32_t round = 0; round < 64; ++round)
    {
        for (uint32_t i = 0; i < sizeof(buf); ++i)
        {
            state  = state * 1664525U + 1013904223U;
            buf[i] = (uint8_t) (state >> 24U);
        }
        for (uint32_t n = 1; n <= sizeof(buf); n += 7)
        {
            generic_sniffer_result_t result = sniff(buf, n);
            require(result == kGenericSnifferFound || result == kGenericSnifferMissing, "non-empty input decided");
            found += result == kGenericSnifferFound ? 1U : 0U;
        }
    }
    require(found == 0, "pseudo-random bytes classified as a DNS query");
}

int main(void)
{
    TEST_RUN_CASE(testAcceptsRealQueries);
    TEST_RUN_CASE(testAcceptsBoundaryNames);
    TEST_RUN_CASE(testRejectsHeaderViolations);
    TEST_RUN_CASE(testRejectsQuestionViolations);
    TEST_RUN_CASE(testTruncatedPrefixesAreMissing);
    TEST_RUN_CASE(testRejectsOtherProtocols);
    TEST_RUN_CASE(testPseudoRandomInputIsDecided);
    return 0;
}

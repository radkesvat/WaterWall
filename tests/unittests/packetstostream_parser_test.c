// Unit tests for the IPv4-header-based framing parser used by PacketsToStream (and, with identical
// code, StreamToPackets). The focus is the size-based extractor packetstostreamTryReadIPv4Packet and
// the framing-side guard packetstostreamIsForwardableIpv4Packet:
//
//   * correct extraction of one/many/split IPv4 packets using the IPv4 total-length field
//   * IPv4-only behavior (IPv6 and non-IPv4 heads are dropped / resynchronized past)
//   * garbage resilience: no input pattern crashes, hangs, or reads out of bounds, and a clean
//     garbage prefix is always re-synchronized so following valid packets are recovered intact
//
// The two tunnels share byte-for-byte identical parser logic, so exercising one is sufficient to
// validate the algorithm.

#include "PacketsToStream/structure.h"

#include <stdio.h>

static int g_failures = 0;

static void require(bool cond, const char *msg)
{
    if (! cond)
    {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_failures++;
    }
}

// Builds a minimal, internally consistent IPv4 packet of total_len bytes into dst. The payload is
// filled with payload_fill so the test can recognize a recovered packet.
static uint32_t buildIpv4(uint8_t *dst, uint16_t total_len, uint8_t proto, uint8_t payload_fill)
{
    memoryZero(dst, IP_HLEN);

    struct ip_hdr *ip = (struct ip_hdr *) dst;
    IPH_VHL_SET(ip, 4, IP_HLEN / 4);
    IPH_LEN_SET(ip, lwip_htons(total_len));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, proto);
    IPH_CHKSUM_SET(ip, 0);

    for (uint32_t i = IP_HLEN; i < total_len; ++i)
    {
        dst[i] = payload_fill;
    }
    return total_len;
}

// Pushes raw bytes into the stream, fragmenting them across pooled buffers of at most chunk bytes so
// the parser is exercised against arbitrary stream fragmentation.
static void pushBytes(buffer_stream_t *bs, buffer_pool_t *pool, const uint8_t *data, uint32_t len,
                      uint32_t chunk)
{
    uint32_t off = 0;
    if (chunk == 0)
    {
        chunk = len;
    }
    while (off < len)
    {
        sbuf_t  *b   = bufferpoolGetSmallBuffer(pool);
        uint32_t cap = sbufGetMaximumWriteableSize(b);
        uint32_t n   = len - off;
        if (n > chunk)
        {
            n = chunk;
        }
        if (n > cap)
        {
            n = cap;
        }
        sbufSetLength(b, n);
        memoryCopy(sbufGetMutablePtr(b), data + off, n);
        bufferstreamPush(bs, b);
        off += n;
    }
}

// Extracts every packet currently available, recycling each one and returning how many were read.
static int drainCount(buffer_stream_t *bs, buffer_pool_t *pool)
{
    int     n = 0;
    sbuf_t *p = NULL;
    while (packetstostreamTryReadIPv4Packet(bs, &p))
    {
        require(p != NULL, "drain: extractor returned true with NULL packet");
        n++;
        bufferpoolReuseBuffer(pool, p);
    }
    return n;
}

static void testSinglePacket(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t raw[64];
    uint32_t len = buildIpv4(raw, 40, IP_PROTO_TCP, 0xAB);

    pushBytes(bs, pool, raw, len, 0);

    sbuf_t *p = NULL;
    require(packetstostreamTryReadIPv4Packet(bs, &p), "single: expected a packet");
    require(p != NULL && sbufGetLength(p) == 40, "single: wrong extracted length");
    if (p != NULL)
    {
        const uint8_t *d = sbufGetRawPtr(p);
        require(d[IP_HLEN] == 0xAB && d[39] == 0xAB, "single: payload mismatch");
        bufferpoolReuseBuffer(pool, p);
    }
    require(! packetstostreamTryReadIPv4Packet(bs, &p), "single: stream should be empty now");
    require(bufferstreamGetBufLen(bs) == 0, "single: leftover bytes");
}

static void testTwoConcatenated(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t raw[200];
    uint32_t a = buildIpv4(raw, 40, IP_PROTO_UDP, 0x11);
    uint32_t b = buildIpv4(raw + a, 75, IP_PROTO_TCP, 0x22);

    pushBytes(bs, pool, raw, a + b, 16); // small fragments

    sbuf_t *p = NULL;
    require(packetstostreamTryReadIPv4Packet(bs, &p), "concat: expected first packet");
    require(p != NULL && sbufGetLength(p) == 40, "concat: first length wrong");
    if (p) bufferpoolReuseBuffer(pool, p);

    require(packetstostreamTryReadIPv4Packet(bs, &p), "concat: expected second packet");
    require(p != NULL && sbufGetLength(p) == 75, "concat: second length wrong");
    if (p) bufferpoolReuseBuffer(pool, p);

    require(! packetstostreamTryReadIPv4Packet(bs, &p), "concat: stream should be empty");
}

static void testSplitPacket(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t raw[128];
    uint32_t len = buildIpv4(raw, 100, IP_PROTO_TCP, 0x5A);

    // First only part of the header.
    pushBytes(bs, pool, raw, 8, 0);
    sbuf_t *p = NULL;
    require(! packetstostreamTryReadIPv4Packet(bs, &p), "split: should wait for full header");

    // Rest of the header + part of the body.
    pushBytes(bs, pool, raw + 8, 50, 0);
    require(! packetstostreamTryReadIPv4Packet(bs, &p), "split: should wait for full body");

    // Remainder.
    pushBytes(bs, pool, raw + 58, len - 58, 0);
    require(packetstostreamTryReadIPv4Packet(bs, &p), "split: expected packet once complete");
    require(p != NULL && sbufGetLength(p) == 100, "split: wrong length");
    if (p) bufferpoolReuseBuffer(pool, p);
}

static void testGarbagePrefixRecovers(buffer_stream_t *bs, buffer_pool_t *pool)
{
    // A run of bytes that can never begin a valid IPv4 packet (version nibble 0), followed by a real
    // packet. The parser must drop the garbage and recover the valid packet intact.
    uint8_t raw[300];
    memoryZero(raw, 137);
    uint32_t len = 137 + buildIpv4(raw + 137, 60, IP_PROTO_ICMP, 0xC7);

    pushBytes(bs, pool, raw, len, 23);

    sbuf_t *p   = NULL;
    bool    got = false;
    while (packetstostreamTryReadIPv4Packet(bs, &p))
    {
        require(p != NULL, "garbage-prefix: NULL packet");
        if (p != NULL && sbufGetLength(p) == 60)
        {
            const uint8_t *d = sbufGetRawPtr(p);
            if (d[IP_HLEN] == 0xC7)
            {
                got = true;
            }
        }
        if (p) bufferpoolReuseBuffer(pool, p);
    }
    require(got, "garbage-prefix: valid packet was not recovered after garbage");
    require(bufferstreamGetBufLen(bs) < (size_t) IP_HLEN, "garbage-prefix: parser did not drain");
}

// Feeds adversarial patterns and asserts the parser always terminates, never returns a bogus
// success, and makes forward progress (drains to less than a header, or extracts something). If any
// pattern caused an unbounded loop the test process would hang; if it read out of bounds the
// buffer_stream debug asserts / sanitizers would trip.
static void testAdversarialNoCrash(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t garbage[1024];

    // Pattern 1: all 0x40 -> version 4 but header length 0, so every offset is structurally invalid.
    memorySet(garbage, 0x40, sizeof(garbage));
    pushBytes(bs, pool, garbage, sizeof(garbage), 64);
    drainCount(bs, pool);
    require(bufferstreamGetBufLen(bs) < (size_t) IP_HLEN, "adversarial 0x40: did not drain");

    // Pattern 2: all 0xFF -> version 15, non-IPv4 everywhere.
    memorySet(garbage, 0xFF, sizeof(garbage));
    pushBytes(bs, pool, garbage, sizeof(garbage), 7);
    drainCount(bs, pool);
    require(bufferstreamGetBufLen(bs) < (size_t) IP_HLEN, "adversarial 0xFF: did not drain");

    // Pattern 3: all 0x60 -> version 6 (IPv6), must be dropped entirely.
    memorySet(garbage, 0x60, sizeof(garbage));
    pushBytes(bs, pool, garbage, sizeof(garbage), 100);
    drainCount(bs, pool);
    require(bufferstreamGetBufLen(bs) < (size_t) IP_HLEN, "adversarial 0x60 (ipv6): did not drain");

    // Drain whatever residue is left so the stream is clean for the next test.
    bufferstreamEmpty(bs);
}

// The documented worst case: a head that *looks* like a valid IPv4 packet but is really garbage. The
// parser must trust the size field (waiting, then forwarding a garbage-sized packet) without ever
// crashing, and must resync afterwards.
static void testLooksValidWorstCase(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t head[IP_HLEN];
    buildIpv4(head, 1000, IP_PROTO_TCP, 0x00); // claims 1000 bytes total

    // Only the 20-byte header is present: parser must wait, not crash, not extract.
    pushBytes(bs, pool, head, IP_HLEN, 0);
    sbuf_t *p = NULL;
    require(! packetstostreamTryReadIPv4Packet(bs, &p), "worst-case: must wait for claimed size");
    require(bufferstreamGetBufLen(bs) == (size_t) IP_HLEN, "worst-case: must keep buffered head");

    // Provide the remaining claimed bytes: the parser forwards the garbage-sized packet (size 1000)
    // exactly as the size field demanded. This is acceptable per the contract.
    uint8_t filler[1000 - IP_HLEN];
    memorySet(filler, 0x99, sizeof(filler));
    pushBytes(bs, pool, filler, sizeof(filler), 128);
    require(packetstostreamTryReadIPv4Packet(bs, &p), "worst-case: should forward the sized packet");
    require(p != NULL && sbufGetLength(p) == 1000, "worst-case: forwarded wrong size");
    if (p) bufferpoolReuseBuffer(pool, p);
    require(bufferstreamGetBufLen(bs) == 0, "worst-case: stream should be drained");
}

// Bounded pseudo-random fuzz: many rounds of random bytes (in random fragment sizes). Each round
// must terminate (an unbounded loop would hang the test) and never return a NULL packet on success.
//
// After the random bytes, a large clean-zero gap and then a recognizable valid packet are pushed.
// The zero gap is wide enough (> kMaxAllowedPacketLength + a resync window) that any garbage-induced
// "valid-looking but waiting" head is completed and consumed inside the gap, after which every head
// is 0x00 (structurally invalid) so the parser resynchronizes onto the sentinel. This deterministically
// proves recovery: no random prefix can permanently desynchronize the extractor.
static void testFuzzRecovers(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint32_t seed = 0xC0FFEEu;
    for (int round = 0; round < 100; ++round)
    {
        uint8_t buf[512];
        uint32_t glen = 20 + (seed % 400);
        for (uint32_t i = 0; i < glen; ++i)
        {
            seed = seed * 1103515245u + 12345u;
            buf[i] = (uint8_t) (seed >> 16);
        }
        uint32_t chunk = 1 + (seed % 97);
        pushBytes(bs, pool, buf, glen, chunk);

        sbuf_t *p = NULL;
        int     guard = 0;
        while (packetstostreamTryReadIPv4Packet(bs, &p)) // must always terminate
        {
            require(p != NULL, "fuzz: success with NULL packet");
            if (p) bufferpoolReuseBuffer(pool, p);
            require(++guard < 100000, "fuzz: extractor did not terminate");
        }

        // Wide clean-zero gap then a sentinel packet.
        uint8_t zeros[2048];
        memoryZero(zeros, sizeof(zeros));
        pushBytes(bs, pool, zeros, sizeof(zeros), 211);

        uint8_t pkt[80];
        uint32_t plen = buildIpv4(pkt, 64, IP_PROTO_TCP, 0x7E);
        pushBytes(bs, pool, pkt, plen, 9);

        bool got = false;
        while (packetstostreamTryReadIPv4Packet(bs, &p))
        {
            if (p != NULL && sbufGetLength(p) == 64)
            {
                const uint8_t *d = sbufGetRawPtr(p);
                if (d[IP_HLEN] == 0x7E)
                {
                    got = true;
                }
            }
            if (p) bufferpoolReuseBuffer(pool, p);
        }
        require(got, "fuzz: sentinel packet not recovered after garbage and clean gap");
        bufferstreamEmpty(bs);
    }
}

static void testIsForwardable(buffer_pool_t *pool)
{
    sbuf_t *b = bufferpoolGetSmallBuffer(pool);
    buildIpv4(sbufGetMutablePtr(b), 0, 0, 0); // placeholder, set length below
    sbufSetLength(b, 50);
    buildIpv4(sbufGetMutablePtr(b), 50, IP_PROTO_TCP, 0x33);
    require(packetstostreamIsForwardableIpv4Packet(b), "forwardable: valid IPv4 should pass");

    // Length/total-length mismatch.
    sbufSetLength(b, 50);
    buildIpv4(sbufGetMutablePtr(b), 49, IP_PROTO_TCP, 0x33);
    require(! packetstostreamIsForwardableIpv4Packet(b), "forwardable: total-length mismatch must fail");

    // IPv6 version nibble.
    sbufSetLength(b, 50);
    memoryZero(sbufGetMutablePtr(b), 50);
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x60;
    require(! packetstostreamIsForwardableIpv4Packet(b), "forwardable: IPv6 must be dropped");

    // Too short to be IPv4.
    sbufSetLength(b, 10);
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x45;
    require(! packetstostreamIsForwardableIpv4Packet(b), "forwardable: sub-header length must fail");
    bufferpoolReuseBuffer(pool, b);

    // Oversized packet (> kMaxAllowedPacketLength) using a large buffer.
    sbuf_t *big = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(big, kMaxAllowedPacketLength + 1);
    memoryZero(sbufGetMutablePtr(big), IP_HLEN);
    ((uint8_t *) sbufGetMutablePtr(big))[0] = 0x45;
    require(! packetstostreamIsForwardableIpv4Packet(big), "forwardable: oversized packet must fail");
    bufferpoolReuseBuffer(pool, big);
}

int main(void)
{
    master_pool_t *mp_large = masterpoolCreateWithCapacity(64);
    master_pool_t *mp_small = masterpoolCreateWithCapacity(64);
    buffer_pool_t *pool     = bufferpoolCreate(mp_large, mp_small, 64, 8192, SMALL_BUFFER_SIZE);

    buffer_stream_t bs = bufferstreamCreate(pool, 0);

    testSinglePacket(&bs, pool);
    testTwoConcatenated(&bs, pool);
    testSplitPacket(&bs, pool);
    testGarbagePrefixRecovers(&bs, pool);
    testAdversarialNoCrash(&bs, pool);
    testLooksValidWorstCase(&bs, pool);
    testFuzzRecovers(&bs, pool);
    testIsForwardable(pool);

    bufferstreamDestroy(&bs);

    if (g_failures == 0)
    {
        printf("packetstostream_parser_test: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "packetstostream_parser_test: %d check(s) failed\n", g_failures);
    return 1;
}

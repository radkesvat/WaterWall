/*
 * Shared IPv4 stream codec: fragmented/coalesced extraction, resynchronization,
 * boundary geometry, validation modes/checksums, and byte/ownership preservation.
 * CTest: waterwall.ipv4_stream_codec_unit
 * Node delivery admission and lifecycle are covered by the bridge fixtures.
 */
#include "Ipv4StreamCodec/codec.h"

static int  g_failures         = 0;
static bool g_separate_entries = false;

#include "test_assert.h"

#define require(condition, message)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(condition, message))                                                                          \
            ++g_failures;                                                                                              \
    } while (0)

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
// the parser is exercised with both merge-eligible and capacity-limited separate entries.
static void pushBytes(buffer_stream_t *bs, buffer_pool_t *pool, const uint8_t *data, uint32_t len, uint32_t chunk)
{
    uint32_t     off              = 0;
    const size_t previous_entries = bufferstreamGetEntryCount(bs);
    size_t       pushed           = 0;
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
        if (g_separate_entries)
        {
            sbufSetLength(b, cap - n);
            sbufShiftRight(b, cap - n);
            require(sbufGetMaximumWriteableSize(b) == n, "fragment fixture retained spare capacity");
        }
        sbufSetLength(b, n);
        memoryCopy(sbufGetMutablePtr(b), data + off, n);
        bufferstreamPush(bs, b);
        off += n;
        ++pushed;
    }
    /* Reads may combine storage and leave a residual tail with spare capacity.
     * Starting empty proves the separate-entry geometry without constraining reads. */
    if (g_separate_entries && previous_entries == 0)
    {
        require(bufferstreamGetEntryCount(bs) == previous_entries + pushed,
                "fragment fixture did not retain each separate entry");
    }
}

// Extracts every packet currently available, recycling each one and returning how many were read.
static int drainCount(buffer_stream_t *bs, buffer_pool_t *pool)
{
    int     n = 0;
    sbuf_t *p = NULL;
    while (ipv4streamTryReadPacket(bs, &p))
    {
        require(p != NULL, "drain: extractor returned true with NULL packet");
        n++;
        bufferpoolReuseBuffer(pool, p);
    }
    return n;
}

static void testSinglePacket(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t  raw[64];
    uint32_t len = buildIpv4(raw, 40, IP_PROTO_TCP, 0xAB);

    pushBytes(bs, pool, raw, len, 0);

    sbuf_t *p = NULL;
    require(ipv4streamTryReadPacket(bs, &p), "single: expected a packet");
    require(p != NULL && sbufGetLength(p) == 40, "single: wrong extracted length");
    if (p != NULL)
    {
        const uint8_t *d = sbufGetRawPtr(p);
        require(d[IP_HLEN] == 0xAB && d[39] == 0xAB, "single: payload mismatch");
        bufferpoolReuseBuffer(pool, p);
    }
    require(! ipv4streamTryReadPacket(bs, &p), "single: stream should be empty now");
    require(bufferstreamGetBufLen(bs) == 0, "single: leftover bytes");
}

static void testTwoConcatenated(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t  raw[200];
    uint32_t a = buildIpv4(raw, 40, IP_PROTO_UDP, 0x11);
    uint32_t b = buildIpv4(raw + a, 75, IP_PROTO_TCP, 0x22);

    pushBytes(bs, pool, raw, a + b, 16); // small fragments

    sbuf_t *p = NULL;
    require(ipv4streamTryReadPacket(bs, &p), "concat: expected first packet");
    require(p != NULL && sbufGetLength(p) == 40, "concat: first length wrong");
    if (p)
        bufferpoolReuseBuffer(pool, p);

    require(ipv4streamTryReadPacket(bs, &p), "concat: expected second packet");
    require(p != NULL && sbufGetLength(p) == 75, "concat: second length wrong");
    if (p)
        bufferpoolReuseBuffer(pool, p);

    require(! ipv4streamTryReadPacket(bs, &p), "concat: stream should be empty");
}

static void testSplitPacket(buffer_stream_t *bs, buffer_pool_t *pool)
{
    uint8_t  raw[128];
    uint32_t len = buildIpv4(raw, 100, IP_PROTO_TCP, 0x5A);

    // First only part of the header.
    pushBytes(bs, pool, raw, 8, 0);
    sbuf_t *p = NULL;
    require(! ipv4streamTryReadPacket(bs, &p), "split: should wait for full header");

    // Rest of the header + part of the body.
    pushBytes(bs, pool, raw + 8, 50, 0);
    require(! ipv4streamTryReadPacket(bs, &p), "split: should wait for full body");

    // Remainder.
    pushBytes(bs, pool, raw + 58, len - 58, 0);
    require(ipv4streamTryReadPacket(bs, &p), "split: expected packet once complete");
    require(p != NULL && sbufGetLength(p) == 100, "split: wrong length");
    if (p)
        bufferpoolReuseBuffer(pool, p);
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
    while (ipv4streamTryReadPacket(bs, &p))
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
        if (p)
            bufferpoolReuseBuffer(pool, p);
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
    enum
    {
        kWorstCasePacketLength = 1000
    };

    uint8_t head[IP_HLEN];
    buildIpv4(head, IP_HLEN, IP_PROTO_TCP, 0x00);
    IPH_LEN_SET((struct ip_hdr *) head, lwip_htons(kWorstCasePacketLength));

    // Only the 20-byte header is present: parser must wait, not crash, not extract.
    pushBytes(bs, pool, head, IP_HLEN, 0);
    sbuf_t *p = NULL;
    require(! ipv4streamTryReadPacket(bs, &p), "worst-case: must wait for claimed size");
    require(bufferstreamGetBufLen(bs) == (size_t) IP_HLEN, "worst-case: must keep buffered head");

    // Provide the remaining claimed bytes: the parser forwards the garbage-sized packet (size 1000)
    // exactly as the size field demanded. This is acceptable per the contract.
    uint8_t filler[kWorstCasePacketLength - IP_HLEN];
    memorySet(filler, 0x99, sizeof(filler));
    pushBytes(bs, pool, filler, sizeof(filler), 128);
    require(ipv4streamTryReadPacket(bs, &p), "worst-case: should forward the sized packet");
    require(p != NULL && sbufGetLength(p) == kWorstCasePacketLength, "worst-case: forwarded wrong size");
    if (p)
        bufferpoolReuseBuffer(pool, p);
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
        uint8_t  buf[512];
        uint32_t glen = 20 + (seed % 400);
        for (uint32_t i = 0; i < glen; ++i)
        {
            seed   = seed * 1103515245u + 12345u;
            buf[i] = (uint8_t) (seed >> 16);
        }
        uint32_t chunk = 1 + (seed % 97);
        pushBytes(bs, pool, buf, glen, chunk);

        sbuf_t *p     = NULL;
        int     guard = 0;
        while (ipv4streamTryReadPacket(bs, &p)) // must always terminate
        {
            require(p != NULL, "fuzz: success with NULL packet");
            if (p)
                bufferpoolReuseBuffer(pool, p);
            require(++guard < 100000, "fuzz: extractor did not terminate");
        }

        // Wide clean-zero gap then a sentinel packet.
        uint8_t zeros[2048];
        memoryZero(zeros, sizeof(zeros));
        pushBytes(bs, pool, zeros, sizeof(zeros), 211);

        uint8_t  pkt[80];
        uint32_t plen = buildIpv4(pkt, 64, IP_PROTO_TCP, 0x7E);
        pushBytes(bs, pool, pkt, plen, 9);

        bool got = false;
        while (ipv4streamTryReadPacket(bs, &p))
        {
            if (p != NULL && sbufGetLength(p) == 64)
            {
                const uint8_t *d = sbufGetRawPtr(p);
                if (d[IP_HLEN] == 0x7E)
                {
                    got = true;
                }
            }
            if (p)
                bufferpoolReuseBuffer(pool, p);
        }
        require(got, "fuzz: sentinel packet not recovered after garbage and clean gap");
        bufferstreamEmpty(bs);
    }
}

static void testIsForwardable(buffer_pool_t *pool, bool (*is_forwardable)(const sbuf_t *))
{
    sbuf_t *b = bufferpoolGetSmallBuffer(pool);
    buildIpv4(sbufGetMutablePtr(b), 0, 0, 0); // placeholder, set length below
    sbufSetLength(b, 50);
    buildIpv4(sbufGetMutablePtr(b), 50, IP_PROTO_TCP, 0x33);
    require(is_forwardable(b), "forwardable: valid IPv4 should pass");

    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x44;
    require(! is_forwardable(b), "forwardable: IHL shorter than the minimum header must fail");
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x4F;
    require(! is_forwardable(b), "forwardable: IHL beyond total packet length must fail");
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x46;
    require(is_forwardable(b), "forwardable: a complete IPv4 options header should pass");

    // Length/total-length mismatch.
    sbufSetLength(b, 50);
    buildIpv4(sbufGetMutablePtr(b), 49, IP_PROTO_TCP, 0x33);
    require(! is_forwardable(b), "forwardable: total-length mismatch must fail");

    // IPv6 version nibble.
    sbufSetLength(b, 50);
    memoryZero(sbufGetMutablePtr(b), 50);
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x60;
    require(! is_forwardable(b), "forwardable: IPv6 must be dropped");

    // Too short to be IPv4.
    sbufSetLength(b, 10);
    ((uint8_t *) sbufGetMutablePtr(b))[0] = 0x45;
    require(! is_forwardable(b), "forwardable: sub-header length must fail");
    bufferpoolReuseBuffer(pool, b);

    // Oversized packet (> kMaxAllowedPacketLength) using a large buffer.
    sbuf_t *big = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(big, kMaxAllowedPacketLength + 1);
    memoryZero(sbufGetMutablePtr(big), IP_HLEN);
    ((uint8_t *) sbufGetMutablePtr(big))[0] = 0x45;
    require(! is_forwardable(big), "forwardable: oversized packet must fail");
    bufferpoolReuseBuffer(pool, big);
}

static void testFrameBoundaries(buffer_stream_t *bs, buffer_pool_t *pool)
{
    const uint16_t lengths[] = {IP_HLEN, 60, kMaxAllowedPacketLength};
    uint8_t        raw[kMaxAllowedPacketLength + 1];
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
    {
        const uint16_t len = lengths[i];
        buildIpv4(raw, len, 253, 0xA7);
        if (len == 60)
            raw[0] = 0x4F; /* Maximum IPv4 options header, without a body. */
        pushBytes(bs, pool, raw, len - 1, 7);
        sbuf_t *packet = NULL;
        require(! ipv4streamTryReadPacket(bs, &packet), "boundary: incomplete packet must wait");
        require(packet == NULL, "boundary: waiting returned a buffer");
        pushBytes(bs, pool, raw + len - 1, 1, 1);
        require(ipv4streamTryReadPacket(bs, &packet), "boundary: complete packet was rejected");
        if (packet != NULL)
        {
            require(sbufGetLength(packet) == len && memoryEqual(sbufGetRawPtr(packet), raw, len),
                    "boundary: packet bytes changed");
            require(ipv4streamIsForwardablePacket(packet), "boundary: complete packet not forwardable");
            bufferpoolReuseBuffer(pool, packet);
        }
        require(bufferstreamGetBufLen(bs) == 0, "boundary: unexpected remainder");
    }

    buildIpv4(raw, sizeof(raw), 253, 0);
    pushBytes(bs, pool, raw, sizeof(raw), 19);
    sbuf_t *packet = NULL;
    require(! ipv4streamTryReadPacket(bs, &packet), "boundary: oversized frame was accepted");
    require(bufferstreamGetBufLen(bs) < IP_HLEN, "boundary: oversized header did not resynchronize");
    bufferstreamEmpty(bs);
}

static void testResyncWindowBoundaries(buffer_stream_t *bs, buffer_pool_t *pool)
{
    const uint32_t offsets[] = {235, 236, 237, 255, 256, 257};
    uint8_t        raw[320];
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
    {
        const uint32_t offset = offsets[i];
        memoryZero(raw, offset);
        buildIpv4(raw + offset, 40, 253, 0xA5);
        pushBytes(bs, pool, raw, offset + IP_HLEN - 1, 11);
        sbuf_t *packet = NULL;
        require(! ipv4streamTryReadPacket(bs, &packet), "window: partial candidate must wait");
        require(bufferstreamGetBufLen(bs) == IP_HLEN - 1, "window: incomplete header was discarded");
        pushBytes(bs, pool, raw + offset + IP_HLEN - 1, 40 - IP_HLEN + 1, 3);
        require(ipv4streamTryReadPacket(bs, &packet), "window: candidate was not recovered");
        if (packet != NULL)
        {
            require(sbufGetLength(packet) == 40 && memoryEqual(sbufGetRawPtr(packet), raw + offset, 40),
                    "window: recovered bytes differ");
            bufferpoolReuseBuffer(pool, packet);
        }
        require(bufferstreamGetBufLen(bs) == 0, "window: unexpected remainder");
    }
}

static uint16_t testChecksum(const uint8_t *raw, size_t length, uint32_t seed)
{
    while (length >= 2)
    {
        seed += ((uint32_t) raw[0] << 8) | raw[1];
        raw += 2;
        length -= 2;
    }
    if (length != 0)
        seed += (uint32_t) raw[0] << 8;
    while ((seed >> 16) != 0)
        seed = (seed & 0xFFFFU) + (seed >> 16);
    return (uint16_t) ~seed;
}

static void testWrite16(uint8_t *dest, uint16_t value)
{
    dest[0] = (uint8_t) (value >> 8);
    dest[1] = (uint8_t) value;
}

static void repairTestIpChecksum(uint8_t *raw)
{
    raw[10] = raw[11] = 0;
    testWrite16(raw + 10, testChecksum(raw, (raw[0] & 15U) * 4U, 0));
}

static uint16_t buildChecksummedPacket(uint8_t *raw, uint8_t protocol)
{
    const uint16_t transport_length = protocol == IP_PROTO_TCP ? 33 : 13;
    const uint16_t length           = IP_HLEN + transport_length;
    buildIpv4(raw, length, protocol, 0xA5);
    raw[12]                        = 192;
    raw[13]                        = 0;
    raw[14]                        = 2;
    raw[15]                        = 1;
    raw[16]                        = 198;
    raw[17]                        = 51;
    raw[18]                        = 100;
    raw[19]                        = 2;
    uint8_t       *transport       = raw + IP_HLEN;
    const uint16_t checksum_offset = protocol == IP_PROTO_TCP ? 16 : protocol == IP_PROTO_UDP ? 6 : 2;
    if (protocol == IP_PROTO_TCP)
        transport[12] = 0x50;
    if (protocol == IP_PROTO_UDP)
        testWrite16(transport + 4, transport_length);
    transport[checksum_offset] = transport[checksum_offset + 1] = 0;
    uint32_t seed                                               = 0;
    if (protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP)
    {
        for (size_t i = 12; i < 20; i += 2)
            seed += ((uint32_t) raw[i] << 8) | raw[i + 1];
        seed += protocol + transport_length;
    }
    uint16_t checksum = testChecksum(transport, transport_length, seed);
    if (protocol == IP_PROTO_UDP && checksum == 0)
        checksum = UINT16_MAX;
    testWrite16(transport + checksum_offset, checksum);
    repairTestIpChecksum(raw);
    return length;
}

static void checkValidation(buffer_pool_t *pool, const uint8_t *raw, uint16_t length,
                            ipv4stream_validation_level_t level, bool accepted, bool unaligned)
{
    sbuf_t *packet = bufferpoolGetBestFit(pool, length + 1U, bufferpoolGetSmallBufferPadding(pool));
    sbufSetLength(packet, length + (unaligned ? 1U : 0U));
    if (unaligned)
        sbufShiftRight(packet, 1);
    memoryCopy(sbufGetMutablePtr(packet), raw, length);
    sbufSetRecalculateChecksum(packet, true);
    const char *reason = ipv4streamValidatePacket(level, packet);
    require((reason == NULL) == accepted, "validation: unexpected accept/reject result");
    require(sbufGetLength(packet) == length && memoryEqual(sbufGetRawPtr(packet), raw, length),
            "validation: inspection changed packet bytes");
    require(sbufGetRecalculateChecksum(packet), "validation: inspection consumed checksum request");
    bufferpoolReuseBuffer(pool, packet);
}

static void testValidationModes(buffer_pool_t *pool)
{
    uint8_t       raw[100];
    const uint8_t protocols[] = {IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP};
    for (size_t i = 0; i < sizeof(protocols); ++i)
    {
        const uint8_t  protocol = protocols[i];
        const uint16_t length   = buildChecksummedPacket(raw, protocol);
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, false);
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, true);
        raw[length - 1] ^= 0x40;
        checkValidation(pool, raw, length, kIpv4StreamValidationNone, true, false);
        checkValidation(pool, raw, length, kIpv4StreamValidationLoose, true, false);
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);
        /* An individual fragment cannot validate a whole transport checksum. */
        raw[6] = 0x20;
        repairTestIpChecksum(raw);
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, false);
        raw[6] = 0;
        raw[7] = 1;
        repairTestIpChecksum(raw);
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, false);
        raw[10] ^= 1;
        checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);
    }

    uint16_t length  = buildChecksummedPacket(raw, IP_PROTO_UDP);
    raw[IP_HLEN + 6] = raw[IP_HLEN + 7] = 0;
    raw[length - 1] ^= 0x80;
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, false);
    testWrite16(raw + IP_HLEN + 4, 7);
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);
    testWrite16(raw + IP_HLEN + 4, length);
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);
    testWrite16(raw + IP_HLEN + 4, 8); /* UDP may cover less than the complete IP body. */
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, true, false);

    length            = buildChecksummedPacket(raw, IP_PROTO_TCP);
    raw[IP_HLEN + 12] = 0x40;
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);
    raw[IP_HLEN + 12] = 0xF0;
    checkValidation(pool, raw, length, kIpv4StreamValidationHard, false, false);

    buildIpv4(raw, 60, 253, 0xA5);
    raw[0] = 0x4F;
    repairTestIpChecksum(raw);
    checkValidation(pool, raw, 60, kIpv4StreamValidationHard, true, false);
    raw[59] ^= 1;
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, true, false);
    checkValidation(pool, raw, 60, kIpv4StreamValidationHard, false, false);
    raw[0] = 0x65;
    checkValidation(pool, raw, 60, kIpv4StreamValidationNone, true, false);
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, false, false);
    raw[0] = 0x44;
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, false, false);
    raw[0] = 0x4F;
    checkValidation(pool, raw, 40, kIpv4StreamValidationLoose, false, false);
    raw[0] = 0x46;
    testWrite16(raw + 2, 20);
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, false, false);
    raw[0] = 0x45;
    testWrite16(raw + 2, 59);
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, false, false);
    testWrite16(raw + 2, 61);
    checkValidation(pool, raw, 60, kIpv4StreamValidationLoose, false, false);
    checkValidation(pool, raw, IP_HLEN - 1, kIpv4StreamValidationLoose, false, false);
}

int main(void)
{
    testCaseSet("ipv4_stream_codec_test");
    master_pool_t *mp_large  = masterpoolCreateWithCapacity(64);
    master_pool_t *mp_small  = masterpoolCreateWithCapacity(64);
    master_pool_t *mp_medium = masterpoolCreateWithCapacity(64);
    buffer_pool_t *pool      = bufferpoolCreate(
        mp_large, mp_medium, mp_small, 64, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, SMALL_BUFFER_SIZE, 8192, 8192);

    buffer_stream_t bs = bufferstreamCreate(pool, 0);

    for (unsigned layout = 0; layout < 2; ++layout)
    {
        g_separate_entries = layout != 0;
        testSinglePacket(&bs, pool);
        testTwoConcatenated(&bs, pool);
        testSplitPacket(&bs, pool);
        testGarbagePrefixRecovers(&bs, pool);
        testAdversarialNoCrash(&bs, pool);
        testLooksValidWorstCase(&bs, pool);
        testFuzzRecovers(&bs, pool);
        testFrameBoundaries(&bs, pool);
        testResyncWindowBoundaries(&bs, pool);
        bufferstreamEmpty(&bs);
    }
    testCaseSet("shared outgoing IPv4 framing");
    testIsForwardable(pool, ipv4streamIsForwardablePacket);
    testValidationModes(pool);

    bufferstreamDestroy(&bs);

    if (g_failures == 0)
    {
        printf("ipv4_stream_codec_test: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "ipv4_stream_codec_test: %d check(s) failed\n", g_failures);
    return 1;
}

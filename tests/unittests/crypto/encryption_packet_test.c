/* Independent packet serializer/checksum oracle exercises packet Encryption:
 * TCP/UDP/options, empty payloads, loss/reordering, fresh nonces, directional
 * authentication, repair intent, address rewriting, UDP-zero policy and bounds.
 * CTest: waterwall.encryption_packet_unit. No sockets or stream framing. */
#include "EncryptionCommon/packet.h"
#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static uint8_t upload_key[32], download_key[32];

static uint32_t sumBytes(uint32_t sum, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i + 1 < length; i += 2)
        sum += ((uint32_t) bytes[i] << 8) | bytes[i + 1];
    if (length & 1U)
        sum += (uint32_t) bytes[length - 1] << 8;
    return sum;
}

static uint16_t checksum(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & UINT16_MAX) + (sum >> 16);
    return (uint16_t) ~sum;
}

static void checksums(uint8_t *packet, size_t length)
{
    const size_t ihl    = (packet[0] & 15U) * 4U;
    const size_t offset = ihl + (packet[9] == 6 ? 16 : 6);
    packet[10] = packet[11] = 0;
    PUT_BE16(packet + 10, checksum(sumBytes(0, packet, ihl)));
    packet[offset] = packet[offset + 1] = 0;
    uint32_t sum                        = sumBytes(packet[9] + (uint32_t) (length - ihl), packet + 12, 8);
    uint16_t value                      = checksum(sumBytes(sum, packet + ihl, length - ihl));
    if (packet[9] == 17 && value == 0)
        value = UINT16_MAX;
    PUT_BE16(packet + offset, value);
}

static bool validChecksums(const sbuf_t *buf)
{
    const uint8_t *packet = sbufGetRawPtr(buf);
    const size_t   ihl    = (packet[0] & 15U) * 4U;
    const size_t   length = sbufGetLength(buf);
    if (checksum(sumBytes(0, packet, ihl)) != 0)
        return false;
    if (packet[9] == 17 && GET_BE16(packet + ihl + 6) == 0)
        return true;
    return checksum(sumBytes(
               sumBytes(packet[9] + (uint32_t) (length - ihl), packet + 12, 8), packet + ihl, length - ihl)) == 0;
}

static sbuf_t *nativePacket(uint8_t protocol, uint16_t ihl, uint16_t thl, uint32_t body_length)
{
    const uint32_t length = ihl + thl + body_length;
    sbuf_t        *buf    = sbufCreateWithPadding(length, kEncryptionPacketNonceSize);
    sbufSetLength(buf, length);
    uint8_t *p = sbufGetMutablePtr(buf);
    memoryZero(p, length);
    p[0] = (uint8_t) (0x40 | (ihl / 4));
    PUT_BE16(p + 2, length);
    PUT_BE16(p + 4, 0x1234);
    PUT_BE16(p + 6, 0x4000);
    p[8] = 61;
    p[9] = protocol;
    PUT_BE32(p + 12, 0xc0000201U);
    PUT_BE32(p + 16, 0xc6336401U);
    for (size_t i = 20; i < ihl; ++i)
        p[i] = 1;
    PUT_BE16(p + ihl, 40001);
    PUT_BE16(p + ihl + 2, 40000);
    if (protocol == 6)
    {
        PUT_BE32(p + ihl + 4, 0x12345678);
        PUT_BE32(p + ihl + 8, 0x9abcdef0);
        p[ihl + 12] = (uint8_t) ((thl / 4) << 4);
        p[ihl + 13] = 0x19;
        PUT_BE16(p + ihl + 14, 8192);
        for (size_t i = 20; i < thl; ++i)
            p[ihl + i] = 1;
    }
    else
        PUT_BE16(p + ihl + 4, thl + body_length);
    for (uint32_t i = 0; i < body_length; ++i)
        p[ihl + thl + i] = (uint8_t) (i * 73U + 17U);
    checksums(p, length);
    return buf;
}

static sbuf_t *packetTestClone(const sbuf_t *buf)
{
    sbuf_t *copy = sbufCreateWithPadding(sbufGetLength(buf), kEncryptionPacketNonceSize);
    sbufSetLength(copy, sbufGetLength(buf));
    sbufWrite(copy, sbufGetRawPtr(buf), sbufGetLength(buf));
    return copy;
}

static void testRoundTrips(void)
{
    const uint16_t headers[] = {20, 24, 60};
    const uint32_t bodies[]  = {0, 1, 32, 257};
    for (unsigned protocol = 6; protocol <= 17; protocol += 11)
        for (size_t i = 0; i < ARRAY_SIZE(headers); ++i)
            for (size_t j = 0; j < ARRAY_SIZE(headers); ++j)
                for (size_t k = 0; k < ARRAY_SIZE(bodies); ++k)
                {
                    const uint16_t thl      = protocol == 6 ? headers[j] : 8;
                    const uint16_t prefix   = headers[i] + thl;
                    sbuf_t        *buf      = nativePacket(protocol, headers[i], thl, bodies[k]);
                    sbuf_t        *original = packetTestClone(buf);
                    require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketOk, "encode failed");
                    require(sbufGetLength(buf) == sbufGetLength(original) + 40 && validChecksums(buf),
                            "encrypted length/checksums wrong");
                    const uint8_t *wire = sbufGetRawPtr(buf);
                    require(wire[0] == ((const uint8_t *) sbufGetRawPtr(original))[0] && wire[9] == protocol &&
                                GET_BE16(wire + headers[i]) == 40001 && GET_BE16(wire + headers[i] + 2) == 40000,
                            "visible packet framing changed");
                    uint8_t       plaintext[257];
                    const uint8_t ad[] = {(uint8_t) protocol};
                    require(wCryptoXChaCha20Poly1305Decrypt(plaintext,
                                                            sizeof(plaintext),
                                                            wire + prefix + 24,
                                                            bodies[k] + 16,
                                                            ad,
                                                            sizeof(ad),
                                                            wire + prefix,
                                                            upload_key) == kWCryptoOk,
                            "independent AEAD decoding failed");
                    require(memoryEqual(plaintext, (const uint8_t *) sbufGetRawPtr(original) + prefix, bodies[k]),
                            "encryption covered the wrong bytes");
                    require(encryptionDecodePacket(upload_key, buf) == kEncryptionPacketOk, "decode failed");
                    require(sbufGetLength(buf) == sbufGetLength(original) && validChecksums(buf) &&
                                memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(original), sbufGetLength(buf)),
                            "decoded packet differs from original");
                    sbufDestroy(original);
                    sbufDestroy(buf);
                }
}

static void testIndependentPackets(void)
{
    sbuf_t *packets[4];
    for (size_t i = 0; i < ARRAY_SIZE(packets); ++i)
    {
        packets[i] = nativePacket(6, 20, 20, 24);
        require(encryptionEncodePacket(upload_key, &packets[i]) == kEncryptionPacketOk, "encode failed");
        for (size_t j = 0; j < i; ++j)
            require(! memoryEqual((const uint8_t *) sbufGetRawPtr(packets[i]) + 40,
                                  (const uint8_t *) sbufGetRawPtr(packets[j]) + 40,
                                  24),
                    "identical packets reused a nonce");
    }
    sbufDestroy(packets[1]);
    const unsigned order[] = {3, 0, 2};
    for (size_t i = 0; i < ARRAY_SIZE(order); ++i)
    {
        require(encryptionDecodePacket(upload_key, packets[order[i]]) == kEncryptionPacketOk,
                "loss/reordering affected independent packet decryption");
        sbufDestroy(packets[order[i]]);
    }
}

static void testAuthenticationAndRepair(void)
{
    sbuf_t *encrypted = nativePacket(6, 20, 24, 32);
    require(encryptionEncodePacket(upload_key, &encrypted) == kEncryptionPacketOk, "encode failed");
    const unsigned corrupt_offsets[] = {44, 68, 100};
    for (size_t i = 0; i < ARRAY_SIZE(corrupt_offsets); ++i)
    {
        sbuf_t *bad = packetTestClone(encrypted);
        sbufGetMutablePtr(bad)[corrupt_offsets[i]] ^= 0x80;
        checksums(sbufGetMutablePtr(bad), sbufGetLength(bad));
        require(encryptionDecodePacket(upload_key, bad) == kEncryptionPacketAuthentication,
                "nonce/body/tag corruption authenticated");
        sbufDestroy(bad);
    }
    sbuf_t *wrong_direction = packetTestClone(encrypted);
    require(encryptionDecodePacket(download_key, wrong_direction) == kEncryptionPacketAuthentication,
            "opposite direction key authenticated");
    sbufDestroy(wrong_direction);
    sbuf_t *bad = packetTestClone(encrypted);
    sbufGetMutablePtr(bad)[68] ^= 1;
    sbufSetRecalculateChecksum(bad, true);
    require(encryptionDecodePacket(upload_key, bad) == kEncryptionPacketAuthentication,
            "checksum-repair flag waived authentication");
    sbufDestroy(bad);
    sbuf_t *rewritten = packetTestClone(encrypted);
    PUT_BE32(sbufGetMutablePtr(rewritten) + 12, 0x0a000001U);
    PUT_BE32(sbufGetMutablePtr(rewritten) + 16, 0x0a000002U);
    require(encryptionDecodePacket(upload_key, rewritten) == kEncryptionPacketChecksum,
            "unrequested bad visible checksum was accepted");
    sbufSetRecalculateChecksum(rewritten, true);
    require(encryptionDecodePacket(upload_key, rewritten) == kEncryptionPacketOk && validChecksums(rewritten) &&
                GET_BE32((const uint8_t *) sbufGetRawPtr(rewritten) + 12) == 0x0a000001U &&
                ! sbufGetRecalculateChecksum(rewritten),
            "address rewrite/repair did not preserve packet authentication");
    sbufDestroy(rewritten);
    sbufDestroy(encrypted);

    for (unsigned repair = 0; repair < 2; ++repair)
    {
        sbuf_t *udp = nativePacket(17, 24, 8, 33);
        PUT_BE16(sbufGetMutablePtr(udp) + 24 + 6, 0);
        sbufSetRecalculateChecksum(udp, repair != 0);
        require(encryptionEncodePacket(upload_key, &udp) == kEncryptionPacketOk, "UDP-zero encode failed");
        require((GET_BE16((const uint8_t *) sbufGetRawPtr(udp) + 30) == 0) == ! repair,
                "UDP-zero encode policy changed");
        require(encryptionDecodePacket(upload_key, udp) == kEncryptionPacketOk && validChecksums(udp),
                "UDP-zero decode failed");
        require((GET_BE16((const uint8_t *) sbufGetRawPtr(udp) + 30) == 0) == ! repair,
                "UDP-zero decode policy changed");
        sbufDestroy(udp);
    }
    sbuf_t *repair = nativePacket(6, 20, 20, 12);
    sbufGetMutablePtr(repair)[10] ^= 1;
    sbufGetMutablePtr(repair)[36] ^= 1;
    require(encryptionEncodePacket(upload_key, &repair) == kEncryptionPacketChecksum,
            "bad native checksum accepted without repair request");
    sbufSetRecalculateChecksum(repair, true);
    require(encryptionEncodePacket(upload_key, &repair) == kEncryptionPacketOk && validChecksums(repair) &&
                encryptionDecodePacket(upload_key, repair) == kEncryptionPacketOk && validChecksums(repair),
            "native checksum repair request was not honored");
    sbufDestroy(repair);
}

static void testAdmissionAndLimits(void)
{
    for (unsigned fragment = 0; fragment < 2; ++fragment)
    {
        sbuf_t *buf = nativePacket(6, 20, 20, 12);
        PUT_BE16(sbufGetMutablePtr(buf) + 6, fragment ? 1 : 0x2000);
        require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketFragmented &&
                    encryptionDecodePacket(upload_key, buf) == kEncryptionPacketFragmented,
                "fragment admitted");
        sbufDestroy(buf);
    }
    sbuf_t *buf = nativePacket(17, 20, 8, 12);
    PUT_BE16(sbufGetMutablePtr(buf) + 24, 19);
    require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketMalformed, "UDP padding admitted");
    sbufDestroy(buf);
    buf                       = nativePacket(6, 20, 20, 12);
    sbufGetMutablePtr(buf)[9] = 1;
    require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketProtocol, "unsupported protocol admitted");
    sbufDestroy(buf);
    buf = nativePacket(6, 20, 20, 0);
    require(encryptionDecodePacket(upload_key, buf) == kEncryptionPacketMalformed, "missing envelope admitted");
    sbufDestroy(buf);
    for (unsigned extra = 0; extra < 2; ++extra)
    {
        buf = nativePacket(6, 60, 60, UINT16_MAX - 40 - 120 + extra);
        if (extra)
            require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketTooLarge,
                    "IPv4 length overflow admitted");
        else
        {
            require(encryptionEncodePacket(upload_key, &buf) == kEncryptionPacketOk &&
                        sbufGetLength(buf) == UINT16_MAX && validChecksums(buf),
                    "maximum encrypted packet failed");
            require(encryptionDecodePacket(upload_key, buf) == kEncryptionPacketOk && validChecksums(buf),
                    "maximum packet decode failed");
        }
        sbufDestroy(buf);
    }
}

int main(void)
{
    testCaseSet("encryption_packet_test");
    initWLibc();
    checkSumInit();
    require(globalstateInitializeSecureRandom(), "secure RNG initialization failed");
    require(frandGlobalInit(), "random generator initialization failed");
    frandInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    const uint8_t base_key[32] = {1, 2, 3, 4, 5};
    require(encryptionPacketDeriveKeys(base_key, upload_key, download_key) &&
                ! memoryEqual(upload_key, download_key, 32),
            "direction keys not independent");
    TEST_RUN_CASE(testRoundTrips);
    TEST_RUN_CASE(testIndependentPackets);
    TEST_RUN_CASE(testAuthenticationAndRepair);
    TEST_RUN_CASE(testAdmissionAndLimits);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}

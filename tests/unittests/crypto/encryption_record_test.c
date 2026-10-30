/*
 * Covers: shared Encryption record wire format, authentication and stream extraction.
 * Setup: real AEAD backends and worker buffer pool; no tunnels or socket I/O.
 * Cases: both algorithms, every split point, coalescing, empty plaintext, configured
 * and hard limits, tail growth, malformed headers and authenticated-data tampering.
 * Checks: exact plaintext/header bytes, consume-nothing incomplete/invalid results,
 * authentication failures and complete buffer settlement.
 * Limits: AES-GCM cases require backend availability; callbacks belong to the node suites.
 * CTest: waterwall.encryption_record_unit
 */
#include "EncryptionCommon/record.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

static twf_worker_env_t env;
static const uint8_t    key[32] = {1, 2, 3, 4, 5};

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* The real merge disposes second inside buffer_pool.c and can replace first
     * inside shiftbuffer.c. Those same-object calls bypass the ordinary GNU
     * wrappers. Observe the public merge ownership boundary, as the existing
     * ConnectionFisher and HalfDuplex fixtures do; keep the real merge behavior. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, second);
    twfLedgerRemember(
        g_twf_buffers.recycled, &g_twf_buffers.recycled_count, second, "too many merged buffers to track");
    if (merged != first)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, first);
        twfTrackAcquired(merged);
    }
    return merged;
}

static sbuf_t *bytes(const void *data, uint32_t length)
{
    sbuf_t *buffer = twfTrackAcquired(sbufCreateWithPadding(length, kEncryptionFramePrefixSize));
    sbufSetLength(buffer, length);
    if (length != 0)
        sbufWrite(buffer, data, length);
    return buffer;
}

static sbuf_t *record(uint32_t algorithm, const void *data, uint32_t length)
{
    sbuf_t *buffer = twfTrackAcquired(sbufCreateWithPadding(length + kEncryptionTagSize, kEncryptionFramePrefixSize));
    sbufSetLength(buffer, length);
    if (length != 0)
        sbufWrite(buffer, data, length);
    twfRequire(encryptionEncodeFrame(algorithm, key, &buffer) == kWCryptoOk, "record encoding failed");
    const uint8_t *wire = sbufGetRawPtr(buffer);
    const uint32_t body = length + kEncryptionNonceSize + kEncryptionTagSize;
    twfRequire(sbufGetLength(buffer) == kEncryptionTlsHeaderSize + body && wire[0] == 0x17 && wire[1] == 3 &&
                   wire[2] == 3 && wire[3] == (uint8_t) (body >> 8) && wire[4] == (uint8_t) body,
               "encoded record changed the wire header or length");
    return buffer;
}

static void expectPlaintext(uint32_t algorithm, sbuf_t *frame, const void *expected, uint32_t length)
{
    twfRequire(encryptionDecodeFrame(algorithm, key, frame) == kWCryptoOk, "valid record did not authenticate");
    twfRequire(sbufGetLength(frame) == length && (length == 0 || memoryEqual(sbufGetRawPtr(frame), expected, length)),
               "decoded record changed plaintext");
    bufferpoolReuseBuffer(env.pool, frame);
}

static void testFragmented(uint32_t algorithm)
{
    twfSetCase("Encryption authenticates records split at every header, nonce, body and tag position");
    const char     payload[] = "fragmented authenticated record";
    sbuf_t        *wire      = record(algorithm, payload, sizeof(payload));
    const uint32_t length    = sbufGetLength(wire);
    for (uint32_t split = 1; split < length; ++split)
    {
        buffer_stream_t stream = bufferstreamCreate(env.pool, kEncryptionFramePrefixSize);
        bufferstreamPush(&stream, bytes(sbufGetRawPtr(wire), split));
        sbuf_t *frame = NULL;
        twfRequire(encryptionReadFrame(&stream, kEncryptionHardMaxFramePayload, &frame) == kEncryptionFrameNeedMore &&
                       frame == NULL && bufferstreamGetBufLen(&stream) == split,
                   "incomplete record consumed bytes or published a frame");
        bufferstreamPush(&stream, bytes((const uint8_t *) sbufGetRawPtr(wire) + split, length - split));
        twfRequire(encryptionReadFrame(&stream, kEncryptionHardMaxFramePayload, &frame) == kEncryptionFrameReady &&
                       bufferstreamGetBufLen(&stream) == 0,
                   "completed fragmented record was not extracted exactly");
        expectPlaintext(algorithm, frame, payload, sizeof(payload));
        bufferstreamDestroy(&stream);
    }
    bufferpoolReuseBuffer(env.pool, wire);
}

static void testCoalesced(uint32_t algorithm)
{
    twfSetCase("Encryption extracts coalesced records and preserves an authenticated empty plaintext");
    const char *payloads[] = {"first", "", "last"};
    sbuf_t     *combined   = bufferpoolGetSmallBuffer(env.pool);
    for (size_t i = 0; i < 3; ++i)
    {
        sbuf_t *frame = record(algorithm, payloads[i], (uint32_t) strlen(payloads[i]));
        sbufConcatNoCheck(combined, frame);
        bufferpoolReuseBuffer(env.pool, frame);
    }
    buffer_stream_t stream = bufferstreamCreate(env.pool, kEncryptionFramePrefixSize);
    bufferstreamPush(&stream, combined);
    for (size_t i = 0; i < 3; ++i)
    {
        sbuf_t *frame = NULL;
        twfRequire(encryptionReadFrame(&stream, kEncryptionHardMaxFramePayload, &frame) == kEncryptionFrameReady,
                   "coalesced record boundary was lost");
        expectPlaintext(algorithm, frame, payloads[i], (uint32_t) strlen(payloads[i]));
    }
    twfRequire(bufferstreamGetBufLen(&stream) == 0, "coalesced input retained trailing bytes");
    bufferstreamDestroy(&stream);
}

static void testLimitsAndGrowth(uint32_t algorithm)
{
    twfSetCase("Encryption accepts exact configured/hard limits and grows a full plaintext allocation");
    uint8_t payload[kEncryptionHardMaxFramePayload];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t) i;
    const uint32_t limits[] = {1, 32, kEncryptionHardMaxFramePayload};
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i)
    {
        buffer_stream_t stream = bufferstreamCreate(env.pool, kEncryptionFramePrefixSize);
        bufferstreamPush(&stream, record(algorithm, payload, limits[i]));
        sbuf_t *frame = NULL;
        twfRequire(encryptionReadFrame(&stream, limits[i], &frame) == kEncryptionFrameReady,
                   "exact configured limit was rejected");
        expectPlaintext(algorithm, frame, payload, limits[i]);
        bufferstreamDestroy(&stream);
    }

    sbuf_t        *buffer      = twfTrackAcquired(sbufCreateWithPadding(64, kEncryptionFramePrefixSize));
    const uint32_t full_length = sbufGetMaximumWriteableSize(buffer);
    twfRequire(full_length <= sizeof(payload), "growth fixture exceeds the record limit");
    sbufSetLength(buffer, full_length);
    sbufWrite(buffer, payload, full_length);
    twfRequire(encryptionEncodeFrame(algorithm, key, &buffer) == kWCryptoOk,
               "full plaintext allocation did not grow for its authentication tag");
    twfTrackAcquired(buffer);
    expectPlaintext(algorithm, buffer, payload, full_length);
}

static void testInvalidHeaders(void)
{
    twfSetCase("Encryption rejects malformed headers and over-limit lengths without waiting for a body");
    uint8_t headers[][5] = {
        {0x16, 3, 3, 0, 28},
        {0x17, 2, 3, 0, 28},
        {0x17, 3, 2, 0, 28},
        {0x17, 3, 3, 0, 27},
        {0x17, 3, 3, 0, 61},
        {0x17, 3, 3, 0x40, 1},
    };
    for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]); ++i)
    {
        buffer_stream_t stream = bufferstreamCreate(env.pool, kEncryptionFramePrefixSize);
        bufferstreamPush(&stream, bytes(headers[i], sizeof(headers[i])));
        sbuf_t  *sentinel = bytes(NULL, 0);
        sbuf_t  *frame    = sentinel;
        uint32_t limit    = i == 5 ? kEncryptionHardMaxFramePayload : 32;
        twfRequire(encryptionReadFrame(&stream, limit, &frame) == kEncryptionFrameInvalid && frame == sentinel &&
                       bufferstreamGetBufLen(&stream) == sizeof(headers[i]),
                   "invalid header consumed bytes, changed output, or waited for its body");
        bufferpoolReuseBuffer(env.pool, sentinel);
        bufferstreamDestroy(&stream);
    }
}

static void testAuthentication(uint32_t algorithm)
{
    twfSetCase("Encryption authenticates nonce, ciphertext, tag and record length");
    const char     payload[] = "authenticated";
    const uint32_t offsets[] = {
        kEncryptionTlsHeaderSize, kEncryptionFramePrefixSize, kEncryptionFramePrefixSize + sizeof(payload)};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
    {
        sbuf_t *frame = record(algorithm, payload, sizeof(payload));
        sbufGetMutablePtr(frame)[offsets[i]] ^= 1;
        twfRequire(encryptionDecodeFrame(algorithm, key, frame) != kWCryptoOk, "tampered record was accepted");
        bufferpoolReuseBuffer(env.pool, frame);
    }

    sbuf_t  *frame    = record(algorithm, payload, sizeof(payload));
    uint32_t length   = sbufGetLength(frame);
    sbuf_t  *original = frame;
    frame             = sbufReserveSpace(frame, length + 1);
    if (frame != original)
        twfTrackAcquired(frame);
    sbufSetLength(frame, length + 1);
    sbufGetMutablePtr(frame)[4] += 1;
    sbufGetMutablePtr(frame)[length] = 0;
    buffer_stream_t stream           = bufferstreamCreate(env.pool, kEncryptionFramePrefixSize);
    bufferstreamPush(&stream, frame);
    frame = NULL;
    twfRequire(encryptionReadFrame(&stream, kEncryptionHardMaxFramePayload, &frame) == kEncryptionFrameReady,
               "authenticated-header fixture is not structurally valid");
    twfRequire(encryptionDecodeFrame(algorithm, key, frame) != kWCryptoOk,
               "changed authenticated record length was accepted");
    bufferpoolReuseBuffer(env.pool, frame);
    bufferstreamDestroy(&stream);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    twfWorkerEnvSetup(&env, 65536, kEncryptionFramePrefixSize);
    testInvalidHeaders();
    const uint32_t algorithms[] = {kEncryptionAlgorithmChaCha20Poly1305, kEncryptionAlgorithmAes256Gcm};
    for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i)
    {
        if (algorithms[i] == kEncryptionAlgorithmAes256Gcm && ! wCryptoAes256GcmIsAvailable())
            continue;
        testFragmented(algorithms[i]);
        testCoalesced(algorithms[i]);
        testLimitsAndGrowth(algorithms[i]);
        testAuthentication(algorithms[i]);
    }
    twfWorkerEnvTeardown(&env);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}

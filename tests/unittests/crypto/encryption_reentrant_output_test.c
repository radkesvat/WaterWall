/*
 * Covers: EncryptionClient/Server retain explicit direction and borrowed-line lifetime.
 * Setup: real pooled line, worker pool and AEAD; the first output synchronously closes
 * through the opposite Finish callback and the previous endpoint destroys its line.
 * Cases: close during chunked encryption and coalesced decryption; empty input discard.
 * Checks: one correctly directed output, exact plaintext, no output after close, zero
 * state and complete release of the original input and remaining buffered records.
 * CTest: waterwall.encryptionclient_reentrant_output_unit;
 * waterwall.encryptionserver_reentrant_output_unit
 */
#if defined(TEST_ENCRYPTION_CLIENT)
#include "EncryptionClient/structure.h"
#define encryption_tstate_t encryptionclient_tstate_t
#define encryption_lstate_t encryptionclient_lstate_t
#define initialize          encryptionclientLinestateInitialize
#define encodePayload       encryptionclientTunnelUpStreamPayload
#define decodePayload       encryptionclientTunnelDownStreamPayload
#define finishUp            encryptionclientTunnelUpStreamFinish
#define finishDown          encryptionclientTunnelDownStreamFinish
#define ENCODE_UPSTREAM     true
#elif defined(TEST_ENCRYPTION_SERVER)
#include "EncryptionServer/structure.h"
#define encryption_tstate_t encryptionserver_tstate_t
#define encryption_lstate_t encryptionserver_lstate_t
#define initialize          encryptionserverLinestateInitialize
#define encodePayload       encryptionserverTunnelDownStreamPayload
#define decodePayload       encryptionserverTunnelUpStreamPayload
#define finishUp            encryptionserverTunnelUpStreamFinish
#define finishDown          encryptionserverTunnelDownStreamFinish
#define ENCODE_UPSTREAM     false
#else
#error "select an Encryption tunnel test role"
#endif

#include "fixtures/failure/tunnel_line_failure_harness.h"

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static tunnel_t        *prev, *encryption, *next;
static bool             encoding, close_on_output;
static unsigned         outputs, finishes;

static void ownerFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == prev, "Finish reached the wrong owner");
    ++finishes;
    lineDestroy(line);
}

static void tailFinish(tunnel_t *t, line_t *line)
{
    discard line;
    twfRequire(t == next, "Finish reached the wrong tail");
    ++finishes;
}

static void capture(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    const bool expect_upstream = encoding ? ENCODE_UPSTREAM : ! ENCODE_UPSTREAM;
    twfRequire(t == (expect_upstream ? next : prev), "Encryption reversed its output direction");
    ++outputs;
    twfRequire(outputs == 1, "Encryption emitted another record after synchronous close");
    if (encoding)
    {
        encryption_tstate_t *ts = tunnelGetState(encryption);
        twfRequire(encryptionDecodeFrame(ts->algorithm, ts->key, buffer) == kWCryptoOk,
                   "chunked output did not authenticate");
        twfRequire(sbufGetLength(buffer) == 16 && memoryEqual(sbufGetRawPtr(buffer), "0123456789abcdef", 16),
                   "first encrypted chunk changed plaintext");
    }
    else
        twfRequire(sbufGetLength(buffer) == 3 && memoryEqual(sbufGetRawPtr(buffer), "ABC", 3),
                   "first decrypted record changed plaintext");
    lineReuseBuffer(line, buffer);
    if (! close_on_output)
        return;

    if (t == next)
        finishDown(encryption, line);
    else
    {
        /* This endpoint is the creator: Finish travels toward next before the
         * owner retires the normal line itself. */
        finishUp(encryption, line);
        lineDestroy(line);
    }
}

static line_t *begin(bool encode)
{
    encoding = encode;
    outputs = finishes = 0;
    close_on_output    = true;
    line_t *line       = twfLinePoolCreateLine(&lines);
    initialize(lineGetState(line, encryption), env.pool);
    lineRef(line);
    return line;
}

static void endClosed(line_t *line)
{
    twfRequire(! lineIsAlive(line) && outputs == 1 && finishes == 1,
               "output close did not stop after one record and one Finish");
    twfRequireLineStateZeroed(line, encryption, "output close retained Encryption line state");
    twfRequireEqualU32(twfLineRefCount(line), 1, "output close leaked a temporary line reference");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
}

static void testEncodeClose(void)
{
    twfSetCase("Encryption stops chunked output when the first callback closes the borrowed line");
    line_t    *line        = begin(true);
    sbuf_t    *buffer      = bufferpoolGetSmallBuffer(env.pool);
    const char plaintext[] = "0123456789abcdef0123456789abcdefTAIL";
    sbufSetLength(buffer, sizeof(plaintext));
    sbufWrite(buffer, plaintext, sizeof(plaintext));
    encodePayload(encryption, line, buffer);
    endClosed(line);
}

static void testDecodeClose(void)
{
    twfSetCase("Encryption discards later coalesced records when the first plaintext callback closes");
    line_t              *line       = begin(false);
    encryption_tstate_t *ts         = tunnelGetState(encryption);
    sbuf_t              *combined   = bufferpoolGetSmallBuffer(env.pool);
    const char          *payloads[] = {"ABC", "DEF"};
    for (size_t i = 0; i < 2; ++i)
    {
        sbuf_t *frame = bufferpoolGetSmallBuffer(env.pool);
        sbufSetLength(frame, 3);
        sbufWrite(frame, payloads[i], 3);
        twfRequire(encryptionEncodeFrame(ts->algorithm, ts->key, &frame) == kWCryptoOk,
                   "coalesced fixture encoding failed");
        sbufConcatNoCheck(combined, frame);
        bufferpoolReuseBuffer(env.pool, frame);
    }
    decodePayload(encryption, line, combined);
    endClosed(line);
}

static void testEmptyInput(void)
{
    twfSetCase("Encryption drops empty application input before record encoding");
    line_t *line = begin(true);
    encodePayload(encryption, line, bufferpoolGetSmallBuffer(env.pool));
    twfRequire(lineIsAlive(line) && outputs == 0 && finishes == 0,
               "empty application input emitted a record or closed the line");
    finishUp(encryption, line);
    lineDestroy(line);
    lineUnref(line);
    twfRequireNoLeakedBuffers();
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    twfWorkerEnvSetup(&env, 65536, kEncryptionFramePrefixSize);
    prev       = tunnelCreate(NULL, 0, 0);
    encryption = tunnelCreate(NULL, sizeof(encryption_tstate_t), sizeof(encryption_lstate_t));
    next       = tunnelCreate(NULL, 0, 0);
    twfRequire(prev != NULL && encryption != NULL && next != NULL, "failed to create Encryption fixture");
    tunnelBind(prev, encryption);
    tunnelBind(encryption, next);
    prev->fnPayloadD        = capture;
    prev->fnFinD            = ownerFinish;
    next->fnPayloadU        = capture;
    next->fnFinU            = tailFinish;
    encryption_tstate_t *ts = tunnelGetState(encryption);
    ts->algorithm           = kEncryptionAlgorithmChaCha20Poly1305;
    ts->max_frame_payload   = 16;
    twfLinePoolSetup(&lines, encryption->lstate_size, 4);
    testEncodeClose();
    testDecodeClose();
    testEmptyInput();
    twfRequireEqualU32(masterpoolGetCheckedOut(lines.master), 0, "Encryption fixture leaked a line");
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(encryption);
    tunnelDestroy(prev);
    twfWorkerEnvTeardown(&env);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}

/*
 * Covers: EncryptionClient/Server retain explicit direction and borrowed-line lifetime.
 * Setup: real pooled line, worker pool and AEAD; the first output synchronously closes
 * through the opposite Finish callback and the previous endpoint destroys its line.
 * Cases: close during chunked encryption and coalesced decryption; empty stream input
 * discard; datagram boundaries, limits, malformed records and per-line selection on mixed input.
 * Checks: one correctly directed output, exact plaintext, no output after close, zero
 * state and complete release of the original input and remaining buffered records.
 * CTest: waterwall.encryptionclient_reentrant_output_unit;
 * waterwall.encryptionserver_reentrant_output_unit
 */
#if defined(TEST_ENCRYPTION_CLIENT)
#include "EncryptionClient/structure.h"
#define encryption_tstate_t encryptionclient_tstate_t
#define encryption_lstate_t encryptionclient_lstate_t
#define initialize          encryptionclientTunnelUpStreamInit
#define encodePayload       encryptionclientTunnelUpStreamPayload
#define decodePayload       encryptionclientTunnelDownStreamPayload
#define finishUp            encryptionclientTunnelUpStreamFinish
#define finishDown          encryptionclientTunnelDownStreamFinish
#define ENCODE_UPSTREAM     true
#elif defined(TEST_ENCRYPTION_SERVER)
#include "EncryptionServer/structure.h"
#define encryption_tstate_t encryptionserver_tstate_t
#define encryption_lstate_t encryptionserver_lstate_t
#define initialize          encryptionserverTunnelUpStreamInit
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
static unsigned         pauses;
static sbuf_t          *reentrant_input;
static uint32_t         expected_length;
static uint8_t          datagram_bytes[kEncryptionHardMaxFramePayload + 1];

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

static void closeFromOutput(tunnel_t *t, line_t *line)
{
    if (t == next)
        finishDown(encryption, line);
    else
    {
        /* The upstream Finish precedes retirement by the creator. */
        finishUp(encryption, line);
        lineDestroy(line);
    }
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
    if (close_on_output)
        closeFromOutput(t, line);
}

static void capturePause(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    ++pauses;
}

static void captureDatagram(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    const bool expect_upstream = encoding ? ENCODE_UPSTREAM : ! ENCODE_UPSTREAM;
    twfRequire(t == (expect_upstream ? next : prev), "Encryption reversed its datagram direction");
    ++outputs;
    if (encoding)
    {
        const encryption_tstate_t *ts = tunnelGetState(encryption);
        twfRequire(sbufGetLength(buffer) == kEncryptionFrameOverhead + expected_length &&
                       encryptionDatagramHasFrame(buffer, ts->max_frame_payload),
                   "datagram output is not exactly one record");
        twfRequire(encryptionDecodeFrame(ts->algorithm, ts->key, buffer) == kWCryptoOk,
                   "datagram output did not authenticate");
    }
    twfRequire(sbufGetLength(buffer) == expected_length &&
                   memoryEqual(sbufGetRawPtr(buffer), datagram_bytes, expected_length),
               "datagram output changed plaintext bytes or length");
    lineReuseBuffer(line, buffer);

    if (reentrant_input != NULL)
    {
        sbuf_t *nested  = reentrant_input;
        reentrant_input = NULL;
        if (expect_upstream)
            tunnelPrevDownStreamPause(t, line);
        else
            tunnelNextUpStreamPause(t, line);

        if (encoding)
            encodePayload(encryption, line, nested);
        else
            decodePayload(encryption, line, nested);
    }
    if (close_on_output)
        closeFromOutput(t, line);
}

static void tailInit(tunnel_t *t, line_t *line)
{
    discard       t;
    const uint8_t transport = addresscontextGetTransportOffer(lineGetDestinationAddressContext(line));
    twfRequire(transport == kAddressContextTransportTcp || transport == kAddressContextTransportUdp,
               "Encryption forwarded Init before selecting an exact protocol");
}

static line_t *newLine(uint8_t source_protocol, uint8_t destination_protocol)
{
    line_t *line = twfLinePoolCreateLine(&lines);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), source_protocol);
    addresscontextSetTransportOffer(lineGetDestinationAddressContext(line), destination_protocol);
    lineRef(line);
    initialize(encryption, line);
    return line;
}

static line_t *begin(bool encode)
{
    encoding = encode;
    outputs = finishes = 0;
    close_on_output    = true;
    return newLine(IP_PROTO_TCP, kAddressContextTransportTcp);
}

static void retire(line_t *line)
{
    finishUp(encryption, line);
    lineDestroy(line);
    twfRequireLineStateZeroed(line, encryption, "Finish retained Encryption line state");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
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
    twfSetCase("Encryption buffers split stream records and discards later coalesced records on close");
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
    sbuf_t *prefix = bufferpoolGetSmallBuffer(env.pool);
    sbufSetLength(prefix, 3);
    sbufWrite(prefix, sbufGetRawPtr(combined), 3);
    sbufShiftRight(combined, 3);
    decodePayload(encryption, line, prefix);
    twfRequire(outputs == 0 && finishes == 0 && lineIsAlive(line), "split stream header closed or emitted output");
    decodePayload(encryption, line, combined);
    endClosed(line);
}

static void testEmptyInput(void)
{
    twfSetCase("Encryption drops empty application input before record encoding");
    encoding = true;
    outputs = finishes = 0;
    line_t *line       = newLine(IP_PROTO_TCP, kAddressContextTransportTcp);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), IP_PROTO_UDP);
    encodePayload(encryption, line, bufferpoolGetSmallBuffer(env.pool));
    twfRequire(lineIsAlive(line) && outputs == 0 && finishes == 0,
               "empty application input emitted a record or closed the line");
    retire(line);
}

static sbuf_t *makeDatagram(uint32_t length, bool wire)
{
    sbuf_t *buffer = bufferpoolGetLargeBuffer(env.pool);
    sbufSetLength(buffer, length);
    sbufWrite(buffer, datagram_bytes, length);
    if (wire)
    {
        const encryption_tstate_t *ts = tunnelGetState(encryption);
        twfRequire(encryptionEncodeFrame(ts->algorithm, ts->key, &buffer) == kWCryptoOk,
                   "failed to encode datagram fixture");
    }
    return buffer;
}

static void deliverDatagram(line_t *line, uint32_t length)
{
    expected_length = length;
    if (encoding)
        encodePayload(encryption, line, makeDatagram(length, false));
    else
        decodePayload(encryption, line, makeDatagram(length, true));
}

static void testMixedDestinationMode(void)
{
    twfSetCase("Mixed Encryption lines sharing a TCP source select the mode from their destination offers");
    line_t *stream   = newLine(IP_PROTO_TCP, kAddressContextTransportBoth);
    line_t *datagram = newLine(IP_PROTO_TCP, kAddressContextTransportUdp);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(stream), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(datagram), IP_PROTO_TCP);

    encoding = true;
    outputs = finishes = 0;
    encodePayload(encryption, stream, makeDatagram(0, false));
    twfRequire(outputs == 0, "stream line encoded an empty delivery after a destination rewrite");
    deliverDatagram(datagram, 0);
    twfRequire(outputs == 1, "datagram line lost an empty delivery after a destination rewrite");
    retire(datagram);
    retire(stream);
}

static void testDatagramBoundaries(bool encode)
{
    twfSetCase("Encryption transfers one record per datagram, including empty and max-size datagrams");
    encoding = encode;
    outputs = finishes       = 0;
    line_t        *line      = newLine(IP_PROTO_TCP, kAddressContextTransportUdp);
    const uint32_t lengths[] = {0, 13, kEncryptionHardMaxFramePayload};
    for (unsigned i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        deliverDatagram(line, lengths[i]);
        twfRequireEqualU32(outputs, i + 1, "datagram delivery emitted the wrong callback count");
    }
    if (encode)
    {
        encodePayload(encryption, line, makeDatagram(kEncryptionHardMaxFramePayload + 1, false));
        twfRequire(outputs == 3 && lineIsAlive(line) && finishes == 0, "oversized datagram was not dropped whole");
        deliverDatagram(line, 29);
        twfRequireEqualU32(outputs, 4, "valid datagram after oversized input was lost");
    }
    retire(line);
}

static void testDatagramReentry(bool encode)
{
    twfSetCase("Encryption preserves datagram delivery through reentrant Pause, input and Finish");
    encoding = encode;
    outputs = finishes = pauses = 0;
    line_t *line                = newLine(0, kAddressContextTransportUdp);
    reentrant_input             = makeDatagram(19, ! encode);
    deliverDatagram(line, 19);
    twfRequire(outputs == 2 && pauses == 1 && lineIsAlive(line), "reentrant datagram duplicated, lost or paused");

    outputs         = 0;
    close_on_output = true;
    deliverDatagram(line, 7);
    endClosed(line);
    close_on_output = false;
}

static void testMalformedDatagrams(void)
{
    twfSetCase("Encryption closes only the line receiving an invalid datagram and forwards no plaintext");
    encoding        = false;
    line_t *healthy = newLine(IP_PROTO_UDP, kAddressContextTransportUdp);
    enum
    {
        kTruncatedHeader,
        kTruncatedTag,
        kTrailingByte,
        kTwoRecords,
        kInvalidTag
    };
    for (unsigned bad = kTruncatedHeader; bad <= kInvalidTag; ++bad)
    {
        outputs = finishes = 0;
        line_t *line       = newLine(0, kAddressContextTransportUdp);
        sbuf_t *wire       = makeDatagram(10, true);
        switch (bad)
        {
        case kTruncatedHeader:
            sbufSetLength(wire, kEncryptionTlsHeaderSize - 1);
            break;
        case kTruncatedTag:
            sbufReduceLength(wire, 1);
            break;
        case kTrailingByte: {
            const uint8_t extra = 0;
            twfRequire(sbufTryAppendBytesInPlace(wire, &extra, sizeof(extra)), "failed to append a trailing byte");
            break;
        }
        case kTwoRecords: {
            sbuf_t *second = makeDatagram(4, true);
            sbufConcatNoCheck(wire, second);
            lineReuseBuffer(line, second);
            break;
        }
        case kInvalidTag:
            sbufGetMutablePtr(wire)[sbufGetLength(wire) - 1] ^= 0x20;
            break;
        }
        decodePayload(encryption, line, wire);
        twfRequire(outputs == 0 && finishes == 2 && ! lineIsAlive(line) && lineIsAlive(healthy),
                   "malformed record escaped, failed to close, or disrupted an independent line");
        twfRequireLineStateZeroed(line, encryption, "malformed record retained line state");
        lineUnref(line);
        deliverDatagram(healthy, 6);
        twfRequireEqualU32(outputs, 1, "independent line failed after malformed record");
    }
    retire(healthy);
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
    prev->fnPauseD          = capturePause;
    next->fnInitU           = tailInit;
    next->fnPayloadU        = capture;
    next->fnFinU            = tailFinish;
    next->fnPauseU          = capturePause;
    encryption_tstate_t *ts = tunnelGetState(encryption);
    ts->algorithm           = kEncryptionAlgorithmChaCha20Poly1305;
    ts->max_frame_payload   = 16;
    twfLinePoolSetup(&lines, encryption->lstate_size, 4);
    testEncodeClose();
    testDecodeClose();
    testEmptyInput();

    prev->fnPayloadD      = captureDatagram;
    next->fnPayloadU      = captureDatagram;
    ts->max_frame_payload = kEncryptionHardMaxFramePayload;
    close_on_output       = false;
    for (size_t i = 0; i < sizeof(datagram_bytes); ++i)
        datagram_bytes[i] = (uint8_t) (i ^ (i >> 8));
    testMixedDestinationMode();
    testDatagramBoundaries(true);
    testDatagramBoundaries(false);
    testDatagramReentry(true);
    testDatagramReentry(false);
    testMalformedDatagrams();
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

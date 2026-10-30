/*
 * Covers: shared WebSocket incremental body decoding and bounded control frames.
 * Setup: Real BufferStream and owner-thread pools, without tunnel callbacks.
 * Checks: Header splits, masked slice offsets, progressive 1 GiB declarations,
 *         early invalid-header rejection, empty/control/coalesced frame order.
 * Limits: Node input admission, HTTP/2 pumping and callback closure are covered
 *         by the HTTP transport fixtures.
 * CTest: waterwall.http_websocket_decoder_unit.
 */
#include "HttpCommon/websocket_decoder.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static const uint8_t kMask[4] = {0x17, 0x82, 0xE3, 0x49};

static uint8_t pattern(size_t offset)
{
    return (uint8_t) ((offset * 131U + 29U) % 251U);
}

static size_t makeHeader(uint8_t *header, uint8_t opcode, bool fin, bool masked, uint64_t length)
{
    header[0] = (uint8_t) ((fin ? 0x80U : 0U) | opcode);
    size_t count;
    if (length <= 125)
    {
        header[1] = (uint8_t) length;
        count     = 2;
    }
    else if (length <= UINT16_MAX)
    {
        header[1] = 126;
        header[2] = (uint8_t) (length >> 8);
        header[3] = (uint8_t) length;
        count     = 4;
    }
    else
    {
        header[1] = 127;
        for (size_t i = 0; i < 8; ++i)
            header[2 + i] = (uint8_t) (length >> (56 - 8 * i));
        count = 10;
    }
    if (masked)
    {
        header[1] |= 0x80U;
        memoryCopy(header + count, kMask, sizeof(kMask));
        count += sizeof(kMask);
    }
    return count;
}

static void pushBytes(buffer_stream_t *stream, const uint8_t *data, uint32_t length)
{
    if (length == 0)
        return;
    sbuf_t *buf = bufferpoolGetBestFit(stream->pool, length, 0);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    bufferstreamPush(stream, buf);
}

static void pushBody(buffer_stream_t *stream, uint32_t offset, uint32_t length, bool masked)
{
    sbuf_t *buf = bufferpoolGetBestFit(stream->pool, length, 0);
    sbufSetLength(buf, length);
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(buf)[i] = pattern(offset + i) ^ (masked ? kMask[(offset + i) & 3U] : 0);
    bufferstreamPush(stream, buf);
}

static void checkBody(sbuf_t *out, size_t offset, uint32_t maximum)
{
    require(out != NULL && sbufGetLength(out) > 0 && sbufGetLength(out) <= maximum,
            "decoder returned an empty or oversized body slice");
    const uint8_t *bytes = sbufGetRawPtr(out);
    for (uint32_t i = 0; i < sbufGetLength(out); ++i)
        require(bytes[i] == pattern(offset + i), "decoded body bytes or masking position changed");
}

static void caseHeaderSplitsAndLengths(buffer_pool_t *pool, bool masked)
{
    testCaseSet("WebSocket header splits and frame-length encodings");
    const uint32_t lengths[] = {0, 1, 125, 126, 65535, 65536};
    for (size_t index = 0; index < ARRAY_SIZE(lengths); ++index)
    {
        uint8_t header[14];
        size_t  header_size = makeHeader(header, 2, true, masked, lengths[index]);
        for (size_t split = 1; split < header_size; ++split)
        {
            buffer_stream_t          stream = bufferstreamCreate(pool, 0);
            http_websocket_decoder_t state  = {0};
            sbuf_t                  *out    = NULL;
            pushBytes(&stream, header, (uint32_t) split);
            require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketNeedMore,
                    "partial WebSocket header did not wait");
            require(out == NULL && ! state.active && bufferstreamGetBufLen(&stream) == split,
                    "partial WebSocket header was consumed");
            pushBytes(&stream, header + split, (uint32_t) (header_size - split));
            if (lengths[index] != 0)
                pushBody(&stream, 0, lengths[index], masked);
            uint32_t received = 0;
            while (received < lengths[index])
            {
                require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketData,
                        "complete data frame did not produce a body slice");
                checkBody(out, received, kHttpWebSocketBodySliceBytes);
                received += sbufGetLength(out);
                require(state.remaining == lengths[index] - received,
                        "body state was not advanced before returning output");
                require(state.active == (received < lengths[index]), "completed frame state remained active");
                bufferpoolReuseBuffer(pool, out);
            }
            require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketNeedMore && out == NULL,
                    "empty stream produced an event");
            require(! state.active && bufferstreamGetBufLen(&stream) == 0, "frame was not completely consumed");
            bufferstreamDestroy(&stream);
        }
    }
}

static void caseLargeDeclaration(buffer_pool_t *pool, bool masked, bool coalesced)
{
    testCaseSet("WebSocket 1 GiB declaration delivers 4 MiB progressively");
    buffer_stream_t          stream   = bufferstreamCreate(pool, 0);
    http_websocket_decoder_t state    = {0};
    const uint32_t           declared = 1U << 30;
    const uint32_t           provided = 4U << 20;
    uint8_t                  header[14];
    size_t                   header_size = makeHeader(header, 2, false, masked, declared);
    pushBytes(&stream, header, (uint32_t) header_size);
    uint32_t       sent = 0, received = 0, iterations = 0;
    const uint32_t chunks[] = {1, 2, 3, 7, 4099, 32769};
    while (sent < provided)
    {
        uint32_t chunk = coalesced ? provided : chunks[iterations++ % ARRAY_SIZE(chunks)];
        chunk          = min(chunk, provided - sent);
        pushBody(&stream, sent, chunk, masked);
        sent += chunk;
        for (;;)
        {
            sbuf_t                 *out    = NULL;
            http_websocket_result_t result = httpWebSocketDecoderStep(&state, &stream, masked, &out);
            if (result == kHttpWebSocketNeedMore)
                break;
            require(result == kHttpWebSocketData, "large valid frame did not stream immediately");
            checkBody(out, received, kHttpWebSocketBodySliceBytes);
            received += sbufGetLength(out);
            require(state.remaining == declared - received && state.active,
                    "partial frame state was not published before output");
            bufferpoolReuseBuffer(pool, out);
        }
        require(received == sent && bufferstreamGetBufLen(&stream) == 0 && bufferstreamGetCharge(&stream) == 0,
                "decoder retained an incomplete data-frame body");
    }
    require(received == provided, "large frame lost application bytes");
    bufferstreamDestroy(&stream);
}

static void caseControlAndCoalescedFrames(buffer_pool_t *pool, bool masked)
{
    testCaseSet("WebSocket control frames stay whole and preserve coalesced order");
    buffer_stream_t               stream    = bufferstreamCreate(pool, 0);
    http_websocket_decoder_t      state     = {0};
    const uint8_t                 opcodes[] = {2, 1, 0, 9, 10, 8};
    const http_websocket_result_t results[] = {kHttpWebSocketNeedMore,
                                               kHttpWebSocketData,
                                               kHttpWebSocketData,
                                               kHttpWebSocketPing,
                                               kHttpWebSocketPong,
                                               kHttpWebSocketClose};
    for (size_t i = 0; i < ARRAY_SIZE(opcodes); ++i)
    {
        uint8_t  header[14];
        uint32_t length = i == 0 || i == 4 ? 0 : (i == 3 ? 125 : 3);
        size_t   count  = makeHeader(header, opcodes[i], true, masked, length);
        pushBytes(&stream, header, (uint32_t) count);
        if (length != 0)
            pushBody(&stream, 0, length, masked);
    }
    for (size_t i = 1; i < ARRAY_SIZE(opcodes); ++i)
    {
        sbuf_t *out = NULL;
        require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == results[i],
                "coalesced event ordering changed");
        require(! state.active && state.remaining == 0, "complete event returned before resetting state");
        if (i == 4)
            require(out == NULL, "empty pong allocated an application buffer");
        else
        {
            checkBody(out, 0, 125);
            require(sbufGetLength(out) == (i == 3 ? 125U : 3U), "control frame was split");
            bufferpoolReuseBuffer(pool, out);
        }
    }
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(pool, 0);
    uint8_t header[14];
    size_t  count = makeHeader(header, 9, true, masked, 125);
    pushBytes(&stream, header, (uint32_t) count);
    pushBody(&stream, 0, 124, masked);
    sbuf_t *out = NULL;
    require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketNeedMore && out == NULL,
            "incomplete ping was delivered");
    require(state.active && state.remaining == 125 && bufferstreamGetBufLen(&stream) == 124,
            "incomplete control frame body was consumed");
    pushBody(&stream, 124, 1, masked);
    require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketPing,
            "completed ping did not produce an event");
    checkBody(out, 0, 125);
    require(sbufGetLength(out) == 125 && ! state.active, "completed ping state or length changed");
    bufferpoolReuseBuffer(pool, out);
    bufferstreamDestroy(&stream);
}

static void caseInvalidHeaders(buffer_pool_t *pool, bool masked)
{
    testCaseSet("WebSocket invalid declarations fail before waiting for bodies");
    struct
    {
        uint8_t  opcode;
        bool     fin;
        bool     wrong_mask;
        uint64_t length;
    } cases[] = {{2, true, false, (uint64_t) UINT32_MAX + 1},
                 {2, true, false, UINT64_MAX},
                 {9, true, false, 126},
                 {8, false, false, 0},
                 {3, true, false, 1},
                 {11, true, false, 0},
                 {2, true, true, 1}};
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        buffer_stream_t          stream = bufferstreamCreate(pool, 0);
        http_websocket_decoder_t state  = {0};
        uint8_t                  header[14];
        bool                     wire_masked = masked != cases[i].wrong_mask;
        size_t count = makeHeader(header, cases[i].opcode, cases[i].fin, wire_masked, cases[i].length);
        /* Even a missing mask key must not defer an already-invalid declaration. */
        pushBytes(&stream, header, (uint32_t) (count - (wire_masked ? 4 : 0)));
        sbuf_t *out = NULL;
        require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketError && out == NULL,
                "invalid WebSocket declaration waited for body bytes");
        require(! state.active, "invalid header published active body state");
        bufferstreamDestroy(&stream);
    }

    buffer_stream_t          stream = bufferstreamCreate(pool, 0);
    http_websocket_decoder_t state  = {0};
    uint8_t                  header[14];
    size_t                   count = makeHeader(header, 2, true, masked, UINT32_MAX);
    pushBytes(&stream, header, (uint32_t) count);
    pushBody(&stream, 0, 3, masked);
    sbuf_t *out = NULL;
    require(httpWebSocketDecoderStep(&state, &stream, masked, &out) == kHttpWebSocketData,
            "supported UINT32_MAX declaration was rejected");
    checkBody(out, 0, 3);
    require(state.remaining == UINT32_MAX - 3U, "maximum frame remaining length overflowed");
    bufferpoolReuseBuffer(pool, out);
    bufferstreamDestroy(&stream);
}

int main(void)
{
    master_pool_t *large  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool   = bufferpoolCreate(large, medium, small, 4, 16384, 65536, 1024, 16384, 16384);
    require(pool != NULL, "failed to create component-test buffer pool");
    for (unsigned masked = 0; masked < 2; ++masked)
    {
        caseHeaderSplitsAndLengths(pool, masked != 0);
        caseLargeDeclaration(pool, masked != 0, false);
        caseLargeDeclaration(pool, masked != 0, true);
        caseControlAndCoalescedFrames(pool, masked != 0);
        caseInvalidHeaders(pool, masked != 0);
    }
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    puts("http_websocket_decoder_test: all checks passed");
    return 0;
}

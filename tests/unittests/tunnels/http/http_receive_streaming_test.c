/*
 * Actual HttpClient/HttpServer receive callbacks: very large declared HTTP chunks
 * and WebSocket frames stream progressively, including coalesced deliveries,
 * masking offsets, nested input, callback-driven Finish and bounded metadata.
 * The fixture owns the normal line; the HTTP middle node borrows it.
 * CTest: waterwall.httpclient_receive_streaming_unit,
 *        waterwall.httpserver_receive_streaming_unit
 */
#ifdef TEST_HTTP_CLIENT
#include "HttpClient/structure.h"
typedef httpclient_tstate_t http_tstate_t;
typedef httpclient_lstate_t http_lstate_t;
#define httpInitialize httpclientLinestateInitialize
#define httpDestroy    httpclientLinestateDestroy
#define httpReceive    httpclientTunnelDownStreamPayload
#define httpFinish     httpclientTunnelDownStreamFinish
#define kRuntimeHttp1  kHttpClientRuntimeHttp1
#define kBodyChunked   kHttpClientH1BodyChunked
#else
#include "HttpServer/structure.h"
typedef httpserver_tstate_t http_tstate_t;
typedef httpserver_lstate_t http_lstate_t;
#define httpInitialize httpserverLinestateInitialize
#define httpDestroy    httpserverLinestateDestroy
#define httpReceive    httpserverTunnelUpStreamPayload
#define httpFinish     httpserverTunnelUpStreamFinish
#define kRuntimeHttp1  kHttpServerRuntimeHttp1
#define kBodyChunked   kHttpServerH1BodyChunked
#endif

#include "HttpCommon/receive.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kBodyBytes     = 4U * 1024U * 1024U,
    kDeclaredBytes = 1024U * 1024U * 1024U,
    kNestedBytes   = 131,
    kOuterBytes    = 32771
};

typedef struct receive_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
    uint32_t         delivered;
    uint32_t         calls;
    uint32_t         depth;
    uint32_t         max_depth;
    unsigned         overflow;
    bool             websocket;
    bool             inject;
    bool             close;
} receive_fixture_t;

static receive_fixture_t f;
#ifndef TEST_HTTP_CLIENT
static const uint8_t mask[4] = {0xa7, 0x31, 0xd2, 0x5c};
#endif

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* The buffer_pool.c internal recycle bypasses GNU's external call wrapper. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, second);
    if (! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, second))
        twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, second, "too many merged buffers");
    if (merged != first)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, first);
        if (! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, merged))
            twfTrackAcquired(merged);
    }
    return merged;
}

static http_lstate_t *state(void)
{
    return lineGetState(f.line, f.http);
}

static uint8_t pattern(uint32_t offset)
{
    return (uint8_t) ((offset * 13U + 7U) % 251U);
}

static sbuf_t *allocateInput(uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(f.env.pool, length, 0);
    sbufSetLength(buf, length);
    return buf;
}

static void receiveBytes(const void *bytes, uint32_t length)
{
    sbuf_t *buf = allocateInput(length);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    httpReceive(f.http, f.line, buf);
}

static void receivePattern(uint32_t offset, uint32_t length)
{
    sbuf_t  *buf   = allocateInput(length);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
    {
        bytes[i] = pattern(offset + i);
#ifndef TEST_HTTP_CLIENT
        if (f.websocket)
            bytes[i] ^= mask[(offset + i) & 3U];
#endif
    }
    httpReceive(f.http, f.line, buf);
}

static void discardWire(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(line, buf);
}

static void receiveBody(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    ++f.depth;
    f.max_depth = max(f.max_depth, f.depth);
    ++f.calls;
    const uint32_t length = sbufGetLength(buf);
    const uint8_t *bytes  = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < length; ++i)
        twfRequire(bytes[i] == pattern(f.delivered + i), "decoded body bytes or FIFO order changed");
    f.delivered += length;
    lineReuseBuffer(line, buf);
    if (f.inject)
    {
        f.inject = false;
        receivePattern(kOuterBytes, kNestedBytes);
    }
    if (f.overflow != 0)
    {
        unsigned mode = f.overflow;
        f.overflow    = 0;
        if (mode == 1)
        {
            httpReceive(f.http, f.line, allocateInput(kHttpReceiveNestedBytes + 1));
        }
        else if (mode == 2)
        {
            sbuf_t *nested = allocateInput(kHttpReceiveNestedCharge + 1);
            sbufSetLength(nested, 1);
            httpReceive(f.http, f.line, nested);
        }
        else
        {
            for (unsigned i = 0; i <= kHttpReceiveNestedEntries; ++i)
            {
                twfRequire(state()->tunnel == f.http, "nested input entry limit rejected an admitted prefix");
                httpReceive(f.http, f.line, allocateInput(1));
            }
        }
    }
    if (f.close)
    {
        f.close = false;
        httpFinish(f.http, f.line);
    }
    --f.depth;
}

static void setup(bool websocket)
{
    memoryZero(&f, sizeof(f));
    twfWorkerEnvSetup(&f.env, 4096, 0);
    f.prev = twfCreatePrevTunnel(&f.trace);
    f.http = tunnelCreate(NULL, sizeof(http_tstate_t), sizeof(http_lstate_t));
    f.next = twfCreateNextTunnel(&f.trace);
    twfRequire(f.http != NULL, "HTTP fixture tunnel allocation failed");
    tunnelBind(f.prev, f.http);
    tunnelBind(f.http, f.next);
    f.prev->chain_index = 0;
    f.http->chain_index = 1;
    f.next->chain_index = 2;
#ifdef TEST_HTTP_CLIENT
    f.prev->fnPayloadD = receiveBody;
    f.next->fnPayloadU = discardWire;
#else
    f.next->fnPayloadU = receiveBody;
    f.prev->fnPayloadD = discardWire;
#endif
    f.line = twfLineCreate(f.http->lstate_size);
    httpInitialize(state(), f.http, f.line);
    state()->runtime_proto                                        = kRuntimeHttp1;
    state()->h1_headers_parsed                                    = true;
    state()->h1_body_mode                                         = kBodyChunked;
    state()->websocket_active                                     = websocket;
    ((http_tstate_t *) tunnelGetState(f.http))->websocket_enabled = websocket;
    f.websocket                                                   = websocket;
}

static void teardown(void)
{
    if (state()->tunnel != NULL)
        httpDestroy(state());
    twfRequireLineStateZeroed(f.line, f.http, "HTTP receive teardown retained state");
    twfRequireEqualU32(twfLineRefCount(f.line), 1, "HTTP receive leaked a line reference");
    twfRequireNoLeakedBuffers();
    http_tstate_t *ts = tunnelGetState(f.http);
    if (ts->cbs != NULL)
        nghttp2_session_callbacks_del(ts->cbs);
    twfLineDestroy(f.line);
    tunnelDestroy(f.prev);
    tunnelDestroy(f.http);
    tunnelDestroy(f.next);
    twfWorkerEnvTeardown(&f.env);
}

static uint32_t frameHeader(uint8_t *header, uint64_t length, uint8_t opcode)
{
    header[0] = 0x80U | opcode;
    header[1] = 127;
    for (unsigned i = 0; i < 8; ++i)
        header[2 + i] = (uint8_t) (length >> (56 - 8 * i));
#ifdef TEST_HTTP_CLIENT
    return 10;
#else
    header[1] |= 0x80;
    memoryCopy(header + 10, mask, sizeof(mask));
    return 14;
#endif
}

static void startBody(void)
{
    if (! f.websocket)
    {
        receiveBytes("40000000\r\n", 10);
        return;
    }
    uint8_t  header[14];
    uint32_t length = frameHeader(header, kDeclaredBytes, 2);
    /* Exercise a header that arrives one byte at a time. */
    for (uint32_t i = 0; i < length; ++i)
        receiveBytes(header + i, 1);
}

static void requireBounded(void)
{
    twfRequire(state()->tunnel == f.http, "valid receive input closed the HTTP state");
    twfRequire(bufferstreamGetBufLen(&state()->in_stream) <= kHttpReceiveStreamBytes,
               "HTTP retained too many undecoded bytes");
    twfRequire(bufferstreamGetCharge(&state()->in_stream) <= kHttpReceiveStreamCharge,
               "HTTP retained too much input allocation charge");
    twfRequire(bufferstreamGetEntryCount(&state()->in_stream) <= kHttpReceiveNestedEntries,
               "HTTP retained too many input allocations");
}

static void caseLargeBody(bool websocket, bool coalesced)
{
    twfSetCase(websocket ? "HTTP WebSocket streams a 1 GiB declared frame" : "HTTP streams a 1 GiB declared chunk");
    setup(websocket);
    startBody();
    uint32_t offset = 0;
    while (offset < kBodyBytes)
    {
        uint32_t length = min(kBodyBytes - offset, coalesced ? kBodyBytes : 16381U);
        receivePattern(offset, length);
        offset += length;
        twfRequireEqualU32(f.delivered, offset, "HTTP waited for a complete peer-declared body");
        requireBounded();
    }
    twfRequire(f.calls > 1, "large body was not delivered in bounded pieces");
    teardown();
}

static void caseNestedBody(bool websocket, bool close)
{
    twfSetCase(close ? "HTTP receive stops after Finish inside output" : "HTTP nested receive preserves outer FIFO");
    setup(websocket);
    startBody();
    f.inject = true;
    f.close  = close;
    receivePattern(0, kOuterBytes);
    twfRequireEqualU32(f.max_depth, 1, "nested input recursively entered the body callback");
    if (close)
    {
        twfRequireEqualU32(f.calls, 1, "HTTP delivered output after callback-driven Finish");
        twfRequireLineStateZeroed(f.line, f.http, "callback-driven Finish retained receive input");
    }
    else
    {
        twfRequireEqualU32(f.delivered, kOuterBytes + kNestedBytes, "nested HTTP body input was lost");
        requireBounded();
    }
    teardown();
}

static void caseMetadataLimit(bool trailer, bool overflow, bool terminated)
{
    twfSetCase(trailer ? "HTTP chunk trailers have an aggregate bound" : "HTTP chunk size lines have a bound");
    setup(false);
    if (trailer)
        receiveBytes("0\r\n", 3);
    const uint32_t limit  = trailer ? 16384U : 1024U;
    const uint32_t length = limit + (overflow ? 1U : 0U);
    sbuf_t        *buf    = allocateInput(length);
    memorySet(sbufGetMutablePtr(buf), trailer ? 'x' : ' ', length);
    if (trailer)
    {
        sbufGetMutablePtr(buf)[0] = 'X';
        sbufGetMutablePtr(buf)[1] = ':';
    }
    else
    {
        sbufGetMutablePtr(buf)[0] = '1';
        sbufGetMutablePtr(buf)[1] = ';';
    }
    if (terminated)
    {
        sbufGetMutablePtr(buf)[length - 2] = '\r';
        sbufGetMutablePtr(buf)[length - 1] = '\n';
        if (trailer)
        {
            sbufGetMutablePtr(buf)[length - 4] = '\r';
            sbufGetMutablePtr(buf)[length - 3] = '\n';
        }
    }
    httpReceive(f.http, f.line, buf);
    if (overflow || ! terminated)
        twfRequireLineStateZeroed(f.line, f.http, "oversized HTTP chunk metadata remained admitted");
    else
        requireBounded();
    teardown();
}

static void caseInvalidWebSocketHeader(void)
{
    twfSetCase("HTTP rejects oversized WebSocket control frames before body arrival");
    setup(true);
    uint8_t  header[14];
    uint32_t length = frameHeader(header, kDeclaredBytes, 9);
    receiveBytes(header, length);
    twfRequireLineStateZeroed(f.line, f.http, "invalid WebSocket declaration waited for body bytes");
    teardown();
}

static void caseSmallRetainedTail(bool websocket)
{
    twfSetCase("HTTP compacts a small incomplete header from a large input allocation");
    setup(websocket);
    sbuf_t *input               = allocateInput(kBodyBytes);
    sbufGetMutablePtr(input)[0] = websocket ? 0x82 : '4';
    sbufSetLength(input, 1);
    httpReceive(f.http, f.line, input);
    requireBounded();
    twfRequireEqualU32(f.delivered, 0, "HTTP forwarded incomplete metadata as a body");
    if (websocket)
    {
        uint8_t  header[14];
        uint32_t length = frameHeader(header, kDeclaredBytes, 2);
        receiveBytes(header + 1, length - 1);
    }
    else
        receiveBytes("0000000\r\n", 9);
    receivePattern(0, 1);
    twfRequireEqualU32(f.delivered, 1, "HTTP compaction lost the incomplete header prefix");
    teardown();
}

static void caseNestedOverflow(bool websocket, unsigned mode)
{
    twfSetCase("HTTP nested input rejects bytes, charge or entry overflow and closes one line");
    setup(websocket);
    startBody();
    f.overflow = mode;
    receivePattern(0, kOuterBytes);
    twfRequireEqualU32(f.calls, 1, "HTTP continued output after nested admission overflow");
    twfRequireEqualU32(f.max_depth, 1, "nested admission overflow recursively delivered output");
    twfRequireLineStateZeroed(f.line, f.http, "HTTP nested overflow retained its line state");
    teardown();
}

static void prepareHttp2(void)
{
    setup(false);
    http_tstate_t *ts = tunnelGetState(f.http);
    twfRequire(nghttp2_session_callbacks_new(&ts->cbs) == 0, "HTTP/2 callbacks allocation failed");
#ifdef TEST_HTTP_CLIENT
    ts->method = (char *) "POST";
    ts->path   = (char *) "/";
    ts->scheme = (char *) "http";
    ts->host   = (char *) "unit.test";
    twfRequire(httpclientTransportEnsureHttp2Session(f.http, f.line, state()), "HTTP/2 client preparation failed");
    /* Empty SETTINGS, then HPACK's indexed :status 200 on the open stream. */
    const uint8_t response[] = {0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88};
    receiveBytes(response, sizeof(response));
    twfRequire(state()->h2_headers_received, "HTTP/2 response stream did not open");
#else
    ts->status_code = 200;
    twfRequire(httpserverTransportPrepareHttp2Session(f.http, f.line, state()), "HTTP/2 server preparation failed");
    state()->runtime_proto               = kHttpServerRuntimeHttp2;
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_session           *peer      = NULL;
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "HTTP/2 peer callbacks allocation failed");
    twfRequire(nghttp2_session_client_new(&peer, callbacks, NULL) == 0, "HTTP/2 peer creation failed");
    nghttp2_session_callbacks_del(callbacks);
    twfRequire(nghttp2_submit_settings(peer, NGHTTP2_FLAG_NONE, NULL, 0) == 0, "HTTP/2 peer SETTINGS failed");
    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
    };
    twfRequire(nghttp2_submit_headers(peer, NGHTTP2_FLAG_END_HEADERS, -1, NULL, headers, ARRAY_SIZE(headers), NULL) ==
                   1,
               "HTTP/2 peer request submission failed");
    for (;;)
    {
        const uint8_t *wire   = NULL;
        nghttp2_ssize  length = nghttp2_session_mem_send2(peer, &wire);
        twfRequire(length >= 0, "HTTP/2 peer serialization failed");
        if (length == 0)
            break;
        receiveBytes(wire, (uint32_t) length);
    }
    nghttp2_session_del(peer);
    twfRequire(state()->h2_stream_id == 1 && ! state()->h2_request_rejected, "HTTP/2 request stream did not open");
#endif
    /* The handshake itself has independent integration coverage. Establish its
     * accepted state here to exercise the actual nghttp2 DATA receive callback. */
    ts->websocket_enabled     = true;
    state()->websocket_active = true;
    f.websocket               = true;
    twfRequire(nghttp2_session_set_local_window_size(state()->session, 0, 0, 8 * 1024 * 1024) == 0,
               "HTTP/2 connection receive window setup failed");
    twfRequire(nghttp2_session_set_local_window_size(state()->session, 0, 1, 8 * 1024 * 1024) == 0,
               "HTTP/2 stream receive window setup failed");
}

static void caseHttp2WebSocket(bool coalesced, bool close)
{
    twfSetCase("HTTP/2 WebSocket DATA streams a 1 GiB frame with bounded retained storage");
    prepareHttp2();
    f.close = close;
    uint8_t        ws_header[14];
    uint32_t       ws_length      = frameHeader(ws_header, kDeclaredBytes, 2);
    const uint32_t payload_length = ws_length + kBodyBytes;
    const uint32_t frames         = (payload_length + 16383U) / 16384U;
    sbuf_t        *input          = allocateInput(payload_length + 9U * frames);
    uint8_t       *wire           = sbufGetMutablePtr(input);
    uint32_t       consumed       = 0;
    uint32_t       written        = 0;
    while (consumed < payload_length)
    {
        uint32_t length = min(16384U, payload_length - consumed);
        wire[written++] = (uint8_t) (length >> 16);
        wire[written++] = (uint8_t) (length >> 8);
        wire[written++] = (uint8_t) length;
        wire[written++] = NGHTTP2_DATA;
        wire[written++] = 0;
        memorySet(wire + written, 0, 3);
        written += 3;
        wire[written++] = 1;
        for (uint32_t i = 0; i < length; ++i)
        {
            uint32_t position = consumed + i;
            if (position < ws_length)
                wire[written++] = ws_header[position];
            else
            {
                uint32_t body_position = position - ws_length;
                uint8_t  byte          = pattern(body_position);
#ifndef TEST_HTTP_CLIENT
                byte ^= mask[body_position & 3U];
#endif
                wire[written++] = byte;
            }
        }
        consumed += length;
    }
    twfRequireEqualU32(written, sbufGetLength(input), "HTTP/2 fixture wire length mismatch");
    if (coalesced)
        httpReceive(f.http, f.line, input);
    else
    {
        uint32_t offset = 0;
        while (offset < written)
        {
            uint32_t length = min(16393U, written - offset);
            receiveBytes(wire + offset, length);
            offset += length;
            twfRequire(f.delivered != 0, "HTTP/2 WebSocket waited for a complete body");
            requireBounded();
        }
        lineReuseBuffer(f.line, input);
    }
    if (close)
    {
        twfRequireEqualU32(f.calls, 1, "HTTP/2 WebSocket continued output after reentrant Finish");
        twfRequireLineStateZeroed(f.line, f.http, "HTTP/2 WebSocket retained state after reentrant Finish");
    }
    else
    {
        twfRequireEqualU32(f.delivered, kBodyBytes, "HTTP/2 WebSocket body was truncated or retained");
        requireBounded();
    }
    teardown();
}

int main(void)
{
    for (unsigned websocket = 0; websocket < 2; ++websocket)
    {
        for (unsigned coalesced = 0; coalesced < 2; ++coalesced)
            caseLargeBody(websocket, coalesced);
        caseNestedBody(websocket, false);
        caseNestedBody(websocket, true);
        caseSmallRetainedTail(websocket);
        for (unsigned mode = 1; mode <= 3; ++mode)
            caseNestedOverflow(websocket, mode);
    }
    for (unsigned trailer = 0; trailer < 2; ++trailer)
        for (unsigned overflow = 0; overflow < 2; ++overflow)
            for (unsigned terminated = 0; terminated < 2; ++terminated)
                caseMetadataLimit(trailer, overflow, terminated);
    caseInvalidWebSocketHeader();
    caseHttp2WebSocket(false, false);
    caseHttp2WebSocket(true, false);
    caseHttp2WebSocket(true, true);
    return 0;
}

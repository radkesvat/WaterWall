/*
 * Covers: httpserver chunked terminator; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes,
 * caseBodylessRequestStaysOpenForResponse, caseHeaderLimitExcludesDeliveredBody,
 * caseCustomUpgradeBypassesAfterReentrantTails, caseChunkedSuffixTailroom,
 * HTTP/1 and HTTP/2 method mismatch diagnostics with safe protocol names.
 * Checks: Assertion labels include: HttpServer destroyed its state at HTTP body end; HttpServer completed a
 * partial trailer block; HttpServer did not forward exactly one body chunk; HttpServer forwarded the
 * wrong body length
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.httpserver_chunked_terminator_unit
 */
/*
 * A terminating HTTP/1.1 chunk can arrive separately from the empty trailer
 * line. The parser must resume trailer scanning without spinning, and body end
 * in single mode must leave the Waterwall line open.
 */
#include "HttpServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

enum
{
    kTestLargeBufferSize = 4096
};

static char     method_log[1024];
static unsigned method_log_count;

static void captureMethodLog(int level, const char *text, int length)
{
    if (level != LOG_LEVEL_WARN || text == NULL || length <= 0 || strstr(text, "method mismatch") == NULL)
        return;
    const size_t copied = min((size_t) length, sizeof(method_log) - 1);
    memoryCopy(method_log, text, copied);
    method_log[copied] = '\0';
    ++method_log_count;
}

typedef struct httpserver_chunked_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
    bool             retired;
} httpserver_chunked_fixture_t;

static void fixtureSetup(httpserver_chunked_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");

    fixture->prev->chain_index = 0;
    fixture->http->chain_index = 1;
    fixture->next->chain_index = 2;
    fixture->http->fnInitU     = httpserverTunnelUpStreamInit;
    fixture->http->fnPayloadU  = httpserverTunnelUpStreamPayload;
    fixture->http->fnPayloadD  = httpserverTunnelDownStreamPayload;
    fixture->http->fnFinU      = httpserverTunnelUpStreamFinish;
    fixture->http->fnFinD      = httpserverTunnelDownStreamFinish;
    fixture->http->fnPauseU    = httpserverTunnelUpStreamPause;
    fixture->http->fnResumeU   = httpserverTunnelUpStreamResume;
    fixture->http->fnPauseD    = httpserverTunnelDownStreamPause;
    fixture->http->fnResumeD   = httpserverTunnelDownStreamResume;

    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpserverLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto     = kHttpServerRuntimeHttp1;
    ls->h1_headers_parsed = true;
    ls->h1_body_mode      = kHttpServerH1BodyChunked;
}

static void fixtureFeed(httpserver_chunked_fixture_t *fixture, const char *bytes)
{
    const uint32_t len = (uint32_t) strlen(bytes);
    sbuf_t        *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, len);
    sbufWrite(buf, bytes, len);
    tunnelUpStreamPayload(fixture->http, fixture->line, buf);
}

static void fixtureTeardown(httpserver_chunked_fixture_t *fixture)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    if (fixture->retired)
    {
        twfRequireLineStateZeroed(fixture->line, fixture->http, "HttpServer retained retired state");
    }
    else
    {
        twfRequire(ls->tunnel == fixture->http, "HttpServer destroyed its state at HTTP body end");
        httpserverLinestateDestroy(ls);
    }
    twfRequireNoLeakedBuffers();

    twfLineDestroy(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes(void)
{
    twfSetCase("HttpServer chunked terminator split across payloads");

    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);

    fixtureFeed(&fixture, "5\r\nhello\r\n");
    fixtureFeed(&fixture, "0\r\n");

    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(! ls->h1_request_finished, "HttpServer completed a partial trailer block");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "HttpServer did not forward exactly one body chunk");
    twfRequireEqualU32(fixture.trace.next_payload_bytes, 5, "HttpServer forwarded the wrong body length");

    fixtureFeed(&fixture, "\r\n");

    twfRequire(ls->h1_request_finished, "HttpServer did not complete the chunked request");
    twfRequire(lineIsAlive(fixture.line), "HttpServer closed a single-mode line at request body end");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpServer reflected request body end into Finish");
    twfRequire(bufferstreamGetLength(&ls->in_stream) == 0, "HttpServer retained chunk trailer bytes");

    fixtureFeed(&fixture, "x");

    twfRequire(bufferstreamGetLength(&ls->in_stream) == 0, "HttpServer buffered bytes after request completion");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "HttpServer forwarded trailing request bytes");

    fixtureTeardown(&fixture);
}

static void caseBodylessRequestStaysOpenForResponse(void)
{
    twfSetCase("HttpServer bodyless request remains open for response");

    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);

    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    httpserverLinestateDestroy(ls);
    httpserverLinestateInitialize(ls, fixture.http, fixture.line);
    ls->runtime_proto = kHttpServerRuntimeHttp1;

    httpserver_tstate_t *ts = tunnelGetState(fixture.http);
    ts->status_code         = 200;

    fixtureFeed(&fixture, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");

    twfRequire(ls->h1_request_finished, "HttpServer did not record the bodyless request end");
    twfRequire(lineIsAlive(fixture.line), "HttpServer closed a bodyless single-mode request");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpServer reflected a bodyless request into Finish");

    sbuf_t *response = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(response, 2);
    sbufWrite(response, "ok", 2);
    httpserverTunnelDownStreamPayload(fixture.http, fixture.line, response);

    twfRequire(fixture.trace.prev_payload > 0, "HttpServer did not emit a response for a bodyless request");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HttpServer closed while emitting the response");

    fixtureTeardown(&fixture);
}

static void caseHeaderLimitExcludesDeliveredBody(unsigned mode)
{
    twfSetCase("HttpServer checks header size separately from a large delivered body");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_lstate_t *ls      = lineGetState(fixture.line, fixture.http);
    ls->h1_headers_parsed        = false;
    const char    *header        = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2097152\r\n\r\n";
    const uint32_t header_length = (uint32_t) stringLength(header);
    const uint32_t length        = LARGE_BUFFER_SIZE_RAM_HIGH;
    sbuf_t        *input         = bufferpoolTryGetBestFit(fixture.env.pool, length, 0);
    memorySet(sbufGetMutablePtr(input), 'b', length);
    sbufSetLength(input, length);
    if (mode == 0)
        memoryCopy(sbufGetMutablePtr(input), header, header_length);
    else if (mode == 1)
        memoryCopy((uint8_t *) sbufGetMutablePtr(input) + kHttpServerMaxHeaderBytes, "\r\n\r\n", 4);
    bufferstreamPush(&ls->in_stream, input);
    bool accepted = httpserverTransportHandleHttp1RequestHeaderPhase(fixture.http, fixture.line, ls);
    twfRequire(accepted == (mode == 0), "HTTP header admission used the complete delivery length");
    if (accepted)
    {
        twfRequire(ls->h1_headers_parsed, "valid coalesced HTTP headers were not parsed");
        twfRequire(bufferstreamGetLength(&ls->in_stream) == length - header_length,
                   "header parsing lost or consumed the following body");
        twfRequire(bufferstreamViewByteAt(&ls->in_stream, length - header_length - 1) == 'b',
                   "header parsing changed the trailing body");
    }
    fixtureTeardown(&fixture);
}

static void caseMethodMismatchDiagnostics(bool http2, const char *method, const char *expected_label)
{
    twfSetCase(http2 ? "HttpServer HTTP/2 method rejection diagnostics"
                     : "HttpServer HTTP/1 method rejection diagnostics");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_tstate_t *ts                = tunnelGetState(fixture.http);
    httpserver_lstate_t *ls                = lineGetState(fixture.line, fixture.http);
    char                 expected_method[] = "GET";
    ts->expected_method                    = expected_method;
    method_log_count                       = 0;
    method_log[0]                          = '\0';

    if (http2)
    {
        twfRequire(nghttp2_session_callbacks_new(&ts->cbs) == 0, "server callbacks allocation failed");
        twfRequire(httpserverTransportPrepareHttp2Session(fixture.http, fixture.line, ls),
                   "HTTP/2 session preparation failed");
        nghttp2_session_callbacks *callbacks = NULL;
        nghttp2_session           *peer      = NULL;
        twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "peer callbacks allocation failed");
        twfRequire(nghttp2_session_client_new(&peer, callbacks, NULL) == 0, "peer session allocation failed");
        nghttp2_session_callbacks_del(callbacks);
        twfRequire(nghttp2_submit_settings(peer, NGHTTP2_FLAG_NONE, NULL, 0) == 0, "peer SETTINGS failed");
        nghttp2_nv headers[] = {
            {(uint8_t *) ":method", (uint8_t *) method, 7, strlen(method), NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *) ":path", (uint8_t *) "/", 5, 1, NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
        };
        twfRequire(nghttp2_submit_request2(peer, NULL, headers, ARRAY_SIZE(headers), NULL, NULL) == 1,
                   "peer request submission failed");
        for (;;)
        {
            const uint8_t *wire   = NULL;
            nghttp2_ssize  length = nghttp2_session_mem_send2(peer, &wire);
            twfRequire(length >= 0, "peer request serialization failed");
            if (length == 0)
                break;
            twfRequire(nghttp2_session_mem_recv2(ls->session, wire, (size_t) length) == length,
                       "server could not process the HTTP/2 request");
        }
        twfRequire(ls->h2_request_rejected, "HTTP/2 method mismatch was accepted");
        nghttp2_session_del(peer);
        nghttp2_session_callbacks_del(ts->cbs);
        ts->cbs = NULL;
    }
    else
    {
        char request[256];
        int  length = snprintf(request, sizeof(request), "%s / HTTP/1.1\r\nHost: unit.test\r\n\r\n", method);
        twfRequire(length > 0 && (size_t) length < sizeof(request), "HTTP/1 fixture request overflow");
        ls->h1_headers_parsed = false;
        sbuf_t *input         = bufferpoolGetLargeBuffer(fixture.env.pool);
        sbufSetLength(input, (size_t) length);
        sbufWrite(input, request, (size_t) length);
        bufferstreamPush(&ls->in_stream, input);
        twfRequire(! httpserverTransportHandleHttp1RequestHeaderPhase(fixture.http, fixture.line, ls),
                   "HTTP/1 method mismatch was accepted");
    }

    char expected[96];
    snprintf(expected, sizeof(expected), "expected=GET got=%s", expected_label);
    twfRequire(method_log_count == 1 && strstr(method_log, expected) != NULL,
               "method rejection omitted the safe expected/received protocol names");
    snprintf(expected, sizeof(expected), "got_bytes=%zu", strlen(method));
    twfRequire(strstr(method_log, expected) != NULL, "method rejection omitted the observed token length");
    if (strcmp(expected_label, "<unknown>") == 0)
        twfRequire(strstr(method_log, method) == NULL, "method rejection exposed an unknown peer token");
    twfRequire(lineIsAlive(fixture.line), "method validation destroyed the borrowed line");
    fixtureTeardown(&fixture);
}

static httpserver_chunked_fixture_t *upgrade_fixture;
static char                          upgrade_up[16], upgrade_down[256];
static size_t                        upgrade_up_len, upgrade_down_len;
static bool                          upgrade_injected;
static unsigned                      upgrade_stop;

static sbuf_t *upgradeBuffer(line_t *line, const char *text)
{
    sbuf_t        *buf    = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    const uint32_t length = (uint32_t) strlen(text);
    sbufSetLength(buf, length);
    sbufWrite(buf, text, length);
    return buf;
}

static void upgradeRequestSink(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    twfRequire(upgrade_up_len + sbufGetLength(buf) < sizeof(upgrade_up), "raw request capture overflow");
    memoryCopy(upgrade_up + upgrade_up_len, sbufGetRawPtr(buf), sbufGetLength(buf));
    upgrade_up_len += sbufGetLength(buf);
    lineReuseBuffer(line, buf);
    if (upgrade_up_len == 1)
    {
        if (upgrade_stop == 1)
        {
            tunnelDownStreamFin(next->prev, line);
            return;
        }
        fixtureFeed(upgrade_fixture, "C");
    }
}

static void upgradeResponseSink(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    const bool initial     = ! upgrade_injected;
    const bool queued_body = sbufGetLength(buf) == 1 && *(const char *) sbufGetRawPtr(buf) == 'Q';
    twfRequire(upgrade_down_len + sbufGetLength(buf) < sizeof(upgrade_down), "raw response capture overflow");
    memoryCopy(upgrade_down + upgrade_down_len, sbufGetRawPtr(buf), sbufGetLength(buf));
    upgrade_down_len += sbufGetLength(buf);
    lineReuseBuffer(line, buf);
    if (initial)
    {
        upgrade_injected = true;
        twfRequire(tunnelIsActiveForLine(prev->next, line), "HttpServer bypassed before the 101 handoff settled");
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamPause(prev->next, line);
            tunnelDownStreamPause(prev->next, line);
        }
        if (upgrade_stop >= 2)
        {
            for (size_t charge = 0; charge <= kHttpServerUpgradeQueueChargeLimit;)
            {
                sbuf_t *nested = upgradeBuffer(line, "x");
                charge += sbufGetQueueCharge(nested);
                if (upgrade_stop == 2)
                    tunnelUpStreamPayload(prev->next, line, nested);
                else
                    tunnelDownStreamPayload(prev->next, line, nested);
                if (((httpserver_lstate_t *) lineGetState(line, prev->next))->line == NULL)
                    break;
            }
            return;
        }
        fixtureFeed(upgrade_fixture, "B");
        tunnelDownStreamPayload(prev->next, line, upgradeBuffer(line, "R"));
    }
    else if (queued_body && upgrade_stop == 0)
    {
        fixtureFeed(upgrade_fixture, "D");
    }
}

static void upgradeDuringNextInit(tunnel_t *next, line_t *line)
{
    twfNextInit(next, line);
    tunnelDownStreamPayload(next->prev, line, upgradeBuffer(line, "Q"));
    fixtureFeed(upgrade_fixture,
                "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: raw-test\r\n\r\nA");
    twfRequireLineStateZeroed(line, next->prev, "raw transition left state after nested next Init");
}

static void caseCustomUpgradeBypassesAfterReentrantTails(unsigned stop)
{
    twfSetCase("HttpServer custom upgrade settles nested tails before permanent bypass");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserverLinestateDestroy(lineGetState(fixture.line, fixture.http));
    fixture.retired = true;
    upgrade_fixture = &fixture;
    upgrade_up_len = upgrade_down_len = 0;
    memoryZero(upgrade_up, sizeof(upgrade_up));
    memoryZero(upgrade_down, sizeof(upgrade_down));
    upgrade_injected         = false;
    upgrade_stop             = stop;
    fixture.prev->fnPayloadD = upgradeResponseSink;
    fixture.next->fnPayloadU = upgradeRequestSink;
    fixture.next->fnInitU    = upgradeDuringNextInit;
    httpserver_tstate_t *ts  = tunnelGetState(fixture.http);
    ts->version_mode         = kHttpServerVersionModeBoth;
    ts->enable_upgrade       = true;
    char upgrade_protocol[]  = "raw-test";
    ts->upgrade_protocol     = upgrade_protocol;
    tunnelUpStreamInit(fixture.http, fixture.line);
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed a borrowed line");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "suspended Init revived retired HTTP state");
    if (stop == 0)
    {
        twfRequire(! tunnelIsActiveForLine(fixture.http, fixture.line), "completed raw upgrade stayed active");
        twfRequireEqualText(upgrade_up, "ABCD", "raw upgrade reordered nested request data");
        twfRequireEqualText(upgrade_down,
                            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw-test\r\n\r\nQR",
                            "raw response overtook 101 or queued data");
        twfRequireEqualText(fixture.trace.seq, "IUuUu", "active HTTP flow signals were not repeatable");
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamResume(fixture.http, fixture.line);
            tunnelDownStreamResume(fixture.http, fixture.line);
        }
        fixtureFeed(&fixture, "E");
        tunnelDownStreamPayload(fixture.http, fixture.line, upgradeBuffer(fixture.line, "S"));
        twfRequireEqualText(upgrade_up, "ABCDE", "bypassed request did not reach next");
        tunnelUpStreamFin(fixture.http, fixture.line);
        twfRequireEqualU32(fixture.trace.next_finish, 1, "bypassed Finish did not reach next");
    }
    else
    {
        twfRequire(tunnelIsActiveForLine(fixture.http, fixture.line), "failed upgrade incorrectly bypassed");
        twfRequireEqualU32(fixture.trace.prev_finish, 1, "failed upgrade did not finish previous direction");
        twfRequireEqualU32(fixture.trace.next_finish, stop == 1 ? 0 : 1, "failed upgrade violated Finish direction");
    }
    fixtureTeardown(&fixture);
}

static sbuf_t *pendingBuffer(line_t *line, uint32_t capacity, uint32_t length, char value)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(line), capacity, 0);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), value, length);
    return buf;
}

static void caseEmptyResponsePayloadDoesNotTerminate(bool queued)
{
    twfSetCase("HttpServer empty response payload is not a final chunk");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t wire[128]              = {0};
    fixture.trace.capture          = wire;
    fixture.trace.capture_capacity = sizeof(wire) - 1;
    httpserver_lstate_t *ls        = lineGetState(fixture.line, fixture.http);
    ls->h1_response_headers_sent   = true;
    ls->h1_headers_parsed          = ! queued;
    const uint32_t lengths[]       = {1, 0, 1};
    const char     values[]        = {'A', 'x', 'B'};
    for (unsigned i = 0; i < ARRAY_SIZE(lengths); ++i)
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, lengths[i], values[i]));
    if (queued)
    {
        twfRequire(fixture.trace.capture_len == 0, "waiting HTTP response leaked body bytes");
        ls->h1_headers_parsed = true;
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, 0, 'x'));
    }
    twfRequireEqualText((char *) wire, "1\r\nA\r\n1\r\nB\r\n", "empty input ended the response");
    bufferbudgetAssertEmpty(&ls->pending_down_budget);
    tunnelDownStreamFin(fixture.http, fixture.line);
    fixture.retired = true;
    twfRequireEqualText((char *) wire, "1\r\nA\r\n1\r\nB\r\n0\r\n\r\n", "Finish did not emit one final chunk");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "response Finish was not forwarded");
    fixtureTeardown(&fixture);
}

static sbuf_t *chunked_payload;
static size_t  chunked_payload_capacity, chunked_payload_headroom;
static bool    chunked_payload_seen, chunked_close_after_payload;

static void chunkedPayloadSink(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    const bool payload = buf == chunked_payload;
    if (payload)
    {
        twfRequire(! chunked_payload_seen, "HTTP chunk payload was delivered twice");
        chunked_payload_seen = true;
        chunked_payload      = NULL;
        twfRequire(sbufGetTotalCapacity(buf) == chunked_payload_capacity,
                   "HTTP chunk suffix changed the payload allocation capacity");
        twfRequire(sbufGetHeadroom(buf) == chunked_payload_headroom,
                   "HTTP chunk suffix changed the expected payload cursor");
        twfRequire(sbufGetRecalculateChecksum(buf), "HTTP chunk suffix lost the payload checksum request");
    }
    twfPrevPayload(prev, line, buf);
    if (payload && chunked_close_after_payload)
        tunnelUpStreamFin(prev->next, line);
}

static void caseChunkedSuffixTailroom(size_t tailroom, bool shifted, bool separate_prefix, bool close_after_payload)
{
    twfSetCase("HttpServer chunk suffix preserves exact tailroom and callback closure");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t wire[kTestLargeBufferSize + 32] = {0};
    fixture.trace.capture                   = wire;
    fixture.trace.capture_capacity          = sizeof(wire) - 1;
    fixture.prev->fnPayloadD                = chunkedPayloadSink;

    sbuf_t *payload = bufferpoolGetBestFit(fixture.env.pool, 64, separate_prefix ? 0 : 32);
    if (shifted)
    {
        sbufWrite(payload, "discard", 7);
        sbufSetLength(payload, 7);
        sbufShiftRight(payload, 7);
    }
    const size_t payload_length = sbufGetWritableCapacity(payload) - tailroom;
    memorySet(sbufGetMutablePtr(payload), 'B', payload_length);
    sbufSetLength(payload, payload_length);
    sbufSetRecalculateChecksum(payload, true);
    twfRequire(sbufGetTailroom(payload) == tailroom, "HTTP chunk fixture did not force exact actual tailroom");

    char prefix[32];
    int  prefix_length = snprintf(prefix, sizeof(prefix), "%x\r\n", (unsigned) payload_length);
    twfRequire(prefix_length > 0 && (size_t) prefix_length < sizeof(prefix), "HTTP chunk fixture prefix overflow");
    twfRequire((sbufGetHeadroom(payload) < (size_t) prefix_length) == separate_prefix,
               "HTTP chunk fixture did not force the selected prefix path");

    chunked_payload                = payload;
    chunked_payload_capacity       = sbufGetTotalCapacity(payload);
    chunked_payload_headroom       = sbufGetHeadroom(payload) - (separate_prefix ? 0 : (size_t) prefix_length);
    chunked_payload_seen           = false;
    chunked_close_after_payload    = close_after_payload;
    const uint32_t recycled_before = twfRecycleCount();
    const bool     sent            = httpserverTransportSendHttp1ChunkedPayload(fixture.http, fixture.line, payload);
    fixture.retired                = close_after_payload;
    twfRequire(sent == ! close_after_payload, "HTTP chunk send ignored downstream callback closure");
    twfRequire(chunked_payload_seen && chunked_payload == NULL, "HTTP chunk replaced or did not transfer its payload");

    uint8_t expected[kTestLargeBufferSize + 32] = {0};
    size_t  expected_length                     = (size_t) prefix_length + payload_length;
    memoryCopy(expected, prefix, (size_t) prefix_length);
    memorySet(expected + prefix_length, 'B', payload_length);
    if (! close_after_payload)
    {
        memoryCopy(expected + expected_length, "\r\n", 2);
        expected_length += 2;
    }
    twfRequire(fixture.trace.capture_len == expected_length && memoryEqual(wire, expected, expected_length),
               "HTTP chunk suffix changed wire bytes or escaped after callback closure");
    const uint32_t callbacks = 1 + (separate_prefix ? 1 : 0) + (! close_after_payload && tailroom < 2 ? 1 : 0);
    twfRequireEqualU32(fixture.trace.prev_payload, callbacks, "HTTP chunk used the wrong suffix fallback");
    twfRequireEqualU32(twfRecycleCount() - recycled_before, callbacks, "HTTP chunk buffers did not settle once");
    twfRequireEqualU32(fixture.trace.next_finish,
                       close_after_payload ? 1 : 0,
                       "HTTP chunk callback closure did not finish next exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HTTP chunk reflected Finish toward the closed downstream side");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed its borrowed chunk transport line");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "HTTP chunk callback guard leaked a line reference");
    fixtureTeardown(&fixture);
}

static bool submitWaitingPayload(httpserver_chunked_fixture_t *fixture, unsigned mode, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    if (mode == 4)
    {
        if (! httpserverTransportSendHttp2DataFrame(fixture->http, fixture->line, ls, buf, false))
            httpserverTransportCloseBothDirections(fixture->http, fixture->line, ls);
    }
    else
        tunnelDownStreamPayload(fixture->http, fixture->line, buf);
    return ls->line != NULL;
}

static void caseWaitingResponseLimit(unsigned mode, bool charge_limit)
{
    twfSetCase("HttpServer readiness queue enforces byte and allocation limits");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    httpserver_tstate_t *ts = tunnelGetState(fixture.http);
    ls->h1_headers_parsed   = false;
    if (mode == 1)
        ls->runtime_proto = kHttpServerRuntimeUnknown;
    else if (mode == 2)
        ts->websocket_enabled = true;
    else if (mode >= 3)
        ls->runtime_proto = kHttpServerRuntimeHttp2;
    const uint32_t capacity =
        charge_limit ? kHttpServerPendingCharge - sizeof(sbuf_t) - kSbufAllocationAlignment : kHttpServerPendingBytes;
    const uint32_t length = charge_limit ? 1 : capacity;
    twfRequire(submitWaitingPayload(&fixture, mode, pendingBuffer(fixture.line, capacity, length, 'A')),
               "exact waiting limit was refused");
    const buffer_budget_cost_t used = bufferbudgetGetUsage(&ls->pending_down_budget);
    twfRequire(used.bytes == length, "waiting bytes were not charged");
    if (charge_limit)
        twfRequire(used.charge == kHttpServerPendingCharge, "test did not reach the exact allocation limit");
    twfRequire(fixture.trace.prev_payload == 0, "unready response was emitted");
    twfRequire(! submitWaitingPayload(&fixture, mode, pendingBuffer(fixture.line, 1, 1, 'B')),
               "waiting response overflow was accepted");
    fixture.retired = true;
    twfRequireEqualText(fixture.trace.seq, "Ff", "overflow did not close both directions in order");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed a borrowed line on overflow");
    fixtureTeardown(&fixture);
}

static unsigned pending_drain_mode;
static bool     pending_header_seen, pending_body_seen;

static void pendingDrainSink(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    tunnel_t            *http   = prev->next;
    httpserver_lstate_t *ls     = lineGetState(line, http);
    bool                 body_a = sbufGetLength(buf) == 3 && memcmp(sbufGetRawPtr(buf), "A\r\n", 3) == 0;
    twfPrevPayload(prev, line, buf);
    if (! pending_header_seen)
    {
        pending_header_seen = true;
        twfRequire(ls->pending_down_draining, "drain guard was not published before response headers");
        twfRequire(bufferbudgetGetUsage(&ls->pending_down_budget).bytes == 2,
                   "oldest pending response lost its charge across the header callback");
        if (pending_drain_mode == 1)
        {
            tunnelDownStreamPayload(
                http, line, pendingBuffer(line, kHttpServerPendingBytes, kHttpServerPendingBytes, 'X'));
            return;
        }
        if (pending_drain_mode == 2)
        {
            tunnelUpStreamFin(http, line);
            return;
        }
        tunnelDownStreamPayload(http, line, pendingBuffer(line, 1, 1, 'C'));
        twfRequire(httpserverTransportFlushPendingDown(http, line, ls), "recursive drain failed");
    }
    else if (body_a && ! pending_body_seen)
    {
        pending_body_seen = true;
        twfRequire(bufferbudgetGetUsage(&ls->pending_down_budget).bytes == 2,
                   "handed-off payload retained its queue charge");
        if (pending_drain_mode == 3)
        {
            tunnelUpStreamFin(http, line);
            return;
        }
        tunnelDownStreamPayload(http, line, pendingBuffer(line, 1, 1, 'D'));
    }
}

static void casePendingDrainReentry(unsigned mode)
{
    twfSetCase("HttpServer response drain preserves FIFO, bounds and callback lifetime");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t wire[1024]             = {0};
    fixture.trace.capture          = wire;
    fixture.trace.capture_capacity = sizeof(wire) - 1;
    httpserver_lstate_t *ls        = lineGetState(fixture.line, fixture.http);
    httpserver_tstate_t *ts        = tunnelGetState(fixture.http);
    ts->status_code                = 200;
    ls->h1_headers_parsed          = false;
    for (char value = 'A'; value <= 'B'; ++value)
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, 1, value));
    twfRequire(fixture.trace.prev_payload == 0, "queued payload bypassed request readiness");
    ls->h1_headers_parsed    = true;
    fixture.prev->fnPayloadD = pendingDrainSink;
    pending_drain_mode       = mode;
    pending_header_seen = pending_body_seen = false;
    bool drained                            = httpserverTransportFlushPendingDown(fixture.http, fixture.line, ls);
    twfRequire(drained == (mode == 0), "response drain reported the wrong callback result");
    if (mode == 0)
    {
        const char *body = strstr((char *) wire, "\r\n\r\n");
        twfRequire(body != NULL, "response header terminator missing");
        twfRequireEqualText(
            body + 4, "1\r\nA\r\n1\r\nB\r\n1\r\nC\r\n1\r\nD\r\n", "nested response overtook the pending FIFO");
        bufferbudgetAssertEmpty(&ls->pending_down_budget);
        twfRequire(! ls->pending_down_draining, "response drain guard remained set");
    }
    else
    {
        fixture.retired = true;
        twfRequireEqualU32(fixture.trace.next_finish, 1, "closing header callback did not finish next");
        twfRequireEqualU32(fixture.trace.prev_finish, mode == 1 ? 1 : 0, "closing header callback reflected Finish");
        twfRequireEqualU32(fixture.trace.prev_payload, mode == 3 ? 3 : 1, "body escaped after callback closure");
    }
    fixtureTeardown(&fixture);
}

int main(void)
{
    logger_t *logger = createNetworkLogger(NULL, false);
    twfRequire(logger != NULL, "network logger setup failed");
    loggerSetHandler(logger, captureMethodLog);
    for (unsigned http2 = 0; http2 < 2; ++http2)
    {
        caseMethodMismatchDiagnostics(http2 != 0, "PUT", "PUT");
        /* Fit the HTTP/2 parser's 15-byte method field so this tests redaction, not truncation. */
        caseMethodMismatchDiagnostics(http2 != 0, "PRIVATE-123", "<unknown>");
    }
    caseChunkedSuffixTailroom(2, false, false, false);
    caseChunkedSuffixTailroom(1, true, false, false);
    caseChunkedSuffixTailroom(0, false, false, false);
    caseChunkedSuffixTailroom(0, false, true, false);
    caseChunkedSuffixTailroom(1, true, false, true);
    caseChunkedSuffixTailroom(0, false, true, true);
    for (unsigned mode = 0; mode < 4; ++mode)
        casePendingDrainReentry(mode);
    for (unsigned mode = 0; mode < 5; ++mode)
        for (unsigned charge_limit = 0; charge_limit < 2; ++charge_limit)
            caseWaitingResponseLimit(mode, charge_limit != 0);
    caseEmptyResponsePayloadDoesNotTerminate(false);
    caseEmptyResponsePayloadDoesNotTerminate(true);
    for (unsigned stop = 0; stop < 4; ++stop)
        caseCustomUpgradeBypassesAfterReentrantTails(stop);
    for (unsigned mode = 0; mode < 3; ++mode)
        caseHeaderLimitExcludesDeliveredBody(mode);
    caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes();
    caseBodylessRequestStaysOpenForResponse();
    networkloggerDestroy();
    return 0;
}

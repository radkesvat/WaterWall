/*
 * Covers: httpserver reentrant finish; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: Reentrant final writes, deferred carrier close/reset, later DATA and queued DATA after service Finish;
 * fixed drain deadlines, early timer wakeup, timer refusal and quiesced cleanup.
 * Checks: Assertion labels include: HttpServer sent payload after the previous direction finished;
 * HttpServer emitted a callback after re-entrant Finish; HttpServer did not stop after the first
 * payload; HttpServer did not use the forced first chunk
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.httpserver_reentrant_finish_unit
 */
/*
 * HttpServer sends the HTTP/1 final chunk while handling downstream Finish. An
 * upstream Finish may re-enter from the previous tunnel during the first
 * payload callback, so the remaining chunks and a reflected Finish must stop.
 * HTTP/2 also closes with a partially consumed provider and pending payloads,
 * both during an ordinary response send and while flushing downstream Finish.
 * A zero peer window also holds final responses across callbacks: carrier Finish
 * must cancel that wait, while request DATA must stop reaching a finished service
 * without preventing WINDOW_UPDATE from releasing the complete response.
 */
#include "HttpServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "wloop_internal.h"

enum
{
    kTestLargeBufferSize = 4096,
    kForcedSendChunkSize = 2,
    kHttp2BodySize       = 32768,
    kHttp2FrameSize      = 16384
};

static uint32_t forced_send_chunk_size = kForcedSendChunkSize;
static uint64_t now_us;
static unsigned timer_add_calls, timer_reset_calls;
static uint32_t timer_reset_ms;
static bool     refuse_timer_add, refuse_timer_reset;

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}

wtimer_t *__real_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout_ms, uint32_t repeat)
{
    ++timer_add_calls;
    return refuse_timer_add ? NULL : __real_wtimerAdd(loop, callback, timeout_ms, repeat);
}

bool __real_wtimerReset(wtimer_t *, uint32_t);
bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    ++timer_reset_calls;
    timer_reset_ms = timeout_ms;
    return ! refuse_timer_reset && __real_wtimerReset(timer, timeout_ms);
}

uint32_t __wrap_bufferpoolGetLargeBufferSize(const buffer_pool_t *pool);

uint32_t __wrap_bufferpoolGetLargeBufferSize(const buffer_pool_t *pool)
{
    discard pool;
    return forced_send_chunk_size;
}

typedef struct httpserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    master_pool_t   *context_master;
    generic_pool_t  *contexts;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
    nghttp2_session *peer;
} httpserver_fixture_t;

static void finishServerFromPrevOnFirstPayload(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(prev);
    ++trace->prev_payload;
    trace->prev_payload_bytes += sbufGetLength(buf);
    twfRecord(trace, 'p');

    httpserver_lstate_t *ls = lineGetState(line, prev->next);
    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        const uint8_t *wire = sbufGetRawPtr(buf);
        twfRequire(sbufGetLength(buf) > 9 && wire[3] == NGHTTP2_DATA,
                   "reentrant HTTP/2 close did not occur during DATA output");
        uint32_t frame_length = ((uint32_t) wire[0] << 16) | ((uint32_t) wire[1] << 8) | wire[2];
        twfRequireEqualU32(frame_length, kHttp2FrameSize, "first HTTP/2 read did not leave a partial provider");
        twfRequire(frame_length < kHttp2BodySize && ls->h2_data.active != NULL && ls->h2_data.head != NULL,
                   "HTTP/2 close did not retain both active and pending provider storage");
    }
    lineReuseBuffer(line, buf);

    twfRequireEqualU32(trace->prev_payload, 1, "HttpServer sent payload after the previous direction finished");
    httpserverTunnelUpStreamFinish(prev->next, line);
}

static void fixtureSetup(httpserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    forced_send_chunk_size = kForcedSendChunkSize;
    now_us                 = UINT64_C(1000123456);
    timer_add_calls = timer_reset_calls = 0;
    refuse_timer_add = refuse_timer_reset = false;
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);
    fixture->context_master = masterpoolCreateWithCapacity(8);
    fixture->contexts = genericpoolCreateWithDefaultAllocatorAndCapacity(fixture->context_master, sizeof(context_t), 8);
    GSTATE.shortcut_context_pools = &fixture->contexts;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");
    httpserver_tstate_t *ts    = tunnelGetState(fixture->http);
    ts->close_drain_timeout_ms = 30000;

    fixture->prev->fnPayloadD = finishServerFromPrevOnFirstPayload;
    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpserverLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto            = kHttpServerRuntimeHttp1;
    ls->h1_response_headers_sent = true;
}

static void fixtureTeardown(httpserver_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    twfRequire(wloopNTimers(fixture->env.loop) == 0, "HttpServer retained a drain timer after cleanup");
    twfLineDestroy(fixture->line);
    if (fixture->peer != NULL)
    {
        nghttp2_session_del(fixture->peer);
    }
    httpserver_tstate_t *ts = tunnelGetState(fixture->http);
    if (ts->cbs != NULL)
    {
        nghttp2_session_callbacks_del(ts->cbs);
    }
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    GSTATE.shortcut_context_pools = NULL;
    genericpoolDestroy(fixture->contexts);
    masterpoolMakeEmpty(fixture->context_master);
    masterpoolDestroy(fixture->context_master);
    twfWorkerEnvTeardown(&fixture->env);
}

static void fixtureAdvanceTo(httpserver_fixture_t *fixture, uint64_t time_us)
{
    twfRequire(time_us >= now_us, "fixture moved its monotonic clock backwards");
    now_us = time_us;
    twfRequire(wloopProcessEvents(fixture->env.loop, 0) >= 0, "HttpServer timer dispatch failed");
}

static void caseFinishDuringFirstFinalChunkStopsRemainingOutput(void)
{
    twfSetCase("HttpServer Finish during first final-chunk payload");

    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);

    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);

    twfRequireEqualText(fixture.trace.seq, "p", "HttpServer emitted a callback after re-entrant Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "HttpServer did not stop after the first payload");
    twfRequireEqualU32(
        fixture.trace.prev_payload_bytes, kForcedSendChunkSize, "HttpServer did not use the forced first chunk");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HttpServer reflected Finish toward the finished previous side");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpServer reflected Finish toward the original sender");
    twfRequire(lineIsAlive(fixture.line), "borrowed HttpServer line was destroyed");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "HttpServer line state was not destroyed exactly once");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "HttpServer leaked a line reference");

    fixtureTeardown(&fixture);
}

static void discardSetupWire(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    discard prev;
    lineReuseBuffer(line, buf);
}

static nghttp2_ssize deferRequestBody(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                      uint32_t *data_flags, nghttp2_data_source *source, void *userdata)
{
    discard session;
    discard stream_id;
    discard buf;
    discard length;
    discard data_flags;
    discard source;
    discard userdata;
    return NGHTTP2_ERR_DEFERRED;
}

static void fixturePrepareHttp2(httpserver_fixture_t *fixture, bool blocked_response)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpserver_tstate_t *ts = tunnelGetState(fixture->http);
    ts->status_code         = 200;
    twfRequire(nghttp2_session_callbacks_new(&ts->cbs) == 0, "server callbacks allocation failed");
    twfRequire(httpserverTransportPrepareHttp2Session(fixture->http, fixture->line, ls),
               "HTTP/2 session preparation failed");

    nghttp2_session_callbacks *callbacks = NULL;
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "peer callbacks allocation failed");
    twfRequire(nghttp2_session_client_new(&fixture->peer, callbacks, NULL) == 0, "peer session allocation failed");
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_settings_entry settings = {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, blocked_response ? 0 : 65535};
    twfRequire(nghttp2_submit_settings(fixture->peer, NGHTTP2_FLAG_NONE, &settings, 1) == 0, "peer SETTINGS failed");
    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_data_provider2 provider = {.read_callback = deferRequestBody};
    twfRequire(nghttp2_submit_request2(
                   fixture->peer, NULL, headers, ARRAY_SIZE(headers), blocked_response ? &provider : NULL, NULL) == 1,
               "peer request submission failed");
    for (unsigned i = 0; i < 8; ++i)
    {
        const uint8_t *wire   = NULL;
        nghttp2_ssize  length = nghttp2_session_mem_send2(fixture->peer, &wire);
        twfRequire(length >= 0, "peer request serialization failed");
        if (length == 0)
        {
            break;
        }
        twfRequire(nghttp2_session_mem_recv2(ls->session, wire, (size_t) length) == length,
                   "server rejected peer request bytes");
    }
    twfRequire(ls->h2_stream_id == 1 && ! ls->h2_request_rejected, "HTTP/2 request was not accepted");

    fixture->prev->fnPayloadD = discardSetupWire;
    twfRequire(httpserverTransportSubmitHttp2ResponseHeaders(fixture->http, fixture->line, ls, false),
               "HTTP/2 response headers failed");
    fixture->prev->fnPayloadD = finishServerFromPrevOnFirstPayload;
    forced_send_chunk_size    = kTestLargeBufferSize;
}

static sbuf_t *fixturePayload(httpserver_fixture_t *fixture, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(fixture->env.pool, length, 0);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), 0x5a, length);
    return buf;
}

static void caseHttp2FinishDuringActiveProvider(bool finishing_response)
{
    twfSetCase(finishing_response ? "HttpServer HTTP/2 partial provider close during final flush"
                                  : "HttpServer HTTP/2 partial provider close during response payload");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixturePrepareHttp2(&fixture, false);

    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    h2DataAppend(&ls->h2_data, fixturePayload(&fixture, kHttp2BodySize), false);
    h2DataAppend(&ls->h2_data, fixturePayload(&fixture, 7), false);
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    if (finishing_response)
    {
        httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    }
    else
    {
        httpserverTunnelDownStreamPayload(fixture.http, fixture.line, fixturePayload(&fixture, 3));
    }

    twfRequireEqualText(fixture.trace.seq,
                        finishing_response ? "p" : "pF",
                        "HTTP/2 output continued or Finish was reflected after reentrant close");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "HTTP/2 output continued after the first DATA fragment");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HTTP/2 reflected Finish toward the previous side");
    twfRequireEqualU32(
        fixture.trace.next_finish, finishing_response ? 0 : 1, "HTTP/2 Finish did not preserve its sender direction");
    twfRequire(lineIsAlive(fixture.line), "borrowed HTTP/2 server line was destroyed");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "HTTP/2 provider state remained after Finish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "HTTP/2 reentrant close leaked a line reference");
    twfRequireNoLeakedBuffers();
    fixtureTeardown(&fixture);
}

static void fixtureQueueBlockedResponse(httpserver_fixture_t *fixture)
{
    fixturePrepareHttp2(fixture, true);
    fixture->prev->fnPayloadD = twfPrevPayload;
    httpserverTunnelDownStreamPayload(fixture->http, fixture->line, fixturePayload(fixture, kHttp2BodySize));
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    twfRequireEqualU32((uint32_t) h2DataPendingBytes(&ls->h2_data),
                       kHttp2BodySize,
                       "zero peer window did not retain the complete response");
    twfRequireEqualU32(fixture->trace.prev_payload, 0, "response escaped a zero peer window");
}

static void caseHttp2CarrierFinishWhileResponseBlocked(void)
{
    twfSetCase("HttpServer independent carrier Finish while final response waits for WINDOW_UPDATE");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(ls->session != NULL && ls->next_finished && ! ls->h2_end_stream_emitted,
               "service Finish did not defer the window-blocked final response");
    twfRequireEqualText(fixture.trace.seq, "", "service Finish closed before draining its response");

    httpserverTunnelUpStreamFinish(fixture.http, fixture.line);

    twfRequireEqualText(fixture.trace.seq, "", "carrier Finish reflected a callback to a finished direction");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "deferred carrier Finish retained HTTP/2 state");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed its borrowed carrier line");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "deferred carrier Finish leaked a reference");
    fixtureTeardown(&fixture);
}

static void caseHttp2ResetWhileResponseBlocked(void)
{
    twfSetCase("HttpServer RST_STREAM cancels a window-blocked final response");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);

    sbuf_t              *input  = fixturePayload(&fixture, HTTP2_FRAME_HDLEN + 4);
    const http2_frame_hd header = {.length = 4, .type = kHttP2RstStream, .stream_id = 1};
    uint8_t             *wire   = sbufGetMutablePtr(input);
    http2FrameHdPack(&header, wire);
    wire[9]  = 0;
    wire[10] = 0;
    wire[11] = 0;
    wire[12] = NGHTTP2_CANCEL;
    httpserverTunnelUpStreamPayload(fixture.http, fixture.line, input);

    twfRequireEqualText(fixture.trace.seq, "f", "RST_STREAM did not close only the remaining carrier direction");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "RST_STREAM retained the impossible response drain");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed its borrowed carrier line after RST_STREAM");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "RST_STREAM leaked a line reference");
    fixtureTeardown(&fixture);
}

static void finishServiceFromNextPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(next);
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    twfRecord(trace, 'P');
    lineReuseBuffer(line, buf);
    twfRequireEqualU32(trace->next_payload, 1, "queued request DATA reached the finished service");
    httpserverTunnelDownStreamFinish(next->prev, line);
}

static void fixtureFeedData(httpserver_fixture_t *fixture, uint32_t frame_count)
{
    enum
    {
        kDataBytes = 7
    };
    sbuf_t *input = fixturePayload(fixture, frame_count * (HTTP2_FRAME_HDLEN + kDataBytes));
    for (uint32_t i = 0; i < frame_count; ++i)
    {
        const http2_frame_hd header = {.length = kDataBytes, .type = kHttP2Data, .stream_id = 1};
        http2FrameHdPack(&header, sbufGetMutablePtr(input) + i * (HTTP2_FRAME_HDLEN + kDataBytes));
    }
    httpserverTunnelUpStreamPayload(fixture->http, fixture->line, input);
}

static void fixtureIncreaseResponseWindow(httpserver_fixture_t *fixture, uint32_t bytes)
{
    sbuf_t              *input  = fixturePayload(fixture, HTTP2_FRAME_HDLEN + 4);
    const http2_frame_hd header = {.length = 4, .type = kHttP2WindowUpdate, .stream_id = 1};
    uint8_t             *wire   = sbufGetMutablePtr(input);
    http2FrameHdPack(&header, wire);
    wire[9]  = (uint8_t) (bytes >> 24);
    wire[10] = (uint8_t) (bytes >> 16);
    wire[11] = (uint8_t) (bytes >> 8);
    wire[12] = (uint8_t) bytes;
    httpserverTunnelUpStreamPayload(fixture->http, fixture->line, input);
}

static void fixtureRequireCompleteResponse(httpserver_fixture_t *fixture)
{
    uint32_t body_bytes  = 0;
    uint32_t end_streams = 0;
    uint32_t offset      = 0;
    while (offset < fixture->trace.capture_len)
    {
        twfRequire(fixture->trace.capture_len - offset >= HTTP2_FRAME_HDLEN, "truncated response frame header");
        http2_frame_hd header;
        http2FrameHdUnpack(fixture->trace.capture + offset, &header);
        offset += HTTP2_FRAME_HDLEN;
        twfRequire(header.length <= fixture->trace.capture_len - offset, "truncated response frame body");
        if (header.type == kHttP2Data)
        {
            twfRequire(header.stream_id == 1, "response used a different HTTP/2 stream");
            for (uint32_t i = 0; i < header.length; ++i)
            {
                twfRequire(fixture->trace.capture[offset + i] == 0x5a, "response bytes changed while draining");
            }
            body_bytes += header.length;
            if (header.flags & kHttP2FlagEndStream)
            {
                ++end_streams;
                twfRequireEqualU32(body_bytes, kHttp2BodySize, "END_STREAM preceded the complete response");
            }
        }
        offset += header.length;
    }
    twfRequireEqualU32(body_bytes, kHttp2BodySize, "WINDOW_UPDATE did not release the complete response");
    twfRequireEqualU32(end_streams, 1, "response did not emit exactly one END_STREAM");
}

static void caseHttp2DiscardsRequestAfterServiceFinish(bool queued_before_finish)
{
    twfSetCase(queued_before_finish ? "HttpServer queued DATA after reentrant service Finish"
                                    : "HttpServer later DATA after service Finish");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    uint8_t captured[kHttp2BodySize + 4096];
    fixture.trace.capture          = captured;
    fixture.trace.capture_capacity = sizeof(captured);
    const uint32_t initial_refc    = twfLineRefCount(fixture.line);
    if (queued_before_finish)
    {
        fixture.next->fnPayloadU = finishServiceFromNextPayload;
        fixtureFeedData(&fixture, 2);
    }
    else
    {
        httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
        fixtureFeedData(&fixture, 1);
    }
    twfRequireEqualU32(
        fixture.trace.next_payload, queued_before_finish ? 1 : 0, "request DATA reached the service after Finish");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "discarded request DATA interrupted response drain");
    fixtureIncreaseResponseWindow(&fixture, 65535);

    fixtureRequireCompleteResponse(&fixture);
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "completed response did not close the carrier exactly once");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "completed response reflected Finish toward the service");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "completed deferred response retained HTTP/2 state");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed its borrowed carrier line");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "deferred response leaked a reference");
    fixtureTeardown(&fixture);
}

static void fixtureRequireDrainClosed(httpserver_fixture_t *fixture, uint32_t initial_refc)
{
    twfRequireEqualU32(fixture->trace.prev_finish, 1, "drain failure did not close the carrier exactly once");
    twfRequireEqualU32(fixture->trace.next_finish, 0, "drain failure reflected Finish toward the finished service");
    twfRequireLineStateZeroed(fixture->line, fixture->http, "drain failure retained HTTP/2 state");
    twfRequire(lineIsAlive(fixture->line), "drain failure destroyed the borrowed carrier line");
    twfRequireEqualU32(twfLineRefCount(fixture->line), initial_refc, "drain failure leaked a line reference");
    twfRequire(wloopNTimers(fixture->env.loop) == 0, "drain failure retained its timer");
    fixtureAdvanceTo(fixture, now_us + UINT64_C(1000000));
    twfRequireEqualU32(fixture->trace.prev_finish, 1, "drain failure notified the carrier again after cleanup");
}

static void caseHttp2DrainDeadlineWithoutInput(void)
{
    twfSetCase("HttpServer fixed drain deadline closes without further client input");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    httpserver_tstate_t *ts     = tunnelGetState(fixture.http);
    ts->close_drain_timeout_ms  = 40;
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    /* A blocked live response has no drain deadline until the service actually finishes. */
    fixtureAdvanceTo(&fixture, now_us + UINT64_C(100000000));
    twfRequire(wloopNTimers(fixture.env.loop) == 0 && fixture.trace.prev_finish == 0,
               "HTTP/2 started its close deadline before service Finish");

    const uint64_t expected_deadline = wloopNowMonotonicMS(fixture.env.loop) + 40;
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(ls->close_drain_deadline_ms == expected_deadline && ls->close_drain_timer != NULL &&
                   wloopNTimers(fixture.env.loop) == 1,
               "service Finish did not arm the configured absolute drain deadline");
    fixtureAdvanceTo(&fixture, (expected_deadline - 1) * 1000);
    twfRequire(fixture.trace.prev_finish == 0 && ls->session != NULL,
               "HTTP/2 drain closed before the configured deadline");
    fixtureAdvanceTo(&fixture, expected_deadline * 1000 + 1000);
    fixtureRequireDrainClosed(&fixture, initial_refc);
    fixtureTeardown(&fixture);
}

static void caseHttp2DrainProgressDoesNotExtendDeadline(void)
{
    twfSetCase("HttpServer request traffic and WINDOW_UPDATE progress do not extend the drain deadline");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    httpserver_tstate_t *ts     = tunnelGetState(fixture.http);
    ts->close_drain_timeout_ms  = 1000;
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    httpserver_lstate_t *ls       = lineGetState(fixture.line, fixture.http);
    const uint64_t       deadline = ls->close_drain_deadline_ms;
    wtimer_t *const      timer    = ls->close_drain_timer;

    for (unsigned i = 0; i < 3; ++i)
    {
        fixtureAdvanceTo(&fixture, now_us + 250000);
        fixtureFeedData(&fixture, 1);
        fixtureIncreaseResponseWindow(&fixture, 7);
        twfRequireEqualU32((uint32_t) h2DataPendingBytes(&ls->h2_data),
                           kHttp2BodySize - 7 * (i + 1),
                           "partial WINDOW_UPDATE did not advance the retained response");
        twfRequire(ls->close_drain_deadline_ms == deadline && ls->close_drain_timer == timer && timer_add_calls == 1 &&
                       timer_reset_calls == 0,
                   "traffic or response progress extended the first drain deadline");
        twfRequire(fixture.trace.next_payload == 0 && fixture.trace.prev_finish == 0,
                   "traffic escaped to the finished backend or prematurely closed the drain");
    }
    fixtureAdvanceTo(&fixture, deadline * 1000 + 1000);
    fixtureRequireDrainClosed(&fixture, initial_refc);
    fixtureTeardown(&fixture);
}

static void expireDrainDuringResponseOutput(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    twfPrevPayload(prev, line, buf);
    httpserver_lstate_t *ls = lineGetState(line, prev->next);
    twfRequire(ls->close_drain_deadline_ms != 0, "final output began before publishing the drain deadline");
    /* The loop cache stays unchanged while this synchronous downstream callback runs. */
    now_us = ls->close_drain_deadline_ms * 1000;
}

static void caseHttp2DrainExpiresDuringFinalOutput(void)
{
    twfSetCase("HttpServer synchronous final output still obeys the original drain deadline");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixturePrepareHttp2(&fixture, false);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    h2DataAppend(&ls->h2_data, fixturePayload(&fixture, kHttp2BodySize), false);
    fixture.prev->fnPayloadD    = expireDrainDuringResponseOutput;
    const uint32_t initial_refc = twfLineRefCount(fixture.line);

    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);

    twfRequireEqualU32(fixture.trace.prev_payload_bytes,
                       kHttp2FrameSize + HTTP2_FRAME_HDLEN,
                       "synchronous final output started another HTTP/2 frame after its deadline");
    twfRequireEqualU32(timer_add_calls, 0, "already expired final output allocated a timer");
    fixtureRequireDrainClosed(&fixture, initial_refc);
    fixtureTeardown(&fixture);
}

static void caseHttp2DrainEarlyTimer(bool refuse_reset)
{
    twfSetCase(refuse_reset ? "HttpServer drain closes safely when an early timer cannot rearm"
                            : "HttpServer early timer wakeup preserves the original drain deadline");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    httpserver_tstate_t *ts     = tunnelGetState(fixture.http);
    ts->close_drain_timeout_ms  = 1000;
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    httpserver_lstate_t *ls       = lineGetState(fixture.line, fixture.http);
    const uint64_t       deadline = ls->close_drain_deadline_ms;
    twfRequire(ls->close_drain_timer->next_timeout < deadline * 1000, "fixture did not exercise coarse timer rounding");
    refuse_timer_reset = refuse_reset;
    fixtureAdvanceTo(&fixture, ls->close_drain_timer->next_timeout + 1);
    twfRequireEqualU32(timer_reset_calls, 1, "early drain wakeup did not try to reset its timer");
    if (! refuse_reset)
    {
        twfRequire(ls->close_drain_deadline_ms == deadline && ls->close_drain_timer != NULL &&
                       fixture.trace.prev_finish == 0 && wloopNTimers(fixture.env.loop) == 1,
                   "early wakeup ended the drain or moved its deadline");
        twfRequire(timer_reset_ms == deadline - wloopNowMonotonicMS(fixture.env.loop),
                   "early wakeup did not rearm only the remaining time");
        fixtureAdvanceTo(&fixture, deadline * 1000 + 1000);
    }
    fixtureRequireDrainClosed(&fixture, initial_refc);
    fixtureTeardown(&fixture);
}

static void caseHttp2DrainTimerRefusal(void)
{
    twfSetCase("HttpServer closes a blocked final response when timer admission is refused");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    refuse_timer_add            = true;
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    twfRequireEqualU32(timer_add_calls, 1, "blocked final response did not attempt to arm a deadline");
    fixtureRequireDrainClosed(&fixture, initial_refc);
    fixtureTeardown(&fixture);
}

static void caseHttp2QuiescedDrainCleanup(void)
{
    twfSetCase("HttpServer quiesced drain timer is reclaimed when its carrier owner drains");
    httpserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixtureQueueBlockedResponse(&fixture);
    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpserverTunnelDownStreamFinish(fixture.http, fixture.line);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(ls->close_drain_timer != NULL, "blocked response did not retain a timer before quiescence");
    wloopCloseNormalAdmission(fixture.env.loop);
    wloopQuiesceNormalWork(fixture.env.loop);
    twfRequire(ls->close_drain_timer->quiesced, "quiescence did not detach the drain timer callback");
    httpserverTunnelUpStreamFinish(fixture.http, fixture.line);
    twfRequireLineStateZeroed(fixture.line, fixture.http, "carrier drain retained the quiesced timer or HTTP/2 state");
    twfRequireEqualText(fixture.trace.seq, "", "quiesced cleanup reflected Finish toward a finished direction");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "quiesced cleanup leaked a line reference");
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    caseHttp2FinishDuringActiveProvider(false);
    caseHttp2FinishDuringActiveProvider(true);
    caseHttp2DiscardsRequestAfterServiceFinish(true);
    caseHttp2DiscardsRequestAfterServiceFinish(false);
    caseHttp2CarrierFinishWhileResponseBlocked();
    caseHttp2ResetWhileResponseBlocked();
    caseHttp2DrainDeadlineWithoutInput();
    caseHttp2DrainProgressDoesNotExtendDeadline();
    caseHttp2DrainExpiresDuringFinalOutput();
    caseHttp2DrainEarlyTimer(false);
    caseHttp2DrainEarlyTimer(true);
    caseHttp2DrainTimerRefusal();
    caseHttp2QuiescedDrainCleanup();
    return 0;
}

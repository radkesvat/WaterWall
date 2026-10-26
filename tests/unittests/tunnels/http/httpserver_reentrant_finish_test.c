/*
 * Covers: httpserver reentrant finish; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseFinishDuringFirstFinalChunkStopsRemainingOutput, caseHttp2FinishDuringActiveProvider
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
 */
#include "HttpServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096,
    kForcedSendChunkSize = 2,
    kHttp2BodySize       = 32768,
    kHttp2FrameSize      = 16384
};

static uint32_t forced_send_chunk_size = kForcedSendChunkSize;

uint32_t __wrap_bufferpoolGetLargeBufferSize(buffer_pool_t *pool);

uint32_t __wrap_bufferpoolGetLargeBufferSize(buffer_pool_t *pool)
{
    discard pool;
    return forced_send_chunk_size;
}

typedef struct httpserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
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
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");

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
    twfWorkerEnvTeardown(&fixture->env);
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

static void fixturePrepareHttp2(httpserver_fixture_t *fixture)
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
    twfRequire(nghttp2_submit_settings(fixture->peer, NGHTTP2_FLAG_NONE, NULL, 0) == 0, "peer SETTINGS failed");
    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
    };
    twfRequire(nghttp2_submit_request(fixture->peer, NULL, headers, ARRAY_SIZE(headers), NULL, NULL) == 1,
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
    fixturePrepareHttp2(&fixture);

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

int main(void)
{
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    caseHttp2FinishDuringActiveProvider(false);
    caseHttp2FinishDuringActiveProvider(true);
    return 0;
}

/*
 * HttpServer sends the HTTP/1 final chunk while handling downstream Finish. An
 * upstream Finish may re-enter from the previous tunnel during the first
 * payload callback, so the remaining chunks and a reflected Finish must stop.
 */
#include "HttpServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096,
    kForcedSendChunkSize = 2
};

uint32_t __wrap_bufferpoolGetLargeBufferSize(buffer_pool_t *pool);

uint32_t __wrap_bufferpoolGetLargeBufferSize(buffer_pool_t *pool)
{
    discard pool;
    return kForcedSendChunkSize;
}

typedef struct httpserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
} httpserver_fixture_t;

static void finishServerFromPrevOnFirstPayload(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(prev);
    ++trace->prev_payload;
    trace->prev_payload_bytes += sbufGetLength(buf);
    twfRecord(trace, 'p');
    lineReuseBuffer(line, buf);

    twfRequireEqualU32(trace->prev_payload, 1, "HttpServer sent payload after the previous direction finished");
    httpserverTunnelUpStreamFinish(prev->next, line);
}

static void fixtureSetup(httpserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
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
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
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

int main(void)
{
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    return 0;
}

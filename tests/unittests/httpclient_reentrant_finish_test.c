/*
 * HttpClient sends the HTTP/1 final chunk while handling upstream Finish. A
 * downstream Finish may re-enter from the next tunnel during the first payload
 * callback, so the remaining chunks and a reflected Finish must be suppressed.
 */
#include "HttpClient/structure.h"

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

typedef struct httpclient_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
} httpclient_fixture_t;

static void finishClientFromNextOnFirstPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(next);
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    twfRecord(trace, 'P');
    lineReuseBuffer(line, buf);

    twfRequireEqualU32(trace->next_payload, 1, "HttpClient sent payload after the next direction finished");
    httpclientTunnelDownStreamFinish(next->prev, line);
}

static void fixtureSetup(httpclient_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpClient tunnel");

    fixture->next->fnPayloadU = finishClientFromNextOnFirstPayload;
    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpclient_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpclientLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto = kHttpClientRuntimeHttp1;
}

static void fixtureTeardown(httpclient_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    twfLineDestroy(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
}

static void caseFinishDuringFirstFinalChunkStopsRemainingOutput(void)
{
    twfSetCase("HttpClient Finish during first final-chunk payload");

    httpclient_fixture_t fixture;
    fixtureSetup(&fixture);

    const uint32_t initial_refc = twfLineRefCount(fixture.line);
    httpclientTunnelUpStreamFinish(fixture.http, fixture.line);

    twfRequireEqualText(fixture.trace.seq, "P", "HttpClient emitted a callback after re-entrant Finish");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "HttpClient did not stop after the first payload");
    twfRequireEqualU32(
        fixture.trace.next_payload_bytes, kForcedSendChunkSize, "HttpClient did not use the forced first chunk");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpClient reflected Finish toward the finished next side");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HttpClient reflected Finish toward the original sender");
    twfRequire(lineIsAlive(fixture.line), "borrowed HttpClient line was destroyed");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "HttpClient line state was not destroyed exactly once");
    twfRequireEqualU32(twfLineRefCount(fixture.line), initial_refc, "HttpClient leaked a line reference");

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    return 0;
}

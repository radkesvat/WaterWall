/*
 * HttpClient sends the HTTP/1 final chunk while handling upstream Finish. The
 * next tunnel can re-enter through a downstream Finish, Pause, or Resume during
 * that send, so the finished previous side must never receive a reflection.
 */
#include "HttpClient/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096,
    kForcedSendChunkSize = 2,
    kHttp1FinalChunkSize = sizeof("0\r\n\r\n") - 1
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

typedef struct httpclient_split_observer_s
{
    twf_trace_t *trace;
    line_t      *upload_line;
    line_t      *download_line;
    uint32_t     upload_finish;
    uint32_t     download_finish;
} httpclient_split_observer_t;

typedef struct httpclient_split_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  transport_lines;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *main_line;
    line_t          *upload_line;
    line_t          *download_line;
    uint8_t          final_chunk[kHttp1FinalChunkSize + 1];
} httpclient_split_fixture_t;

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

static void pauseAndResumeClientFromNextOnFirstSplitPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    httpclient_split_observer_t *observer = tunnelGetState(next);
    twf_trace_t                 *trace    = observer->trace;
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    twfCapture(trace, buf);
    twfRecord(trace, 'P');
    lineReuseBuffer(line, buf);

    if (trace->next_payload == 1)
    {
        httpclientTunnelDownStreamPause(next->prev, line);
        httpclientTunnelDownStreamResume(next->prev, line);
    }
}

static void recordSplitTransportFinish(tunnel_t *next, line_t *line)
{
    httpclient_split_observer_t *observer = tunnelGetState(next);
    twf_trace_t                 *trace    = observer->trace;

    if (line == observer->upload_line)
    {
        twfRequireEqualU32(observer->upload_finish, 0, "split upload transport received Finish twice");
        ++observer->upload_finish;
    }
    else if (line == observer->download_line)
    {
        twfRequireEqualU32(observer->download_finish, 0, "split download transport received Finish twice");
        ++observer->download_finish;
    }
    else
    {
        twfRequire(false, "unexpected line reached the split transport finish observer");
    }

    ++trace->next_finish;
    twfRecord(trace, 'F');
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
    twfWorkerEnvTeardown(&fixture->env);
}

static void splitFixtureInitializeLine(tunnel_t *http, line_t *line, line_t *main_line, line_t *upload_line,
                                       line_t *download_line, httpclient_split_role_t role)
{
    httpclient_lstate_t *ls = lineGetState(line, http);
    httpclientLinestateInitialize(ls, http, line);
    ls->runtime_proto       = kHttpClientRuntimeHttp1;
    ls->split_role          = role;
    ls->split_main_line     = main_line;
    ls->split_upload_line   = upload_line;
    ls->split_download_line = download_line;
    stringCopyN(ls->split_id, "unit-test-split", sizeof(ls->split_id));
}

static void splitFixtureSetup(httpclient_split_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(httpclient_split_observer_t), 0);
    twfRequire(fixture->http != NULL && fixture->next != NULL, "failed to create the split HttpClient fixture");

    fixture->next->fnPayloadU = pauseAndResumeClientFromNextOnFirstSplitPayload;
    fixture->next->fnFinU     = recordSplitTransportFinish;
    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    httpclient_tstate_t *ts = tunnelGetState(fixture->http);
    ts->h1_transport_mode   = kHttpClientH1TransportSplit;
    fixture->main_line      = twfLineCreate(fixture->http->lstate_size);
    twfLinePoolSetup(&fixture->transport_lines, fixture->http->lstate_size, 2);
    fixture->upload_line   = twfLinePoolCreateLine(&fixture->transport_lines);
    fixture->download_line = twfLinePoolCreateLine(&fixture->transport_lines);

    splitFixtureInitializeLine(fixture->http,
                               fixture->main_line,
                               fixture->main_line,
                               fixture->upload_line,
                               fixture->download_line,
                               kHttpClientSplitRoleMain);
    splitFixtureInitializeLine(fixture->http,
                               fixture->upload_line,
                               fixture->main_line,
                               fixture->upload_line,
                               fixture->download_line,
                               kHttpClientSplitRoleUpload);
    splitFixtureInitializeLine(fixture->http,
                               fixture->download_line,
                               fixture->main_line,
                               fixture->upload_line,
                               fixture->download_line,
                               kHttpClientSplitRoleDownload);

    httpclient_split_observer_t *observer = tunnelGetState(fixture->next);
    *observer                             = (httpclient_split_observer_t) {
                                    .trace = &fixture->trace, .upload_line = fixture->upload_line, .download_line = fixture->download_line};

    fixture->trace.capture          = fixture->final_chunk;
    fixture->trace.capture_capacity = kHttp1FinalChunkSize;

    // Keep these allocations inspectable after HttpClient destroys the lines it owns.
    lineRef(fixture->upload_line);
    lineRef(fixture->download_line);
}

static void splitFixtureTeardown(httpclient_split_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();

    twfRequire(! lineIsAlive(fixture->upload_line), "split upload line was not destroyed before teardown");
    twfRequire(! lineIsAlive(fixture->download_line), "split download line was not destroyed before teardown");
    lineUnref(fixture->upload_line);
    lineUnref(fixture->download_line);

    twfLinePoolTeardown(&fixture->transport_lines);
    twfLineDestroy(fixture->main_line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
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

static void caseSplitFinishAbsorbsCompanionBackpressure(void)
{
    twfSetCase("HttpClient split Finish absorbs companion backpressure");

    httpclient_split_fixture_t fixture;
    splitFixtureSetup(&fixture);

    const uint32_t initial_main_refc = twfLineRefCount(fixture.main_line);
    httpclientTunnelUpStreamFinish(fixture.http, fixture.main_line);

    twfRequireEqualText(fixture.trace.seq,
                        "PPPFF",
                        "split final-chunk backpressure reached the finished previous side or reordered teardown");
    twfRequireEqualU32(fixture.trace.next_payload, 3, "split final chunk was not emitted in all forced fragments");
    twfRequireEqualU32(fixture.trace.next_payload_bytes,
                       kHttp1FinalChunkSize,
                       "split final chunk bytes did not reach the next tunnel");
    twfRequireEqualText((const char *) fixture.final_chunk, "0\r\n\r\n", "split final chunk bytes were corrupted");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "split Finish reflected toward the original sender");
    twfRequireEqualU32(fixture.trace.next_finish, 2, "split transport legs did not each receive one upstream Finish");

    httpclient_split_observer_t *observer = tunnelGetState(fixture.next);
    twfRequireEqualU32(observer->upload_finish, 1, "split upload transport did not receive exactly one Finish");
    twfRequireEqualU32(observer->download_finish, 1, "split download transport did not receive exactly one Finish");
    twfRequire(lineIsAlive(fixture.main_line), "borrowed split main line was destroyed");
    twfRequire(! lineIsAlive(fixture.upload_line), "owned split upload line remained alive");
    twfRequire(! lineIsAlive(fixture.download_line), "owned split download line remained alive");
    twfRequireLineStateZeroed(fixture.main_line, fixture.http, "split main line state was not destroyed exactly once");
    twfRequireLineStateZeroed(
        fixture.upload_line, fixture.http, "split upload line state was not destroyed exactly once");
    twfRequireLineStateZeroed(
        fixture.download_line, fixture.http, "split download line state was not destroyed exactly once");
    twfRequireEqualU32(twfLineRefCount(fixture.main_line), initial_main_refc, "split main line leaked a reference");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line), 1, "split upload line leaked a reference");
    twfRequireEqualU32(twfLineRefCount(fixture.download_line), 1, "split download line leaked a reference");
    twfRequireNoLeakedBuffers();

    splitFixtureTeardown(&fixture);
}

int main(void)
{
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    caseSplitFinishAbsorbsCompanionBackpressure();
    return 0;
}

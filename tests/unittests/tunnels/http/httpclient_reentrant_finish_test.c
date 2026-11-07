/*
 * Covers: httpclient reentrant finish; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseFinishDuringFirstFinalChunkStopsRemainingOutput,
 * caseSplitFinishAbsorbsCompanionBackpressure, caseSplitFailureClosesSiblingDuringFinish,
 * caseSplitFinishClosesSiblingDuringFinalPayload, caseSplitUploadFinishKeepsTheResponse,
 * caseSplitUploadFinishDuringDownloadInit
 * Checks: Assertion labels include: HttpClient sent payload after the next direction finished; split upload
 * transport received Finish twice; split download transport received Finish twice; unexpected line
 * reached the split transport finish observer
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.httpclient_reentrant_finish_unit
 */
/*
 * HttpClient sends the HTTP/1 final chunk while handling upstream Finish. The
 * next tunnel can re-enter through a downstream Finish, Pause, or Resume during
 * that send, so the finished previous side must never receive a reflection.
 */
#include "HttpClient/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "wfrand.h"

enum
{
    kTestLargeBufferSize = 4096,
    kForcedSendChunkSize = 2,
    kHttp1FinalChunkSize = sizeof("0\r\n\r\n") - 1
};

uint32_t __wrap_bufferpoolGetLargeBufferSize(const buffer_pool_t *pool);

uint32_t __wrap_bufferpoolGetLargeBufferSize(const buffer_pool_t *pool)
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
    bool         finish_download_during_upload_finish;
    bool         finish_download_during_upload_payload;
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
        if (observer->finish_download_during_upload_payload)
        {
            observer->finish_download_during_upload_payload = false;
            httpclientTunnelDownStreamFinish(next->prev, observer->download_line);
            return;
        }
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

    if (line == observer->upload_line && observer->finish_download_during_upload_finish)
    {
        observer->finish_download_during_upload_finish = false;
        httpclientTunnelDownStreamFinish(next->prev, observer->download_line);
    }
}

static void finishSplitMainAtOwner(tunnel_t *prev, line_t *line)
{
    twfPrevFinish(prev, line);
    lineDestroy(line);
}

static void finishSplitUploadDuringDownloadInit(tunnel_t *next, line_t *line)
{
    httpclient_split_observer_t *observer = tunnelGetState(next);
    httpclient_lstate_t         *ls       = lineGetState(line, next->prev);
    twfNextInit(next, line);

    // Keep the owned transports inspectable after Finish without keeping them logically alive.
    lineRef(line);
    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        observer->upload_line = line;
        return;
    }

    twfRequire(ls->split_role == kHttpClientSplitRoleDownload, "unexpected split startup transport role");
    observer->download_line = line;
    httpclientTunnelDownStreamFinish(next->prev, observer->upload_line);
    twfRequire(! lineIsAlive(observer->upload_line), "split startup upload Finish left its owned line alive");
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

static void caseSplitFailureClosesSiblingDuringFinish(void)
{
    twfSetCase("HttpClient split failure settles a sibling Finish exactly once");

    httpclient_split_fixture_t fixture;
    splitFixtureSetup(&fixture);
    const uint32_t               initial_main_refc = twfLineRefCount(fixture.main_line);
    httpclient_split_observer_t *observer          = tunnelGetState(fixture.next);
    observer->finish_download_during_upload_finish = true;

    httpclient_lstate_t *upload_ls  = lineGetState(fixture.upload_line, fixture.http);
    upload_ls->h1_write_in_progress = true;
    sbuf_t *overflow                = bufferpoolGetBestFit(fixture.env.pool, kHttpClientHttp1NestedMaxBytes + 1U, 0);
    sbufSetLength(overflow, kHttpClientHttp1NestedMaxBytes + 1U);
    httpclientTunnelUpStreamPayload(fixture.http, fixture.main_line, overflow);

    twfRequireEqualU32(fixture.trace.prev_finish, 1, "split failure notified the previous side more than once");
    twfRequireEqualU32(observer->upload_finish, 1, "split failure did not finish its upload transport once");
    twfRequireEqualU32(observer->download_finish, 0, "split failure reflected Finish toward its download sender");
    twfRequire(lineIsAlive(fixture.main_line), "split failure destroyed the borrowed main line");
    twfRequire(! lineIsAlive(fixture.upload_line) && ! lineIsAlive(fixture.download_line),
               "split failure left an owned transport alive");
    twfRequireLineStateZeroed(fixture.main_line, fixture.http, "split failure retained main state");
    twfRequireLineStateZeroed(fixture.upload_line, fixture.http, "split failure retained upload state");
    twfRequireLineStateZeroed(fixture.download_line, fixture.http, "split failure retained download state");
    twfRequireEqualU32(twfLineRefCount(fixture.main_line), initial_main_refc, "split failure leaked a main reference");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line), 1, "split failure leaked an upload reference");
    twfRequireEqualU32(twfLineRefCount(fixture.download_line), 1, "split failure leaked a download reference");
    splitFixtureTeardown(&fixture);
}

static void caseSplitFinishClosesSiblingDuringFinalPayload(void)
{
    twfSetCase("HttpClient split final payload absorbs a sibling Finish");

    httpclient_split_fixture_t fixture;
    splitFixtureSetup(&fixture);
    const uint32_t               initial_main_refc  = twfLineRefCount(fixture.main_line);
    httpclient_split_observer_t *observer           = tunnelGetState(fixture.next);
    observer->finish_download_during_upload_payload = true;
    httpclientTunnelUpStreamFinish(fixture.http, fixture.main_line);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "split sibling Finish reflected toward the finished source");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "split final payload continued after sibling Finish");
    twfRequireEqualU32(observer->upload_finish, 1, "split sibling Finish did not close upload once");
    twfRequireEqualU32(observer->download_finish, 0, "split sibling Finish reflected toward its download sender");
    twfRequire(lineIsAlive(fixture.main_line), "split sibling Finish destroyed the borrowed main line");
    twfRequire(! lineIsAlive(fixture.upload_line) && ! lineIsAlive(fixture.download_line),
               "split sibling Finish left an owned transport alive");
    twfRequireLineStateZeroed(fixture.main_line, fixture.http, "split sibling Finish retained main state");
    twfRequireLineStateZeroed(fixture.upload_line, fixture.http, "split sibling Finish retained upload state");
    twfRequireLineStateZeroed(fixture.download_line, fixture.http, "split sibling Finish retained download state");
    twfRequireEqualU32(
        twfLineRefCount(fixture.main_line), initial_main_refc, "split sibling Finish leaked main reference");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line), 1, "split sibling Finish leaked upload reference");
    twfRequireEqualU32(twfLineRefCount(fixture.download_line), 1, "split sibling Finish leaked download reference");
    splitFixtureTeardown(&fixture);
}

static sbuf_t *splitBytes(httpclient_split_fixture_t *fixture, const char *text)
{
    const uint32_t length = (uint32_t) stringLength(text);
    sbuf_t        *buf    = bufferpoolGetBestFit(fixture->env.pool, length, 0);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), text, length);
    return buf;
}

/* The server closes both transports when its response ends, and the upload's Finish, with nothing queued
 * behind it, can arrive first. The end of the response is still in flight on the download. */
static void caseSplitUploadFinishKeepsTheResponse(void)
{
    twfSetCase("HttpClient split upload Finish keeps the response arriving on the download");

    httpclient_split_fixture_t fixture;
    splitFixtureSetup(&fixture);
    const uint32_t               initial_main_refc = twfLineRefCount(fixture.main_line);
    httpclient_split_observer_t *observer          = tunnelGetState(fixture.next);

    httpclientTunnelDownStreamFinish(fixture.http, fixture.upload_line);
    twfRequire(! lineIsAlive(fixture.upload_line), "split upload Finish left its transport alive");
    twfRequire(lineIsAlive(fixture.download_line), "split upload Finish closed the download before the response ended");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "split upload Finish closed main before the response ended");
    twfRequireEqualU32(observer->upload_finish, 0, "split upload Finish was reflected toward its sender");

    httpclientTunnelUpStreamPayload(fixture.http, fixture.main_line, splitBytes(&fixture, "late"));
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "an upload after the upload transport ended closed main");

    httpclientTunnelDownStreamPayload(
        fixture.http,
        fixture.download_line,
        splitBytes(&fixture, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
    twfRequireEqualU32(
        fixture.trace.prev_payload_bytes, 5, "the response body did not reach main after the upload ended");

    httpclientTunnelDownStreamFinish(fixture.http, fixture.download_line);
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the download Finish did not close main exactly once");
    twfRequireEqualU32(observer->download_finish, 0, "the download Finish was reflected toward its sender");
    twfRequire(lineIsAlive(fixture.main_line), "split teardown destroyed the borrowed main line");
    twfRequireLineStateZeroed(fixture.main_line, fixture.http, "split teardown retained main state");
    twfRequireLineStateZeroed(fixture.upload_line, fixture.http, "split teardown retained upload state");
    twfRequireLineStateZeroed(fixture.download_line, fixture.http, "split teardown retained download state");
    twfRequireEqualU32(twfLineRefCount(fixture.main_line), initial_main_refc, "split teardown leaked a main reference");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line), 1, "split teardown leaked an upload reference");
    twfRequireEqualU32(twfLineRefCount(fixture.download_line), 1, "split teardown leaked a download reference");
    splitFixtureTeardown(&fixture);
}

static void caseSplitUploadFinishDuringDownloadInit(bool owner_destroys_main)
{
    twfSetCase(owner_destroys_main ? "HttpClient split startup upload Finish reaches the main owner"
                                   : "HttpClient split startup upload Finish leaves borrowed main alive");

    httpclient_split_fixture_t fixture;
    memoryZero(&fixture, sizeof(fixture));
    twfWorkerEnvSetup(&fixture.env, kTestLargeBufferSize, 0);
    fixture.prev = twfCreatePrevTunnel(&fixture.trace);
    fixture.http = tunnelCreate(NULL, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));
    fixture.next = tunnelCreate(NULL, sizeof(httpclient_split_observer_t), 0);
    twfRequire(fixture.http != NULL && fixture.next != NULL, "failed to create the split startup fixture");
    if (owner_destroys_main)
    {
        fixture.prev->fnFinD = finishSplitMainAtOwner;
    }
    fixture.next->fnInitU    = finishSplitUploadDuringDownloadInit;
    fixture.next->fnPayloadU = twfNextPayload;
    fixture.next->fnFinU     = recordSplitTransportFinish;
    tunnelBind(fixture.prev, fixture.http);
    tunnelBind(fixture.http, fixture.next);

    httpclient_tstate_t *ts               = tunnelGetState(fixture.http);
    ts->h1_transport_mode                 = kHttpClientH1TransportSplit;
    httpclient_split_observer_t *observer = tunnelGetState(fixture.next);
    observer->trace                       = &fixture.trace;
    twfLinePoolSetup(&fixture.transport_lines, fixture.http->lstate_size, 4);
    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    chain->workers_count  = 1;
    chain->line_pools[0]  = fixture.transport_lines.pools[0];
    fixture.http->chain   = chain;
    fixture.main_line     = twfLinePoolCreateLine(&fixture.transport_lines);
    lineRef(fixture.main_line);

    // A shared next tunnel may synchronously finish one transport while initializing its sibling.
    httpclientSplitUpStreamInit(fixture.http, fixture.main_line);

    twfRequireEqualU32(fixture.trace.next_init, 2, "split startup did not initialize both transports");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "split startup sent headers after its upload finished");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "split startup failure did not finish main exactly once");
    twfRequireEqualU32(observer->upload_finish, 0, "split startup reflected Finish toward its upload sender");
    twfRequireEqualU32(observer->download_finish, 1, "split startup did not finish download exactly once");
    twfRequire(lineIsAlive(fixture.main_line) == ! owner_destroys_main,
               "split startup failure violated main line ownership");
    twfRequire(! lineIsAlive(observer->upload_line), "split startup failure retained upload");
    twfRequire(! lineIsAlive(observer->download_line), "split startup failure retained download");
    twfRequireLineStateZeroed(fixture.main_line, fixture.http, "split startup failure retained main state");
    twfRequireLineStateZeroed(observer->upload_line, fixture.http, "split startup failure retained upload state");
    twfRequireLineStateZeroed(observer->download_line, fixture.http, "split startup failure retained download state");
    twfRequireEqualU32(twfLineRefCount(fixture.main_line),
                       owner_destroys_main ? 1 : 2,
                       "split startup failure leaked a main reference");
    twfRequireEqualU32(twfLineRefCount(observer->upload_line), 1, "split startup failure leaked an upload reference");
    twfRequireEqualU32(
        twfLineRefCount(observer->download_line), 1, "split startup failure leaked a download reference");
    twfRequireNoLeakedBuffers();

    if (lineIsAlive(fixture.main_line))
    {
        lineDestroy(fixture.main_line);
    }
    lineUnref(fixture.main_line);
    lineUnref(observer->upload_line);
    lineUnref(observer->download_line);
    twfLinePoolTeardown(&fixture.transport_lines);
    tunnelDestroy(fixture.prev);
    tunnelDestroy(fixture.http);
    tunnelDestroy(fixture.next);
    memoryFree(chain);
    twfWorkerEnvTeardown(&fixture.env);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "fixture random initialization failed");
    frandInit();
    caseFinishDuringFirstFinalChunkStopsRemainingOutput();
    caseSplitFinishAbsorbsCompanionBackpressure();
    TEST_RUN_CASE(caseSplitFinishClosesSiblingDuringFinalPayload);
    TEST_RUN_CASE(caseSplitFailureClosesSiblingDuringFinish);
    TEST_RUN_CASE(caseSplitUploadFinishKeepsTheResponse);
    caseSplitUploadFinishDuringDownloadInit(true);
    caseSplitUploadFinishDuringDownloadInit(false);
    return 0;
}

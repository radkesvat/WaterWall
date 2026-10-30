/*
 * Covers: httpserver split callback boundary; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseUnpairedDownloadAbsorbsAllCallbacks, casePairedDownloadMapsBackpressureToMain,
 * caseTransportRoleAbsorbsAllCallbacks, caseInitializedRoleForwardsSameLine,
 * caseFinishedNextSuppressesBackpressure, caseWaitingBoundary, casePairedLargeChunk, caseMigrationReplay
 * Checks: Assertion labels include: next callback capture overflow; the main line did not initialize next
 * exactly once; the main line initialized next with the wrong line pointer; HttpServer line state was
 * not destroyed during test teardown
 * Limits: Migration substitutes pipeTo and the replay receiver; real cross-worker delivery remains
 * integration coverage. Component fixtures do not establish host-network or application-throughput behavior.
 * CTest: waterwall.httpserver_split_callback_boundary_unit
 */
/*
 * Split HttpServer transport lines stop at HttpServer: only the paired main
 * line is initialized toward next. Upstream control callbacks must therefore
 * be absorbed on transport lines or, for a paired download, translated to the
 * initialized main line.
 */
#include "HttpServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* Merging recycles the second buffer inside buffer_pool.c, bypassing
     * GNU's external reuse wrapper. Record that ownership settlement here. */
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

enum
{
    kTestLargeBufferSize  = 4096,
    kMaxRecordedCallbacks = 16
};

typedef struct callback_capture_s
{
    char     events[kMaxRecordedCallbacks + 1];
    line_t  *lines[kMaxRecordedCallbacks];
    uint32_t count;
} callback_capture_t;

static callback_capture_t *callbackCaptureGet(tunnel_t *t)
{
    return *(callback_capture_t **) tunnelGetState(t);
}

static void callbackCaptureReset(callback_capture_t *capture)
{
    memoryZero(capture, sizeof(*capture));
}

static void callbackCaptureRecord(tunnel_t *t, line_t *l, char event)
{
    callback_capture_t *capture = callbackCaptureGet(t);
    twfRequire(capture->count < kMaxRecordedCallbacks, "next callback capture overflow");

    capture->events[capture->count] = event;
    capture->lines[capture->count]  = l;
    ++capture->count;
    capture->events[capture->count] = '\0';
}

static void callbackCaptureInit(tunnel_t *t, line_t *l)
{
    callbackCaptureRecord(t, l, 'I');
}

static void callbackCaptureEst(tunnel_t *t, line_t *l)
{
    callbackCaptureRecord(t, l, 'E');
}

static void callbackCapturePause(tunnel_t *t, line_t *l)
{
    callbackCaptureRecord(t, l, 'U');
}

static void callbackCaptureResume(tunnel_t *t, line_t *l)
{
    callbackCaptureRecord(t, l, 'R');
}

static void callbackCaptureFinish(tunnel_t *t, line_t *l)
{
    callbackCaptureRecord(t, l, 'F');
}

static tunnel_t *callbackCaptureCreateNext(callback_capture_t *capture)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(callback_capture_t *), 0);
    twfRequire(t != NULL, "failed to create the callback-capturing next tunnel");

    *(callback_capture_t **) tunnelGetState(t) = capture;
    t->fnInitU                                 = callbackCaptureInit;
    t->fnEstU                                  = callbackCaptureEst;
    t->fnPauseU                                = callbackCapturePause;
    t->fnResumeU                               = callbackCaptureResume;
    return t;
}

typedef struct httpserver_split_callback_fixture_s
{
    twf_worker_env_t   env;
    twf_trace_t        prev_trace;
    callback_capture_t next_capture;
    tunnel_t          *prev;
    tunnel_t          *http;
    tunnel_t          *next;
} httpserver_split_callback_fixture_t;

static uint32_t g_pool_size = kTestLargeBufferSize;

static void fixtureSetup(httpserver_split_callback_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithBufferSizes(&fixture->env,
                                     min(g_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     min(g_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     64,
                                     SPLICE_PAYLOAD_LIMIT,
                                     g_pool_size);

    fixture->prev = twfCreatePrevTunnel(&fixture->prev_trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = callbackCaptureCreateNext(&fixture->next_capture);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");

    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);
}

static line_t *fixtureCreateInitializedLine(httpserver_split_callback_fixture_t *fixture)
{
    line_t *l = twfLineCreate(fixture->http->lstate_size);
    httpserverLinestateInitialize(lineGetState(l, fixture->http), fixture->http, l);
    return l;
}

static void fixtureInitializeNextForMain(httpserver_split_callback_fixture_t *fixture, line_t *main_line)
{
    tunnelNextUpStreamInit(fixture->http, main_line);

    twfRequireEqualText(fixture->next_capture.events, "I", "the main line did not initialize next exactly once");
    twfRequire(fixture->next_capture.lines[0] == main_line,
               "the main line initialized next with the wrong line pointer");
    callbackCaptureReset(&fixture->next_capture);
}

static void fixtureDestroyInitializedLine(httpserver_split_callback_fixture_t *fixture, line_t *l)
{
    httpserverLinestateDestroy(lineGetState(l, fixture->http));
    twfRequireLineStateZeroed(l, fixture->http, "HttpServer line state was not destroyed during test teardown");
    twfLineDestroy(l);
}

static void fixtureTeardown(httpserver_split_callback_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();

    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
}

static void invokeEstPauseResume(tunnel_t *http, line_t *l)
{
    httpserverTunnelUpStreamEst(http, l);
    httpserverTunnelUpStreamPause(http, l);
    httpserverTunnelUpStreamResume(http, l);
}

static void requireNoNextCallbacks(const callback_capture_t *capture, const char *message)
{
    twfRequireEqualU32(capture->count, 0, message);
    twfRequireEqualText(capture->events, "", message);
}

static void requireCallbacksOnLine(const callback_capture_t *capture, line_t *expected_line, const char *message)
{
    for (uint32_t i = 0; i < capture->count; ++i)
    {
        twfRequire(capture->lines[i] == expected_line, message);
    }
}

static void requireLineUnchanged(line_t *l, uint32_t initial_refc, const char *message)
{
    twfRequire(lineIsAlive(l), message);
    twfRequireEqualU32(twfLineRefCount(l), initial_refc, message);
}

static void caseUnpairedDownloadAbsorbsAllCallbacks(void)
{
    twfSetCase("HttpServer split unpaired download callback boundary");

    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t              *download = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *dls      = lineGetState(download, fixture.http);
    dls->split_role               = kHttpServerSplitRoleDownload;
    const uint32_t initial_refc   = twfLineRefCount(download);

    invokeEstPauseResume(fixture.http, download);

    requireNoNextCallbacks(&fixture.next_capture,
                           "an unpaired split download exposed a callback to an uninitialized next line");
    requireLineUnchanged(download, initial_refc, "an unpaired split download callback changed its transport line");

    fixtureDestroyInitializedLine(&fixture, download);
    fixtureTeardown(&fixture);
}

static void casePairedDownloadMapsBackpressureToMain(void)
{
    twfSetCase("HttpServer split paired download callback mapping");

    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t              *download = fixtureCreateInitializedLine(&fixture);
    line_t              *main     = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *dls      = lineGetState(download, fixture.http);
    httpserver_lstate_t *mls      = lineGetState(main, fixture.http);
    dls->split_role               = kHttpServerSplitRoleDownload;
    dls->split_main_line          = main;
    mls->split_role               = kHttpServerSplitRoleMain;

    fixtureInitializeNextForMain(&fixture, main);
    const uint32_t download_refc = twfLineRefCount(download);
    const uint32_t main_refc     = twfLineRefCount(main);

    httpserverTunnelUpStreamEst(fixture.http, download);
    httpserverTunnelUpStreamPause(fixture.http, download);
    httpserverTunnelUpStreamResume(fixture.http, download);

    twfRequireEqualText(
        fixture.next_capture.events, "UR", "a paired download did not map only Pause and Resume to its main line");
    requireCallbacksOnLine(&fixture.next_capture, main, "a paired download callback used the transport line");
    requireLineUnchanged(download, download_refc, "a paired download callback changed its transport line");
    requireLineUnchanged(main, main_refc, "a paired download callback changed its main line");

    fixtureDestroyInitializedLine(&fixture, download);
    fixtureDestroyInitializedLine(&fixture, main);
    fixtureTeardown(&fixture);
}

static void caseTransportRoleAbsorbsAllCallbacks(httpserver_split_role_t role, const char *case_name)
{
    twfSetCase(case_name);

    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t              *transport = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *ls        = lineGetState(transport, fixture.http);
    ls->split_role                 = role;
    const uint32_t initial_refc    = twfLineRefCount(transport);

    invokeEstPauseResume(fixture.http, transport);

    requireNoNextCallbacks(&fixture.next_capture, "a split transport role exposed a callback to next");
    requireLineUnchanged(transport, initial_refc, "a split transport callback changed its line");

    fixtureDestroyInitializedLine(&fixture, transport);
    fixtureTeardown(&fixture);
}

static void caseInitializedRoleForwardsSameLine(httpserver_split_role_t role, const char *case_name)
{
    twfSetCase(case_name);

    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t              *l  = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *ls = lineGetState(l, fixture.http);
    ls->split_role          = role;

    fixtureInitializeNextForMain(&fixture, l);
    const uint32_t initial_refc = twfLineRefCount(l);

    invokeEstPauseResume(fixture.http, l);

    twfRequireEqualText(
        fixture.next_capture.events, "EUR", "an initialized HttpServer line did not preserve same-line callbacks");
    requireCallbacksOnLine(&fixture.next_capture, l, "an initialized HttpServer callback used the wrong line");
    requireLineUnchanged(l, initial_refc, "an initialized HttpServer callback changed its line");

    fixtureDestroyInitializedLine(&fixture, l);
    fixtureTeardown(&fixture);
}

static void caseFinishedNextSuppressesBackpressure(void)
{
    twfSetCase("HttpServer split next-finished backpressure suppression");

    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t              *download = fixtureCreateInitializedLine(&fixture);
    line_t              *main     = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *dls      = lineGetState(download, fixture.http);
    httpserver_lstate_t *mls      = lineGetState(main, fixture.http);
    dls->split_role               = kHttpServerSplitRoleDownload;
    dls->split_main_line          = main;
    dls->next_finished            = true;
    mls->split_role               = kHttpServerSplitRoleMain;

    fixtureInitializeNextForMain(&fixture, main);
    const uint32_t download_refc = twfLineRefCount(download);
    const uint32_t main_refc     = twfLineRefCount(main);

    httpserverTunnelUpStreamPause(fixture.http, download);
    httpserverTunnelUpStreamResume(fixture.http, download);

    requireNoNextCallbacks(&fixture.next_capture, "next_finished did not suppress split backpressure reflection");
    requireLineUnchanged(download, download_refc, "next_finished backpressure changed its transport line");
    requireLineUnchanged(main, main_refc, "next_finished backpressure changed its main line");

    fixtureDestroyInitializedLine(&fixture, download);
    fixtureDestroyInitializedLine(&fixture, main);
    fixtureTeardown(&fixture);
}

static uint32_t  waiting_bytes;
static uint32_t  waiting_depth;
static uint32_t  waiting_max_depth;
static uint32_t  waiting_nested_after;
static uint32_t  waiting_nested_length;
static bool      waiting_inject;
static tunnel_t *waiting_http;
static line_t   *waiting_upload;
static void      waitingBody(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++waiting_depth;
    waiting_max_depth = max(waiting_max_depth, waiting_depth);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
    {
        uint32_t position = waiting_bytes + i;
        bool     nested   = position >= waiting_nested_after && position - waiting_nested_after < waiting_nested_length;
        twfRequire(sbufGetMutablePtr(buf)[i] == (nested ? 'r' : 'q'), "split waiting payload changed or reordered");
    }
    waiting_bytes += sbufGetLength(buf);
    lineReuseBuffer(l, buf);
    if (waiting_inject)
    {
        waiting_inject = false;
        sbuf_t *nested = bufferpoolGetBestFit(lineGetBufferPool(waiting_upload), waiting_nested_length, 0);
        sbufSetLength(nested, waiting_nested_length);
        memorySet(sbufGetMutablePtr(nested), 'r', waiting_nested_length);
        httpserverTunnelUpStreamPayload(waiting_http, waiting_upload, nested);
    }
    --waiting_depth;
}
static void caseWaitingBoundary(uint32_t large, uint32_t length, bool append, bool bypass, bool complete_tail)
{
    g_pool_size = large;
    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_tstate_t *ts             = tunnelGetState(fixture.http);
    ts->h1_transport_mode               = kHttpServerH1TransportSplit;
    ts->split_upload_method             = (char *) "POST";
    ts->split_download_method           = (char *) "GET";
    ts->split_upload_path               = (char *) "/upload";
    ts->split_download_path             = (char *) "/download";
    ts->split_id_name                   = (char *) "id";
    ts->split_direction_name            = (char *) "direction";
    ts->split_upload_value              = (char *) "upload";
    ts->split_download_value            = (char *) "download";
    ts->status_code                     = 200;
    ts->no_split_upload_buffering_limit = bypass;
    ts->split_upload_map                = hmap_httpserver_split_t_init();
    ts->split_download_map              = hmap_httpserver_split_t_init();
    mutexInit(&ts->split_upload_map_mutex);
    mutexInit(&ts->split_download_map_mutex);
    tunnel_chain_t *chain      = tunnelchainCreate(1);
    chain->sum_line_state_size = fixture.http->lstate_size;
    tunnelchainFinalize(chain);
    fixture.http->chain      = chain;
    fixture.next->fnPayloadU = waitingBody;
    fixture.next->fnFinU     = callbackCaptureFinish;
    line_t *upload           = twfLineCreate(fixture.http->lstate_size);
    httpserverSplitUpStreamInit(fixture.http, upload);
    const uint64_t limit = httpserverSplitWaitingLimit(upload);
    sbuf_t        *data  = bufferpoolGetLargeBuffer(fixture.env.pool);
    data                 = sbufReserveSpace(data, length + 256);
    int header           = stringNPrintf((char *) sbufGetMutablePtr(data),
                               256,
                               "POST /upload?id=seven HTTP/1.1\r\nHost: example.test\r\nContent-Length: %u\r\n\r\n",
                               complete_tail ? 1 : length + 1);
    memorySet(sbufGetMutablePtr(data) + header, 'q', length);
    sbufSetLength(data, header + length);
    if (append)
    {
        sbuf_t *prefix = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufMoveTo(prefix, data, header);
        httpserverSplitUpStreamPayload(fixture.http, upload, prefix);
    }
    httpserverSplitUpStreamPayload(fixture.http, upload, data);
    if (length > limit && ! bypass)
    {
        twfRequire(fixture.prev_trace.prev_finish == 1, "split waiting overflow survived");
        twfRequireLineStateZeroed(upload, fixture.http, "split overflow retained state");
    }
    else
    {
        twfRequire(fixture.prev_trace.prev_finish == 0, "split valid header/body delivery closed");
        line_t *download = twfLineCreate(fixture.http->lstate_size);
        httpserverSplitUpStreamInit(fixture.http, download);
        const char *request = "GET /download?id=seven HTTP/1.1\r\nHost: example.test\r\n\r\n";
        sbuf_t     *peer    = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufWrite(peer, request, strlen(request));
        sbufSetLength(peer, strlen(request));
        waiting_bytes = 0;
        httpserverSplitUpStreamPayload(fixture.http, download, peer);
        twfRequire(waiting_bytes == (complete_tail ? 1 : length), "split partner arrival lost waiting data");
        httpserver_lstate_t *upload_ls = lineGetState(upload, fixture.http);
        line_t              *main_line = upload_ls->split_main_line;
        twfRequire(main_line != NULL, "split pair has no main line");
        if (complete_tail)
        {
            twfRequire(upload_ls->h1_request_finished, "pairing did not complete the short waiting body");
            twfRequire(bufferstreamGetBufLen(&upload_ls->in_stream) == 0 &&
                           bufferstreamGetCharge(&upload_ls->in_stream) == 0,
                       "pairing retained a large suffix beyond the completed request");
        }
        httpserverSplitDownStreamFinish(fixture.http, main_line);
        twfRequireLineStateZeroed(download, fixture.http, "split download retained state");
        twfLineDestroy(download);
    }
    twfLineDestroy(upload);
    hmap_httpserver_split_t_drop(&ts->split_upload_map);
    hmap_httpserver_split_t_drop(&ts->split_download_map);
    mutexDestroy(&ts->split_upload_map_mutex);
    mutexDestroy(&ts->split_download_map_mutex);
    tunnelchainDestroy(chain);
    fixtureTeardown(&fixture);
    g_pool_size = kTestLargeBufferSize;
}

static void casePairedLargeChunk(bool coalesced, bool nested_pair)
{
    twfSetCase("HttpServer paired split progressively drains a 1 GiB declared chunk");
    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_tstate_t *ts   = tunnelGetState(fixture.http);
    ts->h1_transport_mode     = kHttpServerH1TransportSplit;
    ts->split_upload_method   = (char *) "POST";
    ts->split_download_method = (char *) "GET";
    ts->split_upload_path     = (char *) "/upload";
    ts->split_download_path   = (char *) "/download";
    ts->split_id_name         = (char *) "id";
    ts->split_direction_name  = (char *) "direction";
    ts->split_upload_value    = (char *) "upload";
    ts->split_download_value  = (char *) "download";
    ts->status_code           = 200;
    ts->split_upload_map      = hmap_httpserver_split_t_init();
    ts->split_download_map    = hmap_httpserver_split_t_init();
    mutexInit(&ts->split_upload_map_mutex);
    mutexInit(&ts->split_download_map_mutex);
    tunnel_chain_t *chain      = tunnelchainCreate(1);
    chain->sum_line_state_size = fixture.http->lstate_size;
    tunnelchainFinalize(chain);
    fixture.http->chain      = chain;
    fixture.next->fnPayloadU = waitingBody;

    line_t *upload   = twfLineCreate(fixture.http->lstate_size);
    line_t *download = twfLineCreate(fixture.http->lstate_size);
    httpserverSplitUpStreamInit(fixture.http, upload);
    httpserverSplitUpStreamInit(fixture.http, download);
    waiting_bytes = waiting_depth = waiting_max_depth = 0;
    waiting_nested_after                              = nested_pair ? 32771U : 0;
    waiting_nested_length                             = nested_pair ? 131U : 0;
    waiting_inject                                    = nested_pair;
    waiting_http                                      = fixture.http;
    waiting_upload                                    = upload;
    const char *requests[]                            = {
        "POST /upload?id=large HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n40000000\r\n",
        "GET /download?id=large HTTP/1.1\r\nHost: example.test\r\n\r\n"};
    line_t *lines[] = {upload, download};
    for (unsigned i = 0; i < ARRAY_SIZE(requests); ++i)
    {
        sbuf_t *request = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufWrite(request, requests[i], strlen(requests[i]));
        sbufSetLength(request, strlen(requests[i]));
        httpserverTunnelUpStreamPayload(fixture.http, lines[i], request);
        if (i == 0 && nested_pair)
        {
            sbuf_t *body = bufferpoolGetBestFit(fixture.env.pool, waiting_nested_after, 0);
            sbufSetLength(body, waiting_nested_after);
            memorySet(sbufGetMutablePtr(body), 'q', waiting_nested_after);
            httpserverTunnelUpStreamPayload(fixture.http, upload, body);
            twfRequireEqualU32(waiting_bytes, 0, "unpaired split upload exposed its body before pairing");
        }
    }
    httpserver_lstate_t *ls        = lineGetState(upload, fixture.http);
    line_t              *main_line = ls->split_main_line;
    twfRequire(main_line != NULL, "large chunk split transport did not pair");
    const uint32_t initial = waiting_nested_after + waiting_nested_length;
    twfRequireEqualU32(waiting_bytes, initial, "pairing lost or recursively dispatched nested input");
    const uint32_t total = 4U * 1024U * 1024U;
    for (uint32_t offset = 0; offset < total;)
    {
        uint32_t length = min(total - offset, coalesced ? total : 16381U);
        sbuf_t  *body   = bufferpoolGetBestFit(fixture.env.pool, length, 0);
        sbufSetLength(body, length);
        memorySet(sbufGetMutablePtr(body), 'q', length);
        httpserverTunnelUpStreamPayload(fixture.http, upload, body);
        offset += length;
        twfRequireEqualU32(waiting_bytes, initial + offset, "paired split waited for the whole declared chunk");
        twfRequire(bufferstreamGetBufLen(&ls->in_stream) <= kHttpReceiveStreamBytes &&
                       bufferstreamGetCharge(&ls->in_stream) <= kHttpReceiveStreamCharge,
                   "paired split retained unbounded chunk input");
    }
    twfRequireEqualU32(waiting_max_depth, 1, "pair-triggered upload recursively entered body delivery");
    httpserverSplitDownStreamFinish(fixture.http, main_line);
    twfRequireLineStateZeroed(upload, fixture.http, "paired upload retained state after Finish");
    twfRequireLineStateZeroed(download, fixture.http, "paired download retained state after Finish");
    twfLineDestroy(upload);
    twfLineDestroy(download);
    hmap_httpserver_split_t_drop(&ts->split_upload_map);
    hmap_httpserver_split_t_drop(&ts->split_download_map);
    mutexDestroy(&ts->split_upload_map_mutex);
    mutexDestroy(&ts->split_download_map_mutex);
    tunnelchainDestroy(chain);
    fixtureTeardown(&fixture);
    waiting_nested_after = waiting_nested_length = 0;
    waiting_http                                 = NULL;
    waiting_upload                               = NULL;
}

typedef struct migration_capture_s
{
    tunnel_t      *http;
    line_t        *upload;
    const uint8_t *expected;
    size_t         expected_length;
    size_t         received;
    unsigned       calls;
    bool           allow_pipe;
    bool           close_first;
    bool           piped;
} migration_capture_t;

static migration_capture_t *migration_capture;

bool __wrap_pipeTo(tunnel_t *t, line_t *l, wid_t target_wid);
bool __wrap_pipeTo(tunnel_t *t, line_t *l, wid_t target_wid)
{
    twfRequire(migration_capture != NULL && t == migration_capture->http && l == migration_capture->upload &&
                   target_wid == 1,
               "unexpected split migration boundary");
    twfRequireLineStateZeroed(l, t, "migration started before retiring source HTTP state");
    migration_capture->piped = true;
    return migration_capture->allow_pipe;
}

static void migrationPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard              t;
    migration_capture_t *capture = migration_capture;
    twfRequire(capture != NULL && l == capture->upload, "migration replay used the wrong line");
    const size_t length = sbufGetLength(buf);
    twfRequire(length <= capture->expected_length - capture->received, "migration replay duplicated bytes");
    twfRequire(memcmp(sbufGetRawPtr(buf), capture->expected + capture->received, length) == 0,
               "migration replay changed prefix, active suffix or nested FIFO order");
    capture->received += length;
    ++capture->calls;
    lineReuseBuffer(l, buf);
    if (capture->close_first)
        lineDestroy(l);
}

static void caseMigrationReplay(unsigned mode)
{
    twfSetCase("HttpServer split migration preserves active and queued receive bytes");
    httpserver_split_callback_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_tstate_t *ts   = tunnelGetState(fixture.http);
    ts->h1_transport_mode     = kHttpServerH1TransportSplit;
    ts->split_upload_method   = (char *) "POST";
    ts->split_download_method = (char *) "GET";
    ts->split_upload_path     = (char *) "/upload";
    ts->split_download_path   = (char *) "/download";
    ts->split_id_name         = (char *) "id";
    ts->split_direction_name  = (char *) "direction";
    ts->split_upload_value    = (char *) "upload";
    ts->split_download_value  = (char *) "download";
    ts->split_upload_map      = hmap_httpserver_split_t_init();
    ts->split_download_map    = hmap_httpserver_split_t_init();
    mutexInit(&ts->split_upload_map_mutex);
    mutexInit(&ts->split_download_map_mutex);

    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, fixture.http->lstate_size, 4);
    line_t *upload = twfLinePoolCreateLine(&line_pool);
    lineRef(upload);
    httpserverSplitUpStreamInit(fixture.http, upload);
    line_t              *remote    = fixtureCreateInitializedLine(&fixture);
    httpserver_lstate_t *remote_ls = lineGetState(remote, fixture.http);
    remote_ls->split_role          = kHttpServerSplitRoleDownload;
    remote_ls->split_download_line = remote;
    const hash_t hash              = calcHashBytes("remote", 6);
    twfRequire(hmap_httpserver_split_t_insert(&ts->split_download_map, hash, remote_ls).inserted,
               "failed to publish remote split peer");
    /* Only the matching-map lookup observes this foreign worker identity. The
     * pipe boundary is substituted; no foreign worker state or pool is used. */
    remote->wid = 1;

    static const char request[] =
        "POST /upload?id=remote HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1073741824\r\n\r\n";
    const uint32_t body_length   = 65537;
    const uint32_t input_length  = sizeof(request) - 1 + body_length;
    const uint32_t nested_length = mode == 0 ? 0 : 19;
    uint8_t       *expected      = memoryAllocate(input_length + nested_length);
    memoryCopy(expected, request, sizeof(request) - 1);
    memorySet(expected + sizeof(request) - 1, 'q', body_length);
    memorySet(expected + input_length, 'r', nested_length);
    sbuf_t *input = bufferpoolGetBestFit(fixture.env.pool, input_length, 0);
    sbufWriteLarge(input, expected, input_length);
    sbufSetLength(input, input_length);

    migration_capture_t capture = {.http            = fixture.http,
                                   .upload          = upload,
                                   .expected        = expected,
                                   .expected_length = input_length + nested_length,
                                   .allow_pipe      = mode != 3,
                                   .close_first     = mode == 2};
    migration_capture           = &capture;
    fixture.prev->fnPayloadU    = migrationPayload;
    if (mode == 0)
        httpserverTunnelUpStreamPayload(fixture.http, upload, input);
    else
    {
        /* Exercise migration while the current delivery holds a nested budget
         * reservation and two later inputs are still queued behind its suffix. */
        httpserver_lstate_t *ls = lineGetState(upload, fixture.http);
        ls->receive.draining    = true;
        twfRequire(httpReceiveAdmit(&ls->receive, fixture.env.pool, input) == kHttpReceiveQueued,
                   "fixture nested active input was rejected");
        sbuf_t *first = httpReceiveNext(&ls->receive, fixture.env.pool);
        for (unsigned part = 0; part < 2; ++part)
        {
            const uint32_t count  = part == 0 ? 7 : 12;
            sbuf_t        *nested = bufferpoolGetSmallBuffer(fixture.env.pool);
            sbufSetLength(nested, count);
            memorySet(sbufGetMutablePtr(nested), 'r', count);
            httpserverTunnelUpStreamPayload(fixture.http, upload, nested);
        }
        httpserverSplitProcessUpStreamPayload(fixture.http, upload, first);
    }
    twfRequire(capture.piped, "coalesced split input did not request remote pairing");
    if (mode == 2)
        twfRequire(capture.calls == 1 && capture.received == kHttpReceiveSliceBytes,
                   "migration continued replay after its line closed");
    else if (mode == 3)
        twfRequire(capture.calls == 0 && fixture.prev_trace.prev_finish == 1,
                   "refused migration forwarded bytes or failed to close its source");
    else
        twfRequire(capture.received == capture.expected_length, "migration lost a coalesced or queued suffix");
    twfRequireLineStateZeroed(upload, fixture.http, "migration retained source receive state");
    migration_capture = NULL;
    memoryFree(expected);

    remote->wid = 0;
    fixtureDestroyInitializedLine(&fixture, remote);
    if (lineIsAlive(upload))
        lineDestroy(upload);
    lineUnref(upload);
    twfLinePoolTeardown(&line_pool);
    hmap_httpserver_split_t_drop(&ts->split_upload_map);
    hmap_httpserver_split_t_drop(&ts->split_download_map);
    mutexDestroy(&ts->split_upload_map_mutex);
    mutexDestroy(&ts->split_download_map_mutex);
    fixtureTeardown(&fixture);
}

int main(void)
{
    for (unsigned mode = 0; mode < 4; ++mode)
        caseMigrationReplay(mode);
    casePairedLargeChunk(false, false);
    casePairedLargeChunk(true, false);
    casePairedLargeChunk(true, true);
    const uint32_t sizes[] = {32768, 64 * 1024, SPLICE_PAYLOAD_LIMIT};
    for (unsigned i = 0; i < 2; ++i)
        for (unsigned append = 0; append < 2; ++append)
        {
            uint32_t limit = 131070 * (sizes[i] / 32768);
            caseWaitingBoundary(sizes[i], limit - 1, append, false, false);
            caseWaitingBoundary(sizes[i], limit, append, false, false);
            caseWaitingBoundary(sizes[i], limit + 1, append, false, false);
        }
    caseWaitingBoundary(SPLICE_PAYLOAD_LIMIT, SPLICE_PAYLOAD_LIMIT, false, false, false);
    caseWaitingBoundary(32768, 131071, false, true, false);
    caseWaitingBoundary(65536, 131073, false, false, true);
    caseUnpairedDownloadAbsorbsAllCallbacks();
    casePairedDownloadMapsBackpressureToMain();
    caseTransportRoleAbsorbsAllCallbacks(kHttpServerSplitRoleUnknown,
                                         "HttpServer split unknown transport callback boundary");
    caseTransportRoleAbsorbsAllCallbacks(kHttpServerSplitRoleUpload,
                                         "HttpServer split upload transport callback boundary");
    caseInitializedRoleForwardsSameLine(kHttpServerSplitRoleNone, "HttpServer single-mode callback forwarding");
    caseInitializedRoleForwardsSameLine(kHttpServerSplitRoleMain, "HttpServer split main-line callback forwarding");
    caseFinishedNextSuppressesBackpressure();
    return 0;
}

/*
 * Split HttpServer transport lines stop at HttpServer: only the paired main
 * line is initialized toward next. Upstream control callbacks must therefore
 * be absorbed on transport lines or, for a paired download, translated to the
 * initialized main line.
 */
#include "HttpServer/structure.h"

#include "tunnel_line_failure_harness.h"

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

static void fixtureSetup(httpserver_split_callback_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

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

int main(void)
{
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

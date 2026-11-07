/*
 * Covers: halfduplexclient reentrant close; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseSynchronousSiblingCloseSurvivesReentrantMainFinish, runRuntimeCase,
 * caseUploadFinishKeepsResponse
 * Checks: Assertion labels include: HalfDuplexClient finished an unexpected sibling; re-entrant main Finish
 * left HalfDuplexClient state alive; synchronous sibling close did not propagate exactly once; outer
 * frame re-finished the re-entrantly closed main line
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.halfduplexclient_reentrant_close_unit
 */
/* Synchronous sibling close may re-entrantly finish the borrowed main line. */

#include "HalfDuplexClient/structure.h"

#include "fixtures/protocols/halfduplex_splice_fixture.h"

static bool splice_inputs;

typedef struct halfduplexclient_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  line_pool;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *halfduplex;
    tunnel_t        *next;
    line_t          *main_line;
    line_t          *upload_line;
    line_t          *download_line;
} halfduplexclient_fixture_t;

static halfduplexclient_fixture_t *g_fixture;

static void nextFinishReentrantlyClosesMain(tunnel_t *next, line_t *line)
{
    halfduplexclient_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && next == fixture->next && line == fixture->upload_line,
               "HalfDuplexClient finished an unexpected sibling");
    ++fixture->trace.next_finish;
    twfRecord(&fixture->trace, 'F');

    halfduplexclientTunnelUpStreamFinish(fixture->halfduplex, fixture->main_line);
    twfRequireLineStateZeroed(
        fixture->main_line, fixture->halfduplex, "re-entrant main Finish left HalfDuplexClient state alive");
    lineDestroy(fixture->main_line);
}

static void fixtureSetup(halfduplexclient_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, 4096, 0);

    fixture->prev       = twfCreatePrevTunnel(&fixture->trace);
    fixture->halfduplex = tunnelCreate(NULL, kTunnelStateSize, kLineStateSize);
    fixture->next       = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->halfduplex != NULL, "failed to create HalfDuplexClient fixture tunnel");
    tunnelBind(fixture->prev, fixture->halfduplex);
    tunnelBind(fixture->halfduplex, fixture->next);
    fixture->next->fnFinU = nextFinishReentrantlyClosesMain;

    twfLinePoolSetup(&fixture->line_pool, fixture->halfduplex->lstate_size, 6);
    fixture->main_line     = twfLinePoolCreateLine(&fixture->line_pool);
    fixture->upload_line   = twfLinePoolCreateLine(&fixture->line_pool);
    fixture->download_line = twfLinePoolCreateLine(&fixture->line_pool);

    halfduplexclient_lstate_t *main_ls     = lineGetState(fixture->main_line, fixture->halfduplex);
    halfduplexclient_lstate_t *upload_ls   = lineGetState(fixture->upload_line, fixture->halfduplex);
    halfduplexclient_lstate_t *download_ls = lineGetState(fixture->download_line, fixture->halfduplex);
    halfduplexclientLinestateInitialize(main_ls, fixture->main_line);
    halfduplexclientLinestateInitialize(upload_ls, fixture->main_line);
    halfduplexclientLinestateInitialize(download_ls, fixture->main_line);
    main_ls->upload_line   = fixture->upload_line;
    main_ls->download_line = fixture->download_line;
    g_fixture              = fixture;
}

static void caseSynchronousSiblingCloseSurvivesReentrantMainFinish(void)
{
    twfSetCase("HalfDuplexClient synchronous sibling close survives re-entrant main Finish");
    halfduplexclient_fixture_t fixture;
    fixtureSetup(&fixture);

    lineRef(fixture.main_line);
    lineRef(fixture.upload_line);
    lineRef(fixture.download_line);
    halfduplexclientTunnelDownStreamFinish(fixture.halfduplex, fixture.download_line);

    twfRequireEqualU32(fixture.trace.next_finish, 1, "synchronous sibling close did not propagate exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "outer frame re-finished the re-entrantly closed main line");
    twfRequire(! lineIsAlive(fixture.main_line) && ! lineIsAlive(fixture.upload_line) &&
                   ! lineIsAlive(fixture.download_line),
               "HalfDuplexClient left a line logically alive after close rejection");
    twfRequireLineStateZeroed(
        fixture.upload_line, fixture.halfduplex, "rejected close left the upload sibling state alive");
    twfRequireLineStateZeroed(
        fixture.download_line, fixture.halfduplex, "rejected close left the download sibling state alive");
    twfRequireEqualU32(twfLineRefCount(fixture.main_line), 1, "main line retained an extra reference");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line), 1, "upload sibling retained an extra reference");
    twfRequireEqualU32(twfLineRefCount(fixture.download_line), 1, "download sibling retained an extra reference");

    lineUnref(fixture.download_line);
    lineUnref(fixture.upload_line);
    lineUnref(fixture.main_line);
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_pool.master), 0, "HalfDuplexClient leaked a line");

    tunnelDestroy(fixture.next);
    tunnelDestroy(fixture.halfduplex);
    tunnelDestroy(fixture.prev);
    twfLinePoolTeardown(&fixture.line_pool);
    g_fixture = NULL;
    twfWorkerEnvTeardown(&fixture.env);
}

typedef enum upload_finish_stage_e
{
    kUploadFinishAfterStartup,
    kUploadFinishDuringDownloadInit,
    kUploadFinishDuringDownloadIntro,
    kUploadFinishDuringUploadIntro
} upload_finish_stage_t;

typedef struct runtime_fixture_s
{
    twf_worker_env_t      env;
    tunnel_chain_t       *chain;
    tunnel_t             *client, *prev, *next;
    line_t               *main, *upload, *download;
    unsigned              mode, init_count, est_count, pause_count, resume_count, read_pauses, read_resumes;
    unsigned              upload_callbacks, download_callbacks, finishes;
    unsigned              owner_finishes, upload_finishes, download_finishes;
    uint8_t               upload_bytes[2 * 1024 * 1024 + 64], pair_id[kHLFDPairIdSize];
    size_t                upload_length;
    uint8_t               response[32];
    size_t                response_length;
    bool                  injected;
    bool                  keep_main_alive, finish_on_resume, retirement_case;
    upload_finish_stage_t upload_finish_stage;
} runtime_fixture_t;
static runtime_fixture_t r;

static sbuf_t *runtimePayload(const void *data, uint32_t length)
{
    return halfduplexTestBytes(r.env.pool, data, length, splice_inputs && length <= 4096, length ? 1 : 0);
}

static void runtimeOwnerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.main, "owned child Finish escaped to app owner");
    ++r.owner_finishes;
    if (! r.keep_main_alive)
        lineDestroy(l);
}
static void runtimeChildFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.upload || l == r.download, "Finish reached wrong child");
    ++r.finishes;
    if (l == r.upload)
        ++r.upload_finishes;
    else
        ++r.download_finishes;
    if (r.mode == 14 && l == r.upload && lineIsAlive(r.download))
        halfduplexclientTunnelDownStreamFinish(r.client, r.download);
}
static void runtimePause(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.main, "Pause escaped child mapping");
    ++r.pause_count;
    if ((r.mode == 8 || r.mode == 9) && ! r.injected)
    {
        r.injected = true;
        halfduplexclientTunnelUpStreamPayload(r.client, l, runtimePayload("A", 1));
        halfduplexclientTunnelUpStreamPause(r.client, l);
    }
}
static void runtimeResume(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.main, "Resume escaped child mapping");
    ++r.resume_count;
    if (r.finish_on_resume)
    {
        halfduplexclientTunnelUpStreamFinish(r.client, l);
        lineDestroy(l);
    }
}
static void runtimeReadPause(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.download, "application read Pause used uninitialized/wrong child");
    ++r.read_pauses;
}
static void runtimeReadResume(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.download, "application read Resume used uninitialized/wrong child");
    ++r.read_resumes;
}
static void runtimeEstablished(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.main && r.init_count == 2, "Est escaped before both child Init admissions");
    ++r.est_count;
    if (r.mode == 2)
    {
        halfduplexclientTunnelUpStreamFinish(r.client, l);
        lineDestroy(l);
    }
    else if (r.mode != 7 && (r.mode < 10 || r.mode == 14))
        halfduplexclientTunnelUpStreamPayload(r.client, l, runtimePayload(r.mode == 8 || r.mode == 9 ? "B" : "A", 1));
}
static void runtimeInitialize(tunnel_t *t, line_t *l)
{
    discard t;
    lineRef(l);
    ++r.init_count;
    if (r.init_count == 1)
        r.upload = l;
    else
        r.download = l;
    if (r.mode == 0 && r.init_count == 1)
    {
        halfduplexclientTunnelUpStreamPause(r.client, r.main);
        halfduplexclientTunnelUpStreamResume(r.client, r.main);
    }
    if (r.mode == 8 || r.mode == 9)
    {
        if (r.init_count == 1 || r.mode == 9)
            halfduplexclientTunnelDownStreamPause(r.client, l);
    }
    if (r.mode >= 10 && r.mode <= 13 && r.init_count == 1)
    {
        bool     entries = r.mode >= 12;
        unsigned count   = 1;
        uint32_t length  = entries ? 0 : kHalfDuplexClientMaxPendingBytes;
        uint8_t *data    = memoryAllocate(length + 1);
        memset(data, 'x', length);
        for (unsigned i = 0; i < count; ++i)
        {
            sbuf_t *pending = entries
                                  ? twfTrackAcquired(sbufCreateWithPadding(kHalfDuplexClientMaxPendingCharge - 128, 64))
                                  : runtimePayload(data, length);
            if (entries)
                sbufSetLength(pending, 0);
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, pending);
        }
        twfRequire(lineIsAlive(r.main), "exact temporary input bound refused");
        if (r.mode == 11 || r.mode == 13)
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("x", 1));
        memoryFree(data);
        if (! lineIsAlive(r.main))
            return;
    }
    if (r.mode != 7)
        halfduplexclientTunnelDownStreamEst(r.client, l);
    if (r.retirement_case && r.upload_finish_stage == kUploadFinishDuringDownloadInit && r.init_count == 2)
        halfduplexclientTunnelDownStreamFinish(r.client, r.upload);
    if ((r.mode == 3 && r.init_count == 1) || (r.mode == 4 && r.init_count == 2))
        halfduplexclientTunnelDownStreamFinish(r.client, l);
}
static void runtimeReceive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(r.init_count == 2, "pair intro sent before adjacent Init");
    if (r.upload_callbacks == 0 || l == r.download)
        twfRequire(! sbufIsSplice(buf), "intro output must be ordinary");
    buf             = halfduplexTestMaterialize(r.env.pool, buf);
    uint32_t length = sbufGetLength(buf);
    if (l == r.download)
    {
        ++r.download_callbacks;
        twfRequire(r.download_callbacks == 1 && length == kHLFDIntroSize &&
                       ((const uint8_t *) sbufGetRawPtr(buf))[0] == kHLFDCmdDownload,
                   "download intro duplicated or changed");
        memoryCopy(r.pair_id, (const uint8_t *) sbufGetRawPtr(buf) + kHLFDPairIdOffset, kHLFDPairIdSize);
    }
    else
    {
        twfRequire(l == r.upload && r.upload_length + length <= sizeof(r.upload_bytes), "upload capture overflow");
        ++r.upload_callbacks;
        memoryCopyLarge(r.upload_bytes + r.upload_length, sbufGetRawPtr(buf), length);
        r.upload_length += length;
    }
    lineReuseBuffer(l, buf);
    if (r.retirement_case)
    {
        if (r.upload_finish_stage == kUploadFinishDuringDownloadIntro && l == r.download)
            halfduplexclientTunnelDownStreamFinish(r.client, r.upload);
        if (r.upload_finish_stage == kUploadFinishDuringUploadIntro && l == r.upload)
        {
            halfduplexclientTunnelDownStreamPause(r.client, r.upload);
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("queued", 6));
            twfRequire(bufferqueueGetEntryCount(
                           &((halfduplexclient_lstate_t *) lineGetState(r.main, r.client))->pending_up) == 1,
                       "intro reentry did not retain the pending upload");
            halfduplexclientTunnelDownStreamFinish(r.client, r.upload);
        }
    }
    if (l == r.download)
    {
        if (r.mode == 1)
        {
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("B", 1));
            halfduplexclientTunnelDownStreamPause(r.client, r.upload);
        }
        if (r.mode == 5)
            halfduplexclientTunnelDownStreamFinish(r.client, l);
        if (r.mode == 6)
        {
            halfduplexclientTunnelUpStreamFinish(r.client, r.main);
            lineDestroy(r.main);
        }
    }
}

static void runtimeResponse(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(l == r.main, "download response escaped the main line");
    buf                   = halfduplexTestMaterialize(r.env.pool, buf);
    const uint32_t length = sbufGetLength(buf);
    twfRequire(r.response_length + length <= sizeof(r.response), "download response capture overflow");
    memoryCopy(r.response + r.response_length, sbufGetRawPtr(buf), length);
    r.response_length += length;
    lineReuseBuffer(l, buf);
}

static void runtimeSetup(void)
{
    twfWorkerEnvSetup(&r.env, 4096, 64);
    r.client = halfduplexclientTunnelCreate(NULL);
    r.prev   = tunnelCreate(NULL, 0, 0);
    r.next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(r.prev, r.client);
    tunnelBind(r.client, r.next);
    r.prev->fnFinD               = runtimeOwnerFinish;
    r.prev->fnPayloadD           = runtimeResponse;
    r.prev->fnEstD               = runtimeEstablished;
    r.prev->fnPauseD             = runtimePause;
    r.prev->fnResumeD            = runtimeResume;
    r.next->fnInitU              = runtimeInitialize;
    r.next->fnFinU               = runtimeChildFinish;
    r.next->fnPayloadU           = runtimeReceive;
    r.next->fnPauseU             = runtimeReadPause;
    r.next->fnResumeU            = runtimeReadResume;
    r.chain                      = tunnelchainCreate(1);
    r.chain->sum_line_state_size = r.client->lstate_size;
    tunnelchainFinalize(r.chain);
    r.client->chain = r.chain;
    r.main          = lineCreate(tunnelchainGetLinePools(r.chain), 0);
    lineRef(r.main);
    halfduplexclientTunnelUpStreamInit(r.client, r.main);
}

static void runtimeTeardown(void)
{
    twfRequireLineStateZeroed(r.main, r.client, "main state survived close");
    lineUnref(r.main);
    twfRequireLineStateZeroed(r.upload, r.client, "upload state survived close");
    lineUnref(r.upload);
    if (r.download != NULL)
    {
        twfRequireLineStateZeroed(r.download, r.client, "download state survived close");
        lineUnref(r.download);
    }
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(r.chain);
    tunnelDestroy(r.next);
    tunnelDestroy(r.prev);
    tunnelDestroy(r.client);
    twfWorkerEnvTeardown(&r.env);
}

static void runRuntimeCase(unsigned mode)
{
    twfSetCase("HalfDuplex exact pair Init/Est publication, FIFO and terminal ownership");
    memoryZero(&r, sizeof(r));
    r.mode = mode;
    runtimeSetup();
    if (mode == 15)
    {
        // No headroom forces the checked framing path. Its synthetic length
        // must be rejected before allocating or accessing any body bytes.
        sbuf_t *input = twfTrackAcquired(sbufCreateWithPadding(0, 0));
        input->len    = UINT32_MAX;
        halfduplexclientTunnelUpStreamPayload(r.client, r.main, input);
    }
    bool closes = (mode >= 2 && mode <= 6) || mode == 11 || mode == 13 || mode == 15;
    if (closes)
    {
        twfRequire(! lineIsAlive(r.main) && ! lineIsAlive(r.upload) &&
                       (r.download == NULL || ! lineIsAlive(r.download)),
                   "Init/intro Finish leaked an owned line");
        if (mode == 3 || mode == 4)
            twfRequire(r.est_count == 0, "closed Init emitted mapped Est");
        twfRequire(r.upload_length == 0, "terminal intro callback emitted later upload bytes");
    }
    else
    {
        if (mode == 0)
        {
            twfRequire(r.read_pauses == 0 && r.read_resumes == 0, "canceled pre-child Pause was replayed after Init");
            halfduplexclientTunnelUpStreamPause(r.client, r.main);
            halfduplexclientTunnelUpStreamPause(r.client, r.main);
            halfduplexclientTunnelUpStreamResume(r.client, r.main);
            halfduplexclientTunnelUpStreamResume(r.client, r.main);
            twfRequire(r.read_pauses == 2 && r.read_resumes == 2,
                       "application read notifications were filtered after child Init");
        }
        if (mode == 7)
        {
            twfRequire(r.est_count == 0, "pair fabricated Est");
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("A", 1));
        }
        if (mode == 8 || mode == 9)
        {
            twfRequire(r.upload_length == 0 && r.est_count == 1 && r.read_pauses == 1,
                       "Init backlog drained through Pause or lost pending read Pause");
            halfduplexclientTunnelDownStreamResume(r.client, r.upload);
            if (mode == 9)
            {
                twfRequire(r.upload_length == 0 && r.resume_count == 0, "one child Resume cleared sibling pressure");
                halfduplexclientTunnelDownStreamResume(r.client, r.download);
            }
        }
        halfduplexclientTunnelDownStreamEst(r.client, r.upload);
        halfduplexclientTunnelDownStreamEst(r.client, r.download);
        twfRequire(r.est_count == 1, "child duplicate Est escaped without lineMarkEstablished");
        twfRequire(r.download_callbacks == 1 && r.upload_length >= kHLFDIntroSize &&
                       r.upload_bytes[0] == kHLFDCmdUpload &&
                       memoryEqual(r.upload_bytes + kHLFDPairIdOffset, r.pair_id, kHLFDPairIdSize),
                   "pair IDs changed");
        if (mode < 10 || mode == 14)
        {
            const char *body = mode == 1 || mode == 8 || mode == 9 ? "AB" : "A";
            twfRequire(r.upload_length == kHLFDIntroSize + strlen(body) &&
                           memoryEqual(r.upload_bytes + kHLFDIntroSize, body, strlen(body)),
                       "intro reentry lost FIFO");
        }
        if (mode == 10)
            twfRequire(r.upload_length == kHalfDuplexClientMaxPendingBytes + kHLFDIntroSize &&
                           r.upload_bytes[r.upload_length - 1] == 'x',
                       "exact temporary byte limit truncated input");
        if (mode == 1)
            twfRequire(bufferqueueGetEntryCount(
                           &((halfduplexclient_lstate_t *) lineGetState(r.main, r.client))->pending_up) == 0,
                       "first-intro nested batch stranded behind Pause");
        if (mode == 12)
            twfRequire(r.upload_callbacks == 1, "temporary charge equality lost empty admitted inputs");
        halfduplexclientTunnelUpStreamFinish(r.client, r.main);
        lineDestroy(r.main);
    }
    runtimeTeardown();
}

static void caseUploadFinishKeepsResponse(upload_finish_stage_t stage, bool hold_download, bool finish_on_resume,
                                          bool keep_main_alive)
{
    twfSetCase(stage == kUploadFinishDuringDownloadInit    ? "HalfDuplex upload Finish during download Init"
               : stage == kUploadFinishDuringDownloadIntro ? "HalfDuplex upload Finish before upload intro"
               : stage == kUploadFinishDuringUploadIntro   ? "HalfDuplex upload Finish during upload intro"
               : finish_on_resume                          ? "HalfDuplex upload retirement Resume closes application"
               : hold_download                             ? "HalfDuplex upload retirement preserves download Pause"
               : keep_main_alive                           ? "HalfDuplex response tail with borrowed main retained"
                                                           : "HalfDuplex upload-first Finish preserves response tail");
    memoryZero(&r, sizeof(r));
    r.mode                = 16; // Establish both children without injecting application input.
    r.retirement_case     = true;
    r.upload_finish_stage = stage;
    r.finish_on_resume    = finish_on_resume;
    r.keep_main_alive     = keep_main_alive;
    runtimeSetup();

    static const uint8_t prefix[]   = {'p', 0, 'r', 'e'};
    static const uint8_t tail[]     = {'t', 'a', 0, 'i', 'l'};
    static const uint8_t expected[] = {'p', 0, 'r', 'e', 't', 'a', 0, 'i', 'l'};
    if (stage != kUploadFinishDuringDownloadInit)
        halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("A", 1));

    if (stage == kUploadFinishDuringDownloadInit || stage == kUploadFinishDuringDownloadIntro)
    {
        twfRequire(! lineIsAlive(r.main) && ! lineIsAlive(r.upload) && ! lineIsAlive(r.download),
                   "upload loss before publication left an incomplete pair alive");
        twfRequireEqualU32(r.init_count, 2, "startup upload loss skipped adjacent download Init");
        twfRequireEqualU32(r.upload_callbacks, 0, "startup sent an intro after upload Finish");
        twfRequireEqualU32(r.download_callbacks,
                           stage == kUploadFinishDuringDownloadIntro ? 1 : 0,
                           "startup upload loss emitted unexpected download output");
        if (stage == kUploadFinishDuringDownloadInit)
            twfRequireEqualU32(r.est_count, 0, "startup upload loss emitted application Est");
        twfRequireEqualU32(r.owner_finishes, 1, "startup upload loss did not finish main exactly once");
        twfRequireEqualU32(r.download_finishes, 1, "startup upload loss did not close download exactly once");
    }
    else
    {
        if (stage == kUploadFinishAfterStartup)
        {
            halfduplexclientTunnelDownStreamPayload(r.client, r.download, runtimePayload(prefix, sizeof(prefix)));
            halfduplexclientTunnelDownStreamPause(r.client, r.upload);
            if (hold_download)
                halfduplexclientTunnelDownStreamPause(r.client, r.download);
            halfduplexclientTunnelDownStreamFinish(r.client, r.upload);
        }
        twfRequire(! lineIsAlive(r.upload), "upload Finish retained its owned transport");
        if (! finish_on_resume)
            twfRequire(lineIsAlive(r.main) && lineIsAlive(r.download),
                       "upload Finish closed download before the response tail arrived");
        twfRequireEqualU32(r.pause_count, 1, "upload pressure was not mapped to main exactly once");
        twfRequireEqualU32(
            r.resume_count, hold_download ? 0 : 1, "upload retirement did not reconcile aggregate producer pressure");
        if (finish_on_resume)
        {
            twfRequire(! lineIsAlive(r.main) && ! lineIsAlive(r.download),
                       "application Finish during retirement Resume retained the pair");
            twfRequireEqualU32(r.owner_finishes, 0, "retirement reflected Finish toward the closing application");
            twfRequireEqualU32(r.download_finishes, 1, "reentrant application Finish did not close download once");
        }
        else
        {
            twfRequireEqualU32(r.owner_finishes, 0, "upload Finish prematurely finished the application");
            twfRequireEqualU32(r.download_finishes, 0, "upload Finish prematurely closed download");
            halfduplexclient_lstate_t *ls = lineGetState(r.main, r.client);
            twfRequire(ls->upload_line == NULL, "retired upload remained attached to main");
            twfRequire(bufferqueueGetEntryCount(&ls->pending_up) == 0,
                       "upload retirement retained queued application input");
            const unsigned upload_callbacks = r.upload_callbacks;
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("late", 4));
            twfRequireEqualU32(r.upload_callbacks, upload_callbacks, "late application payload reached retired upload");
            twfRequire(bufferqueueGetEntryCount(&ls->pending_up) == 0,
                       "late application payload was queued after upload retirement");
            halfduplexclientTunnelUpStreamPause(r.client, r.main);
            halfduplexclientTunnelUpStreamResume(r.client, r.main);
            twfRequireEqualU32(r.read_pauses, 1, "application Pause lost the surviving download mapping");
            twfRequireEqualU32(r.read_resumes, 1, "application Resume lost the surviving download mapping");
            if (hold_download)
            {
                halfduplexclientTunnelDownStreamResume(r.client, r.download);
                twfRequireEqualU32(r.resume_count, 1, "download Resume stranded main after upload retirement");
            }
            if (stage == kUploadFinishDuringUploadIntro)
                halfduplexclientTunnelDownStreamPayload(r.client, r.download, runtimePayload(prefix, sizeof(prefix)));
            halfduplexclientTunnelDownStreamPayload(r.client, r.download, runtimePayload(tail, sizeof(tail)));
            twfRequire(r.response_length == sizeof(expected) && memoryEqual(r.response, expected, sizeof(expected)),
                       "upload-first Finish truncated or changed the exact response bytes");
            halfduplexclientTunnelDownStreamFinish(r.client, r.download);
            twfRequireEqualU32(r.owner_finishes, 1, "download Finish did not finish main exactly once");
            twfRequireEqualU32(r.download_finishes, 0, "download Finish was reflected toward its sender");
            twfRequire(lineIsAlive(r.main) == keep_main_alive, "download Finish violated borrowed main ownership");
            if (keep_main_alive)
            {
                twfRequireLineStateZeroed(r.main, r.client, "download Finish retained borrowed main state");
                lineDestroy(r.main);
            }
        }
    }
    twfRequireEqualU32(r.upload_finishes, 0, "upload Finish was reflected toward its sender");
    twfRequireEqualU32(twfLineRefCount(r.main), 1, "upload retirement leaked a main reference");
    twfRequireEqualU32(twfLineRefCount(r.upload), 1, "upload retirement leaked an upload reference");
    twfRequireEqualU32(twfLineRefCount(r.download), 1, "upload retirement leaked a download reference");
    runtimeTeardown();
}

static void runUploadFinishCases(void)
{
    caseUploadFinishKeepsResponse(kUploadFinishAfterStartup, false, false, false);
    caseUploadFinishKeepsResponse(kUploadFinishAfterStartup, false, false, true);
    caseUploadFinishKeepsResponse(kUploadFinishAfterStartup, true, false, false);
    caseUploadFinishKeepsResponse(kUploadFinishAfterStartup, false, true, false);
    caseUploadFinishKeepsResponse(kUploadFinishDuringDownloadInit, false, false, false);
    caseUploadFinishKeepsResponse(kUploadFinishDuringDownloadIntro, false, false, false);
    caseUploadFinishKeepsResponse(kUploadFinishDuringUploadIntro, false, false, false);
    caseUploadFinishKeepsResponse(kUploadFinishDuringUploadIntro, false, true, false);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    for (unsigned mode = 0; mode < 16; ++mode)
        runRuntimeCase(mode);
    runUploadFinishCases();
#if WW_HAVE_SPLICE
    splice_inputs = true;
    for (unsigned mode = 0; mode < 16; ++mode)
        runRuntimeCase(mode);
    runUploadFinishCases();
#endif
    caseSynchronousSiblingCloseSurvivesReentrantMainFinish();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("halfduplexclient_reentrant_close_test: all cases passed");
    return 0;
}

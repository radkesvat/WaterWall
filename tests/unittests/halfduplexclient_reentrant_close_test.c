/* Synchronous sibling close may re-entrantly finish the borrowed main line. */

#include "HalfDuplexClient/structure.h"

#define __wrap_bufferpoolTryGetBestFit trackedTryGetBestFit
#include "halfduplex_splice_fixture.h"
#undef __wrap_bufferpoolTryGetBestFit

static unsigned allocation_countdown;
sbuf_t         *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding);
sbuf_t         *__wrap_bufferpoolTryGetBestFit(buffer_pool_t *pool, uint64_t size, uint16_t padding)
{
    if (allocation_countdown && --allocation_countdown == 0)
        return NULL;
    return trackedTryGetBestFit(pool, size, padding);
}

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
    main_ls->upload_line       = fixture->upload_line;
    main_ls->download_line     = fixture->download_line;
    upload_ls->upload_line     = fixture->upload_line;
    upload_ls->download_line   = fixture->download_line;
    download_ls->upload_line   = fixture->upload_line;
    download_ls->download_line = fixture->download_line;
    upload_ls->next_started = download_ls->next_started = true;
    g_fixture                                           = fixture;
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

typedef struct runtime_fixture_s
{
    twf_worker_env_t env;
    tunnel_chain_t  *chain;
    tunnel_t        *client, *prev, *next;
    line_t          *main, *upload, *download;
    unsigned         mode, init_count, est_count, pause_count, resume_count, read_pauses;
    unsigned         upload_callbacks, download_callbacks, finishes;
    uint8_t          upload_bytes[2 * 1024 * 1024 + 64], pair_id[kHLFDPairIdSize];
    size_t           upload_length;
    bool             injected;
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
    lineDestroy(l);
}
static void runtimeChildFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.upload || l == r.download, "Finish reached wrong child");
    ++r.finishes;
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
}
static void runtimeReadPause(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == r.download, "application read Pause used uninitialized/wrong child");
    ++r.read_pauses;
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
    if (r.mode == 8 || r.mode == 9)
    {
        if (r.init_count == 1 || r.mode == 9)
            halfduplexclientTunnelDownStreamPause(r.client, l);
    }
    if (r.mode >= 10 && r.mode <= 13 && r.init_count == 1)
    {
        bool     entries = r.mode >= 12;
        unsigned count   = entries ? kHalfDuplexClientMaxPendingBuffers : 1;
        uint32_t length  = entries ? 0 : kHalfDuplexClientMaxPendingBytes;
        uint8_t *data    = memoryAllocate(length + 1);
        memset(data, 'x', length);
        for (unsigned i = 0; i < count; ++i)
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload(data, length));
        twfRequire(lineIsAlive(r.main), "exact temporary input bound refused");
        if (r.mode == 11 || r.mode == 13)
            halfduplexclientTunnelUpStreamPayload(r.client, r.main, runtimePayload("x", 1));
        memoryFree(data);
        if (! lineIsAlive(r.main))
            return;
    }
    if (r.mode != 7)
        halfduplexclientTunnelDownStreamEst(r.client, l);
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

static void runRuntimeCase(unsigned mode)
{
    twfSetCase("HalfDuplex exact pair Init/Est publication, FIFO and terminal ownership");
    memoryZero(&r, sizeof(r));
    r.mode = mode;
    twfWorkerEnvSetup(&r.env, 4096, 64);
    r.client = halfduplexclientTunnelCreate(NULL);
    r.prev   = tunnelCreate(NULL, 0, 0);
    r.next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(r.prev, r.client);
    tunnelBind(r.client, r.next);
    r.prev->fnFinD               = runtimeOwnerFinish;
    r.prev->fnEstD               = runtimeEstablished;
    r.prev->fnPauseD             = runtimePause;
    r.prev->fnResumeD            = runtimeResume;
    r.next->fnInitU              = runtimeInitialize;
    r.next->fnFinU               = runtimeChildFinish;
    r.next->fnPayloadU           = runtimeReceive;
    r.next->fnPauseU             = runtimeReadPause;
    r.chain                      = tunnelchainCreate(1);
    r.chain->sum_line_state_size = r.client->lstate_size;
    tunnelchainFinalize(r.chain);
    r.client->chain = r.chain;
    r.main          = lineCreate(tunnelchainGetLinePools(r.chain), 0);
    lineRef(r.main);
    halfduplexclientTunnelUpStreamInit(r.client, r.main);
    if (mode >= 15)
    {
        sbuf_t *input = runtimePayload("failure", 7);
        if (mode == 17)
        {
            // Ordinary synthetic length exercises refusal before any body read.
            if (sbufIsSplice(input))
                input = halfduplexTestMaterialize(r.env.pool, input);
            input->len = UINT32_MAX;
        }
        else
            allocation_countdown = mode - 14;
        halfduplexclientTunnelUpStreamPayload(r.client, r.main, input);
    }
    bool closes = (mode >= 2 && mode <= 6) || mode == 11 || mode == 13 || mode >= 15;
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
            twfRequire(bufferqueueGetBufCount(
                           &((halfduplexclient_lstate_t *) lineGetState(r.main, r.client))->pending_up) == 0,
                       "first-intro nested batch stranded behind Pause");
        if (mode == 12)
            twfRequire(r.upload_callbacks == 1024, "temporary entry equality lost empty admitted inputs");
        halfduplexclientTunnelUpStreamFinish(r.client, r.main);
        lineDestroy(r.main);
    }
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

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    for (unsigned mode = 0; mode < 18; ++mode)
        runRuntimeCase(mode);
#if WW_HAVE_SPLICE
    splice_inputs = true;
    for (unsigned mode = 0; mode < 18; ++mode)
        runRuntimeCase(mode);
#endif
    caseSynchronousSiblingCloseSurvivesReentrantMainFinish();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("halfduplexclient_reentrant_close_test: all cases passed");
    return 0;
}

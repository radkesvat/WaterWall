/*
 * HalfDuplexServer reconstructs one owned main line from borrowed upload and
 * download transports. The next tunnel may reject the main line synchronously
 * from Init, which closes the download transport before the pairing callback
 * resumes. Both transports must remain allocated across that callback, and the
 * pending upload buffer must be returned through a buffer pool captured before
 * re-entry.
 */
#include "HalfDuplexServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096,
    kIntroSize           = sizeof(uint64_t)
};

typedef struct halfduplexserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *halfduplex;
    tunnel_t        *next;
    line_t          *upload_line;
    line_t          *download_line;
    line_t          *replacement_line;
    buffer_pool_t   *unavailable_pool_shortcut[1];
    uint32_t         scheduled_closes;
    bool             buffer_shortcut_hidden;
    bool             refuse_scheduled_closes;
    bool             closed_upload_ref_held;
    bool             scheduled_upload_ref_held;
} halfduplexserver_fixture_t;

static halfduplexserver_fixture_t *g_fixture = NULL;

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    discard task;
    discard t;

    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "HalfDuplexServer scheduled a close outside the active fixture");
    twfRequire(line == fixture->upload_line, "HalfDuplexServer scheduled the wrong transport for closure");
    twfRequireEqualU32(
        twfLineRefCount(line), 3, "the upload transport was not retained across the re-entrant main Init");
    twfRequire(on_cancel == NULL, "HalfDuplexServer unexpectedly requested cancellation notification");
    ++fixture->scheduled_closes;
    lineRef(line);
    if (fixture->refuse_scheduled_closes)
    {
        lineUnref(line);
        return kLineTaskSubmitRejectedSettled;
    }
    fixture->scheduled_upload_ref_held = true;
    return kLineTaskSubmitAcceptedAsync;
}

static void transportOwnerDownstreamFinish(tunnel_t *prev, line_t *line)
{
    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "the transport owner ran outside the active fixture");
    twfRequire(prev == fixture->prev, "the wrong previous tunnel received the transport Finish");
    twfRequire(line == fixture->download_line || line == fixture->upload_line,
               "HalfDuplexServer finished an untracked transport synchronously");

    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');

    if (line == fixture->upload_line)
    {
        twfRequire(fixture->refuse_scheduled_closes,
                   "HalfDuplexServer closed the upload transport after successful task admission");
        lineRef(line);
        fixture->closed_upload_ref_held = true;
        lineDestroy(line);
        return;
    }

    twfRequireEqualU32(
        twfLineRefCount(line), 3, "the download transport was not retained across the re-entrant main Init");
    lineDestroy(line);
    twfRequire(! lineIsAlive(line), "the synthetic transport owner did not destroy the download line");

    fixture->replacement_line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    twfRequire(fixture->replacement_line != line,
               "the download allocation was released and reused while main Init was still active");

    /*
     * Any cleanup that resolves the pool through either transport after Init
     * returns will now fail. The pending buffer can only be recycled through
     * the pool pointer captured before the nested callback.
     */
    GSTATE.shortcut_buffer_pools    = fixture->unavailable_pool_shortcut;
    fixture->buffer_shortcut_hidden = true;
}

static void rejectMainLineInit(tunnel_t *next, line_t *main_line)
{
    halfduplexserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL, "the rejecting tunnel ran outside the active fixture");
    twfRequire(next == fixture->next, "the wrong next tunnel received main Init");

    ++fixture->trace.next_init;
    twfRecord(&fixture->trace, 'I');

    halfduplexserver_lstate_t *main_ls = lineGetState(main_line, fixture->halfduplex);
    twfRequire(main_ls->upload_line == fixture->upload_line, "main Init referenced the wrong upload transport");
    twfRequire(main_ls->download_line == fixture->download_line, "main Init referenced the wrong download transport");
    twfRequireEqualU32(
        twfLineRefCount(fixture->upload_line), 2, "the upload transport reference was not held before main Init");
    twfRequireEqualU32(
        twfLineRefCount(fixture->download_line), 2, "the download transport reference was not held before main Init");

    halfduplexserverTunnelDownStreamFinish(fixture->halfduplex, main_line);
    twfRequire(! lineIsAlive(main_line), "rejected main Init did not destroy the owned main line");
}

static void fixtureSetup(halfduplexserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev       = twfCreatePrevTunnel(&fixture->trace);
    fixture->halfduplex = tunnelCreate(NULL, sizeof(halfduplexserver_tstate_t), sizeof(halfduplexserver_lstate_t));
    fixture->next       = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->halfduplex != NULL, "failed to create the HalfDuplexServer tunnel");

    halfduplexserver_tstate_t *ts = tunnelGetState(fixture->halfduplex);
    mutexInit(&ts->upload_line_map_mutex);
    mutexInit(&ts->download_line_map_mutex);
    ts->upload_line_map   = hmap_cons_t_with_capacity(kHmapCap);
    ts->download_line_map = hmap_cons_t_with_capacity(kHmapCap);

    tunnelBind(fixture->prev, fixture->halfduplex);
    tunnelBind(fixture->halfduplex, fixture->next);
    fixture->prev->fnFinD  = transportOwnerDownstreamFinish;
    fixture->next->fnInitU = rejectMainLineInit;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->halfduplex->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->halfduplex->chain = fixture->chain;

    g_fixture = fixture;
}

static line_t *createTransportLine(halfduplexserver_fixture_t *fixture)
{
    line_t *line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    halfduplexserverTunnelUpStreamInit(fixture->halfduplex, line);
    return line;
}

static sbuf_t *createIntroBuffer(halfduplexserver_fixture_t *fixture, bool upload)
{
    uint8_t intro[kIntroSize] = {0x25, 0x11, 0x42, 0x73, 0x19, 0xA4, 0xC8, 0x5E};
    if (! upload)
    {
        intro[0] |= kHLFDCmdDownload;
    }

    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, sizeof(intro));
    sbufWrite(buf, intro, sizeof(intro));
    return buf;
}

static void sendIntro(halfduplexserver_fixture_t *fixture, line_t *line, bool upload)
{
    halfduplexserverTunnelUpStreamPayload(fixture->halfduplex, line, createIntroBuffer(fixture, upload));
}

static void fixtureTeardown(halfduplexserver_fixture_t *fixture)
{
    if (fixture->buffer_shortcut_hidden)
    {
        GSTATE.shortcut_buffer_pools    = fixture->env.pool_shortcut;
        fixture->buffer_shortcut_hidden = false;
    }

    /* Model quiescence cancellation of the accepted close before owner drain. */
    if (fixture->scheduled_upload_ref_held)
    {
        lineUnref(fixture->upload_line);
        fixture->scheduled_upload_ref_held = false;
    }
    if (fixture->upload_line != NULL && lineIsAlive(fixture->upload_line))
    {
        halfduplexserverTunnelUpStreamFinish(fixture->halfduplex, fixture->upload_line);
        lineDestroy(fixture->upload_line);
    }
    if (fixture->closed_upload_ref_held)
    {
        lineUnref(fixture->upload_line);
        fixture->closed_upload_ref_held = false;
    }
    if (fixture->replacement_line != NULL && lineIsAlive(fixture->replacement_line))
    {
        lineDestroy(fixture->replacement_line);
    }

    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->next);
    halfduplexserverTunnelDestroy(fixture->halfduplex, wwLifecycleStartupRollback());
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
}

static void runRejectedPairingCase(bool upload_first, bool refuse_scheduled_close)
{
    twfSetCase(refuse_scheduled_close
                   ? (upload_first ? "HalfDuplexServer upload-first rejected main Init and close task"
                                   : "HalfDuplexServer download-first rejected main Init and close task")
                   : (upload_first ? "HalfDuplexServer upload-first rejected main Init"
                                   : "HalfDuplexServer download-first rejected main Init"));

    halfduplexserver_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.refuse_scheduled_closes = refuse_scheduled_close;

    if (upload_first)
    {
        fixture.upload_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.upload_line, true);
        fixture.download_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.download_line, false);
    }
    else
    {
        fixture.download_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.download_line, false);
        fixture.upload_line = createTransportLine(&fixture);
        sendIntro(&fixture, fixture.upload_line, true);
    }

    twfRequire(fixture.buffer_shortcut_hidden, "the synchronous transport owner did not run");
    GSTATE.shortcut_buffer_pools   = fixture.env.pool_shortcut;
    fixture.buffer_shortcut_hidden = false;

    twfRequireEqualText(fixture.trace.seq,
                        refuse_scheduled_close ? "eeIff" : "eeIf",
                        "unexpected callback order during rejected main Init");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the reconstructed main line was not initialized exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish,
                       refuse_scheduled_close ? 2 : 1,
                       "the required transports were not synchronously finished exactly once");
    twfRequireEqualU32(fixture.scheduled_closes, 1, "the upload transport close was not scheduled exactly once");
    twfRequireEqualU32(twfRecycleCount(), 2, "the two intro buffers were not recycled exactly once");
    twfRequire(lineIsAlive(fixture.upload_line) != refuse_scheduled_close,
               "the upload transport had the wrong logical-life result after task admission");
    twfRequireEqualU32(twfLineRefCount(fixture.upload_line),
                       refuse_scheduled_close ? 1 : 2,
                       "HalfDuplexServer leaked its upload transport reference");

    fixtureTeardown(&fixture);
}

int main(void)
{
    runRejectedPairingCase(true, false);
    runRejectedPairingCase(false, false);
    runRejectedPairingCase(true, true);
    runRejectedPairingCase(false, true);

    printf("halfduplexserver_reentrant_init_test: all cases passed\n");
    return 0;
}

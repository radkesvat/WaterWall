/* Rejected sibling close may re-entrantly finish the borrowed main line. */

#include "HalfDuplexClient/structure.h"

#include "tunnel_line_failure_harness.h"

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
    uint32_t         scheduled_closes;
} halfduplexclient_fixture_t;

static halfduplexclient_fixture_t *g_fixture;

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    discard                     task;
    halfduplexclient_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && line == fixture->upload_line && t == fixture->halfduplex,
               "HalfDuplexClient scheduled the wrong sibling close");
    twfRequire(on_cancel == NULL, "HalfDuplexClient unexpectedly requested cancellation notification");

    lineRef(line);
    lineUnref(line);
    ++fixture->scheduled_closes;
    return kLineTaskSubmitRejectedSettled;
}

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
    g_fixture                  = fixture;
}

static void caseRejectedSiblingCloseSurvivesReentrantMainFinish(void)
{
    twfSetCase("HalfDuplexClient rejected sibling close survives re-entrant main Finish");
    halfduplexclient_fixture_t fixture;
    fixtureSetup(&fixture);

    lineRef(fixture.main_line);
    lineRef(fixture.upload_line);
    lineRef(fixture.download_line);
    halfduplexclientTunnelDownStreamFinish(fixture.halfduplex, fixture.download_line);

    twfRequireEqualU32(fixture.scheduled_closes, 1, "HalfDuplexClient did not submit exactly one sibling close");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "rejected sibling close did not propagate exactly once");
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

int main(void)
{
    caseRejectedSiblingCloseSurvivesReentrantMainFinish();
    puts("halfduplexclient_reentrant_close_test: all cases passed");
    return 0;
}

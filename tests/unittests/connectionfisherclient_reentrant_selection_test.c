/*
 * ConnectionFisherClient cross-line selection lifetime coverage.
 *
 * Closing one losing child calls into the shared next-side tunnel.  That
 * tunnel may synchronously finish a different child; every pointer retained in
 * the selection snapshot must therefore carry its own physical line reference.
 */
#include "ConnectionFisherClient/structure.h"

#include "ev_memory.h"
#include "tunnel_line_failure_harness.h"

enum
{
    kConnectionFisherSelectionLargeBuffer = 8192,
    kConnectionFisherSelectionLineCap     = 8,
    kConnectionFisherSelectionChildCount  = 3,
};

typedef struct connectionfisher_selection_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *fisher;
    tunnel_t        *next;
    line_t          *main_line;
    line_t          *selected_child;
    line_t          *first_loser;
    line_t          *reentrant_loser;
    line_t          *reentrant_target;
    uint32_t         reentrant_target_refcount;
    bool             reentered;
} connectionfisher_selection_fixture_t;

static connectionfisher_selection_fixture_t *fixtureFromNext(tunnel_t *t)
{
    return *(connectionfisher_selection_fixture_t **) tunnelGetState(t);
}

static void reentrantNextFinish(tunnel_t *t, line_t *l)
{
    connectionfisher_selection_fixture_t *fixture = fixtureFromNext(t);

    if (l != fixture->first_loser || fixture->reentered)
    {
        return;
    }

    fixture->reentered                 = true;
    fixture->reentrant_target_refcount = twfLineRefCount(fixture->reentrant_target);

    /* This is not Finish reflection: the next-side tunnel received Finish for
     * first_loser and independently closes a different line it also owns
     * state for. */
    tunnelPrevDownStreamFinish(t, fixture->reentrant_target);
}

static void ownerPrevFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}

static void initializeChild(connectionfisher_selection_fixture_t *fixture, line_t *child, uint32_t slot)
{
    connectionfisherclient_lstate_t *main_ls  = lineGetState(fixture->main_line, fixture->fisher);
    connectionfisherclient_lstate_t *child_ls = lineGetState(child, fixture->fisher);

    connectionfisherclientLinestateInitializeChild(child_ls, child, fixture->main_line, slot);
    main_ls->child_lines[slot] = child;
    ++main_ls->open_child_count;
}

static void fixtureSetup(connectionfisher_selection_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfSetCase("connectionfisher selection retains every child across cross-line Finish");
    twfWorkerEnvSetup(&fixture->env, kConnectionFisherSelectionLargeBuffer, 0);
    twfLinePoolSetup(&fixture->lines,
                     tunnelGetCorrectAlignedLineStateSize(sizeof(connectionfisherclient_lstate_t)),
                     kConnectionFisherSelectionLineCap);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->fisher =
        tunnelCreate(NULL, sizeof(connectionfisherclient_tstate_t), sizeof(connectionfisherclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(connectionfisher_selection_fixture_t *), 0);
    twfRequire(fixture->fisher != NULL && fixture->next != NULL, "failed to create selection fixture tunnels");

    *(connectionfisher_selection_fixture_t **) tunnelGetState(fixture->next) = fixture;
    fixture->next->fnFinU                                                    = reentrantNextFinish;
    fixture->fisher->fnFinD = connectionfisherclientTunnelDownStreamFinish;
    tunnelBind(fixture->prev, fixture->fisher);
    tunnelBind(fixture->fisher, fixture->next);

    fixture->main_line        = twfLinePoolCreateLine(&fixture->lines);
    fixture->selected_child   = twfLinePoolCreateLine(&fixture->lines);
    fixture->first_loser      = twfLinePoolCreateLine(&fixture->lines);
    fixture->reentrant_loser  = twfLinePoolCreateLine(&fixture->lines);
    fixture->reentrant_target = fixture->reentrant_loser;

    connectionfisherclient_lstate_t *main_ls = lineGetState(fixture->main_line, fixture->fisher);
    twfRequire(connectionfisherclientLinestateInitializeMain(
                   main_ls, fixture->main_line, kConnectionFisherSelectionChildCount),
               "failed to initialize the selection main line");

    initializeChild(fixture, fixture->selected_child, 0);
    initializeChild(fixture, fixture->first_loser, 1);
    initializeChild(fixture, fixture->reentrant_loser, 2);
    lineMarkEstablished(fixture->selected_child);
}

static void fixtureTeardown(connectionfisher_selection_fixture_t *fixture)
{
    if (fixture->main_line != NULL)
    {
        connectionfisherclientCloseMainLineFromUpstream(fixture->fisher, fixture->main_line);
        twfRequireLineStateZeroed(
            fixture->main_line, fixture->fisher, "selection fixture main state survived teardown");
        lineDestroy(fixture->main_line);
        fixture->main_line = NULL;
    }

    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture->lines.master),
                       0,
                       "selection fixture retained a physical child line");
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->fisher);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseReentrantSiblingFinishKeepsSnapshotValid(void)
{
    connectionfisher_selection_fixture_t fixture;
    fixtureSetup(&fixture);

    twfRequire(connectionfisherclientSelectChild(fixture.fisher, fixture.selected_child),
               "selection failed after the next tunnel closed another losing child");
    twfRequire(fixture.reentered, "closing the first loser did not exercise cross-line re-entry");
    twfRequireEqualU32(
        fixture.reentrant_target_refcount, 2, "the losing-child snapshot did not retain the re-entrantly closed line");
    twfRequire(lineIsAlive(fixture.selected_child), "cross-line loser closure destroyed the selected child");

    connectionfisherclient_lstate_t *main_ls = lineGetState(fixture.main_line, fixture.fisher);
    twfRequire(main_ls->selected_child == fixture.selected_child, "selection lost the winning child");
    twfRequireEqualU32(main_ls->open_child_count, 1, "selection retained losing children in its live count");
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture.lines.master),
                       2,
                       "re-entrantly closed losing children were not reclaimed after selection");
    twfRequireNoLeakedBuffers();

    fixtureTeardown(&fixture);
}

static void caseReentrantSiblingFinishKeepsMainCloseSnapshotValid(void)
{
    connectionfisher_selection_fixture_t fixture;
    fixtureSetup(&fixture);

    connectionfisherclientCloseMainLineFromUpstream(fixture.fisher, fixture.main_line);

    twfRequire(fixture.reentered, "main close did not exercise cross-line child re-entry");
    twfRequireEqualU32(fixture.reentrant_target_refcount,
                       2,
                       "the main-close child snapshot did not retain the re-entrantly closed line");
    twfRequireLineStateZeroed(fixture.main_line, fixture.fisher, "main close left ConnectionFisherClient state behind");
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture.lines.master),
                       1,
                       "main close retained a physical child line after cross-line re-entry");
    twfRequireNoLeakedBuffers();

    fixtureTeardown(&fixture);
}

static void caseSelectedChildFinishClosesDetachedLosers(void)
{
    connectionfisher_selection_fixture_t fixture;
    fixtureSetup(&fixture);

    fixture.reentrant_target = fixture.selected_child;
    fixture.prev->fnFinD     = ownerPrevFinish;

    twfRequire(! connectionfisherclientSelectChild(fixture.fisher, fixture.selected_child),
               "selection survived its selected child and main owner closing");
    twfRequire(fixture.reentered, "loser close did not re-entrantly finish the selected child");
    twfRequireEqualU32(
        fixture.reentrant_target_refcount, 2, "selection did not retain the selected child across loser close");
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture.lines.master),
                       0,
                       "main death stranded a losing child detached from its registry");
    twfRequireNoLeakedBuffers();

    /* The owner Finish above logically destroyed the main, and the final
     * selection references have now released its storage. */
    fixture.main_line = NULL;
    fixtureTeardown(&fixture);
}

typedef struct connectionfisher_timeout_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    master_pool_t   *message_master;
    tunnel_t        *prev;
    tunnel_t        *fisher;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *children[kConnectionFisherSelectionChildCount];
    uint32_t         child_init_count;
    uint32_t         child_ping_count;
    uint32_t         child_finish_count[kConnectionFisherSelectionChildCount];
    uint32_t         main_finish_count;
    uint32_t         reentrant_target_refcount;
    bool             reentered;
} connectionfisher_timeout_fixture_t;

static connectionfisher_timeout_fixture_t *timeoutFixtureFromTunnel(tunnel_t *t)
{
    return *(connectionfisher_timeout_fixture_t **) tunnelGetState(t);
}

static uint32_t timeoutChildIndex(connectionfisher_timeout_fixture_t *fixture, line_t *line)
{
    for (uint32_t i = 0; i < fixture->child_init_count; ++i)
    {
        if (fixture->children[i] == line)
        {
            return i;
        }
    }

    twfRequire(false, "ConnectionFisher callback named an unknown child line");
    return 0;
}

static void timeoutNextInit(tunnel_t *t, line_t *line)
{
    connectionfisher_timeout_fixture_t *fixture = timeoutFixtureFromTunnel(t);
    twfRequire(fixture->child_init_count < kConnectionFisherSelectionChildCount,
               "ConnectionFisher created too many timeout candidates");
    fixture->children[fixture->child_init_count++] = line;
}

static void timeoutNextPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    connectionfisher_timeout_fixture_t *fixture = timeoutFixtureFromTunnel(t);
    discard                             timeoutChildIndex(fixture, line);
    ++fixture->child_ping_count;
    lineReuseBuffer(line, buf);
}

static void timeoutNextFinish(tunnel_t *t, line_t *line)
{
    connectionfisher_timeout_fixture_t *fixture = timeoutFixtureFromTunnel(t);
    const uint32_t                      index   = timeoutChildIndex(fixture, line);
    ++fixture->child_finish_count[index];

    if (index == 0 && ! fixture->reentered)
    {
        fixture->reentered                 = true;
        fixture->reentrant_target_refcount = twfLineRefCount(fixture->children[1]);

        /* The next-side owner independently closes a different candidate.
         * That downstream Finish must not be reflected back toward it. */
        tunnelPrevDownStreamFinish(t, fixture->children[1]);
    }
}

static void timeoutMainOwnerFinish(tunnel_t *t, line_t *line)
{
    connectionfisher_timeout_fixture_t *fixture = timeoutFixtureFromTunnel(t);
    ++fixture->main_finish_count;
    lineDestroy(line);
}

static void timeoutFixtureSetup(connectionfisher_timeout_fixture_t *fixture, line_t **main_line)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kConnectionFisherSelectionLargeBuffer, 0);
    fixture->env.loop->status = WLOOP_STATUS_RUNNING;

    fixture->message_master = masterpoolCreateWithCapacity(16);
    twfRequire(fixture->message_master != NULL, "failed to create the ConnectionFisher message pool");
    workerMessagesInstallMasterPoolCallbacks(fixture->message_master);
    GSTATE.masterpool_messages = fixture->message_master;
    mutexInit(&fixture->env.worker.control_mutex);
    twfRequire(workerMessagesInit(&fixture->env.worker), "failed to create the ConnectionFisher message queue");
    twfRequire(workerMessagesOpenAdmission(&fixture->env.worker), "failed to open ConnectionFisher message admission");

    fixture->prev = tunnelCreate(NULL, sizeof(connectionfisher_timeout_fixture_t *), 0);
    fixture->fisher =
        tunnelCreate(NULL, sizeof(connectionfisherclient_tstate_t), sizeof(connectionfisherclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(connectionfisher_timeout_fixture_t *), 0);
    twfRequire(fixture->prev != NULL && fixture->fisher != NULL && fixture->next != NULL,
               "failed to create the ConnectionFisher timeout fixture tunnels");
    *(connectionfisher_timeout_fixture_t **) tunnelGetState(fixture->prev) = fixture;
    *(connectionfisher_timeout_fixture_t **) tunnelGetState(fixture->next) = fixture;
    fixture->prev->fnFinD                                                  = timeoutMainOwnerFinish;
    fixture->next->fnInitU                                                 = timeoutNextInit;
    fixture->next->fnPayloadU                                              = timeoutNextPayload;
    fixture->next->fnFinU                                                  = timeoutNextFinish;
    fixture->fisher->fnFinD = connectionfisherclientTunnelDownStreamFinish;
    tunnelBind(fixture->prev, fixture->fisher);
    tunnelBind(fixture->fisher, fixture->next);

    twfLinePoolSetup(&fixture->lines, fixture->fisher->lstate_size, kConnectionFisherSelectionLineCap);
    fixture->chain = memoryAllocateZero(sizeof(*fixture->chain) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to create the ConnectionFisher timeout fixture chain");
    fixture->chain->workers_count = 1;
    fixture->chain->line_pools[0] = fixture->lines.pools[0];
    fixture->fisher->chain        = fixture->chain;

    connectionfisherclient_tstate_t *state = tunnelGetState(fixture->fisher);
    state->simultaneous_tries_perline      = kConnectionFisherSelectionChildCount;
    *main_line                             = twfLinePoolCreateLine(&fixture->lines);
}

static void timeoutFixtureTeardown(connectionfisher_timeout_fixture_t *fixture)
{
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture->lines.master),
                       0,
                       "timeout refusal retained a main or candidate line");
    twfLinePoolTeardown(&fixture->lines);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->fisher);
    tunnelDestroy(fixture->prev);

    workerMessagesDestroy(&fixture->env.worker);
    mutexDestroy(&fixture->env.worker.control_mutex);
    twfRequireEqualU32(
        (uint32_t) masterpoolGetCheckedOut(fixture->message_master), 0, "timeout refusal retained a scheduling record");
    GSTATE.masterpool_messages = NULL;
    masterpoolMakeEmpty(fixture->message_master);
    masterpoolDestroy(fixture->message_master);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseTimeoutInstallFailureClosesEveryRoleOnce(void)
{
    twfSetCase("connectionfisher timeout install failure closes every role once");

    connectionfisher_timeout_fixture_t fixture;
    line_t                            *main_line = NULL;
    timeoutFixtureSetup(&fixture, &main_line);

    eventloopTestFailNextTryZalloc();
    connectionfisherclientTunnelUpStreamInit(fixture.fisher, main_line);

    twfRequireEqualU32((uint32_t) fixture.env.loop->ntimers, 0, "failed ConnectionFisher timeout remained armed");
    twfRequireEqualU32(fixture.child_init_count,
                       kConnectionFisherSelectionChildCount,
                       "timeout fixture did not initialize every candidate");
    twfRequireEqualU32(
        fixture.child_ping_count, kConnectionFisherSelectionChildCount, "timeout fixture did not ping every candidate");
    twfRequire(fixture.reentered, "timeout failure did not exercise re-entrant candidate closure");
    twfRequireEqualU32(fixture.reentrant_target_refcount,
                       2,
                       "timeout close did not retain the re-entrantly closed candidate snapshot");
    twfRequireEqualU32(fixture.child_finish_count[0], 1, "first candidate did not receive one upstream Finish");
    twfRequireEqualU32(fixture.child_finish_count[1], 0, "downstream candidate Finish was reflected to its sender");
    twfRequireEqualU32(fixture.child_finish_count[2], 1, "last candidate did not receive one upstream Finish");
    twfRequireEqualU32(fixture.main_finish_count, 1, "main owner did not receive one downstream Finish");
    twfRequireNoLeakedBuffers();

    timeoutFixtureTeardown(&fixture);
}

int main(void)
{
    caseReentrantSiblingFinishKeepsSnapshotValid();
    caseReentrantSiblingFinishKeepsMainCloseSnapshotValid();
    caseSelectedChildFinishClosesDetachedLosers();
    caseTimeoutInstallFailureClosesEveryRoleOnce();
    puts("connectionfisherclient_reentrant_selection_test: all cases passed");
    return 0;
}

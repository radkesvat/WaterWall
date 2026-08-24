/*
 * ConnectionFisherClient cross-line selection lifetime coverage.
 *
 * Closing one losing child calls into the shared next-side tunnel.  That
 * tunnel may synchronously finish a different child; every pointer retained in
 * the selection snapshot must therefore carry its own physical line reference.
 */
#include "ConnectionFisherClient/structure.h"

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

int main(void)
{
    caseReentrantSiblingFinishKeepsSnapshotValid();
    caseReentrantSiblingFinishKeepsMainCloseSnapshotValid();
    caseSelectedChildFinishClosesDetachedLosers();
    puts("connectionfisherclient_reentrant_selection_test: all cases passed");
    return 0;
}

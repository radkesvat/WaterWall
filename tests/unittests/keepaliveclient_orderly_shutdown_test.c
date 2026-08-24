/*
 * KeepAliveClient per-worker timer failure and snapshot-lifetime coverage.
 *
 * The timer task is enqueued by onStart but runs on a worker event loop, so a
 * failed allocation is a Category-B runtime failure and not a main-thread
 * startup failure. This drives it exactly the way the runtime does - through
 * onStart and the worker message queue - and injects the failure on one worker
 * only, which is what proves the two ownership rules that matter:
 *
 *   - the failing worker leaves its own slot NULL and touches nothing else;
 *   - the timer another worker already published stays owned by that worker and
 *     is deleted by its own onWorkerStop during the orderly shutdown;
 *   - a ping callback may close another snapshotted line re-entrantly, so every
 *     snapshot entry retains physical line lifetime until the timer settles it.
 */
#include "KeepAliveClient/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

// ---------------------------------------------------------------------------
// wtimerAdd injection, per worker loop
// ---------------------------------------------------------------------------

static wloop_t *g_failing_loop = NULL;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (loop == g_failing_loop)
    {
        return NULL;
    }
    return __real_wtimerAdd(loop, cb, timeout_ms, repeat);
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = 1024,
    kTestWorkerCount     = 2,
    kTestPingIntervalMs  = 60000
};

// File scope: the published GSTATE shortcuts point into this environment, so it
// must outlive every case that pumps a worker.
static tos_worker_env_t g_env;

typedef struct keepaliveclient_fixture_s
{
    twf_trace_t trace;
    tunnel_t   *keepalive;
    tunnel_t   *next;
    wtimer_t   *worker_timer_slots[kTestWorkerCount];
} keepaliveclient_fixture_t;

static void fixtureSetup(keepaliveclient_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&g_env, kTestWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);

    fixture->keepalive = tunnelCreate(NULL, sizeof(keepaliveclient_tstate_t), sizeof(keepaliveclient_lstate_t));
    twfRequire(fixture->keepalive != NULL, "failed to create the KeepAliveClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->keepalive, fixture->next);

    keepaliveclient_tstate_t *ts = tunnelGetState(fixture->keepalive);
    mutexInit(&ts->lines_mutex);
    ts->ping_interval_ms = kTestPingIntervalMs;
    ts->worker_timers    = fixture->worker_timer_slots;
}

static void fixtureTeardown(keepaliveclient_fixture_t *fixture)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(fixture->keepalive);
    mutexDestroy(&ts->lines_mutex);
    tosWorkerEnvTeardown(&g_env);
}

// ---------------------------------------------------------------------------
// Category B: one worker cannot create its required timer
// ---------------------------------------------------------------------------

static void caseWorkerTimerFailure(void)
{
    twfSetCase("keepaliveclient worker timer failure");
    tosResetProcessApi(true);

    keepaliveclient_fixture_t fixture;
    fixtureSetup(&fixture);

    // Worker 1 is the one that cannot allocate.
    g_failing_loop = g_env.loops[1];

    keepaliveclientTunnelOnStart(fixture.keepalive);

    // onStart only enqueues; the tasks run when each worker drains its queue.
    tosRequireNoProcessApiCall();
    twfRequire(fixture.worker_timer_slots[0] == NULL, "onStart must not create a timer itself");

    tosPumpWorker(&g_env, 0);
    tosRequireNoProcessApiCall();
    twfRequire(fixture.worker_timer_slots[0] != NULL, "worker 0 must publish its timer");

    tosPumpWorker(&g_env, 1);

    tosRequireAcceptedRequest(1);
    twfRequire(fixture.worker_timer_slots[1] == NULL, "the failing worker must leave its own slot NULL");
    twfRequire(fixture.worker_timer_slots[0] != NULL, "the failing worker must not delete a timer another worker owns");

    // Normal shutdown: each worker deletes its own slot, so the timer worker 0
    // published is released without the failing worker ever touching it. Both
    // stops run as the worker that owns the slot, which is the only context
    // onWorkerStop accepts.
    wid_t previous = tosSetCurrentWorker(0);
    keepaliveclientTunnelOnWorkerQuiesce(fixture.keepalive, 0, wwLifecycleProcessShutdown());
    twfRequire(fixture.worker_timer_slots[0] == NULL, "onWorkerStop must delete the published timer");

    // The worker whose allocation failed must still be safe to stop.
    discard tosSetCurrentWorker(1);
    keepaliveclientTunnelOnWorkerQuiesce(fixture.keepalive, 1, wwLifecycleProcessShutdown());
    twfRequire(fixture.worker_timer_slots[1] == NULL, "stopping a worker with no timer must stay a no-op");
    discard tosSetCurrentWorker(previous);

    g_failing_loop = NULL;
    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// A ping callback can synchronously close another snapshotted line
// ---------------------------------------------------------------------------

typedef struct keepaliveclient_snapshot_owner_state_s
{
    line_t  *must_be_retained;
    uint32_t finish_count;
} keepaliveclient_snapshot_owner_state_t;

typedef struct keepaliveclient_snapshot_next_state_s
{
    line_t  *line_to_close;
    uint32_t payload_count;
} keepaliveclient_snapshot_next_state_t;

static void snapshotOwnerFinish(tunnel_t *t, line_t *l)
{
    keepaliveclient_snapshot_owner_state_t *state = tunnelGetState(t);

    if (l == state->must_be_retained)
    {
        twfRequireEqualU32(twfLineRefCount(l), 2, "the timer snapshot did not retain a line before re-entrant close");
    }

    ++state->finish_count;
    lineDestroy(l);
}

static void snapshotNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveclient_snapshot_next_state_t *state = tunnelGetState(t);

    ++state->payload_count;
    lineReuseBuffer(l, buf);

    if (state->line_to_close != NULL)
    {
        line_t *line_to_close = state->line_to_close;
        state->line_to_close  = NULL;

        /* This is a legal local close by the upstream neighbour. It reaches
         * KeepAliveClient as downstream Finish and may reclaim a distinct line
         * from the timer's snapshot before the callback returns. */
        tunnelPrevDownStreamFinish(t, line_to_close);
    }
}

static void caseTimerSnapshotRetainsEveryLineAcrossReentrantClose(void)
{
    twfSetCase("keepaliveclient timer snapshot retains later lines across re-entrant close");
    tosResetProcessApi(true);

    tosWorkerEnvSetup(&g_env, kTestWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);
    bufferpoolUpdateAllocationPaddings(g_env.pools[0], kKeepAliveFramePrefixSize, kKeepAliveFramePrefixSize);

    tunnel_t *owner     = tunnelCreate(NULL, sizeof(keepaliveclient_snapshot_owner_state_t), 0);
    tunnel_t *keepalive = tunnelCreate(NULL, sizeof(keepaliveclient_tstate_t), sizeof(keepaliveclient_lstate_t));
    tunnel_t *next      = tunnelCreate(NULL, sizeof(keepaliveclient_snapshot_next_state_t), 0);
    twfRequire(owner != NULL && keepalive != NULL && next != NULL, "failed to create timer snapshot tunnels");

    owner->fnFinD     = snapshotOwnerFinish;
    keepalive->fnFinD = keepaliveclientTunnelDownStreamFinish;
    next->fnPayloadU  = snapshotNextPayload;
    tunnelBind(owner, keepalive);
    tunnelBind(keepalive, next);

    keepaliveclient_tstate_t *ts = tunnelGetState(keepalive);
    mutexInit(&ts->lines_mutex);

    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, keepalive->lstate_size, 4);

    line_t *later_line = twfLinePoolCreateLine(&line_pool);
    line_t *first_line = twfLinePoolCreateLine(&line_pool);

    keepaliveclientLinestateInitialize(lineGetState(later_line, keepalive), later_line);
    keepaliveclientTrackLine(keepalive, later_line);
    keepaliveclientLinestateInitialize(lineGetState(first_line, keepalive), first_line);
    keepaliveclientTrackLine(keepalive, first_line);

    keepaliveclient_snapshot_owner_state_t *owner_state = tunnelGetState(owner);
    owner_state->must_be_retained                       = later_line;

    keepaliveclient_snapshot_next_state_t *next_state = tunnelGetState(next);
    next_state->line_to_close                         = later_line;

    wtimer_t *timer =
        __real_wtimerAdd(g_env.loops[0], keepaliveclientWorkerTimerCallback, kTestPingIntervalMs, INFINITE);
    twfRequire(timer != NULL, "failed to create timer snapshot fixture timer");
    weventSetUserData(timer, keepalive);

    keepaliveclientWorkerTimerCallback(timer);

    twfRequireEqualU32(next_state->payload_count, 1, "the timer pinged a line that was closed re-entrantly");
    twfRequireEqualU32(owner_state->finish_count, 1, "the upstream neighbour did not close the later line");
    twfRequire(ts->lines_head == lineGetState(first_line, keepalive),
               "re-entrant close removed the wrong tracked line");
    twfRequireEqualU32(twfLineRefCount(first_line), 1, "the timer leaked its first-line snapshot reference");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    weventSetUserData(timer, NULL);
    wtimerDelete(timer);

    owner_state->must_be_retained = NULL;
    tunnelPrevDownStreamFinish(next, first_line);
    twfRequireEqualU32(owner_state->finish_count, 2, "fixture teardown did not close the remaining line");
    twfRequire(ts->lines_head == NULL, "fixture teardown left a tracked line");

    twfLinePoolTeardown(&line_pool);
    mutexDestroy(&ts->lines_mutex);
    tunnelDestroy(next);
    tunnelDestroy(keepalive);
    tunnelDestroy(owner);
    tosWorkerEnvTeardown(&g_env);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    keepaliveclient_fixture_t fixture;
    fixtureSetup(&fixture);

    g_failing_loop = g_env.loops[0];
    keepaliveclientTunnelOnStart(fixture.keepalive);
    tosPumpWorker(&g_env, 0);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("keepaliveclient worker timer failure with a refused handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff timer failure", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    caseWorkerTimerFailure();
    caseTimerSnapshotRetainsEveryLineAcrossReentrantClose();
    caseRefusedHandoffAborts();

    printf("keepaliveclient_orderly_shutdown_test: all cases passed\n");
    return 0;
}

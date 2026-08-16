/*
 * KeepAliveClient per-worker timer failure injection.
 *
 * The timer task is enqueued by onStart but runs on a worker event loop, so a
 * failed allocation is a Category-B runtime failure and not a main-thread
 * startup failure. This drives it exactly the way the runtime does - through
 * onStart and the worker message queue - and injects the failure on one worker
 * only, which is what proves the two ownership rules that matter:
 *
 *   - the failing worker leaves its own slot NULL and touches nothing else;
 *   - the timer another worker already published stays owned by that worker and
 *     is deleted by its own onWorkerStop during the orderly shutdown.
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
    caseRefusedHandoffAborts();

    printf("keepaliveclient_orderly_shutdown_test: all cases passed\n");
    return 0;
}

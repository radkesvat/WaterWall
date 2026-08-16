/* UserController per-worker timer failure injection through the real queue. */
#include "UserController/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

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

enum
{
    kTestWorkerCount   = 2,
    kTestSweepInterval = 60000
};

static tos_worker_env_t g_env;

typedef struct usercontroller_fixture_s
{
    tunnel_t                     *tunnel;
    usercontroller_worker_state_t worker_states[kTestWorkerCount];
} usercontroller_fixture_t;

static void fixtureSetup(usercontroller_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&g_env, kTestWorkerCount, 8192, 1024);

    fixture->tunnel = tunnelCreate(NULL, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t));
    twfRequire(fixture->tunnel != NULL, "failed to create the UserController tunnel");

    usercontroller_tstate_t *ts = tunnelGetState(fixture->tunnel);
    ts->worker_states           = fixture->worker_states;
    ts->worker_count            = kTestWorkerCount;
    ts->sweep_interval_ms       = kTestSweepInterval;
}

static void fixtureTeardown(usercontroller_fixture_t *fixture)
{
    tunnelDestroy(fixture->tunnel);
    tosWorkerEnvTeardown(&g_env);
}

static void caseWorkerOneTimerFailure(void)
{
    twfSetCase("usercontroller worker-1 timer failure");
    tosResetProcessApi(true);

    usercontroller_fixture_t fixture;
    fixtureSetup(&fixture);
    g_failing_loop = g_env.loops[1];

    usercontrollerTunnelOnStart(fixture.tunnel);
    tosRequireNoProcessApiCall();

    tosPumpWorker(&g_env, 0);
    tosRequireNoProcessApiCall();
    twfRequire(fixture.worker_states[0].sweep_timer != NULL, "worker 0 must publish its timer");

    tosPumpWorker(&g_env, 1);
    tosRequireAcceptedRequest(1);
    twfRequire(fixture.worker_states[1].sweep_timer == NULL, "the failed worker must leave its timer slot NULL");
    twfRequire(fixture.worker_states[0].sweep_timer != NULL, "a failed worker must not delete another worker's timer");

    wid_t previous = tosSetCurrentWorker(0);
    usercontrollerTunnelOnWorkerQuiesce(fixture.tunnel, 0, wwLifecycleProcessShutdown());
    twfRequire(fixture.worker_states[0].sweep_timer == NULL, "worker quiesce must delete its published timer");

    discard tosSetCurrentWorker(1);
    usercontrollerTunnelOnWorkerQuiesce(fixture.tunnel, 1, wwLifecycleProcessShutdown());
    twfRequire(fixture.worker_states[1].sweep_timer == NULL, "a missing timer must remain safe during quiesce");
    discard tosSetCurrentWorker(previous);

    g_failing_loop = NULL;
    fixtureTeardown(&fixture);
}

static void refusedHandoffBody(void *argument)
{
    discard argument;

    usercontroller_fixture_t fixture;
    fixtureSetup(&fixture);
    g_failing_loop = g_env.loops[1];
    usercontrollerTunnelOnStart(fixture.tunnel);
    tosPumpWorker(&g_env, 1);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("usercontroller timer failure with refused shutdown handoff");
    tosResetProcessApi(false);
    tosRequireChildExit(
        "the refused UserController shutdown handoff", refusedHandoffBody, NULL, kTosChildFallbackAbort);
    tosResetProcessApi(true);
}

int main(void)
{
    caseWorkerOneTimerFailure();
    caseRefusedHandoffAborts();

    printf("usercontroller_orderly_shutdown_test: all cases passed\n");
    return 0;
}

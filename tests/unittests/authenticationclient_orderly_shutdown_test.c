/*
 * AuthenticationClient control-plane timer failure injection.
 *
 * These timers are created on the worker-0 event loop after startup has handed
 * control to the workers, so a failed allocation is a Category-B runtime
 * failure and not a main-thread startup failure. The sync timer additionally
 * reports the failure to its caller, which is what stops the startup sequence
 * before the control line is ever opened.
 *
 * The ping timer lives in a static worker-0 task, so its case goes through the
 * public onStart entry point and the worker message queue exactly as the
 * runtime does.
 */
#include "AuthenticationClient/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

// ---------------------------------------------------------------------------
// wtimerAdd injection
// ---------------------------------------------------------------------------

static bool g_timer_fails = false;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (g_timer_fails)
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
    kTestLargeBufferSize  = 8192,
    kTestSyncIntervalMs   = 1000,
    kTestReconnectDelayMs = 500
};

typedef struct authenticationclient_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *client;
    tunnel_t        *next;
} authenticationclient_fixture_t;

static void fixtureSetup(authenticationclient_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->client = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    twfRequire(fixture->client != NULL, "failed to create the AuthenticationClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->client, fixture->next);

    authenticationclient_tstate_t *ts = tunnelGetState(fixture->client);
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->pull_interval_ms      = kTestSyncIntervalMs;
    ts->push_interval_ms      = kTestSyncIntervalMs;
    ts->reconnect_interval_ms = kTestReconnectDelayMs;
    ts->started               = true;
}

static void fixtureTeardown(authenticationclient_fixture_t *fixture)
{
    authenticationclient_tstate_t *ts = tunnelGetState(fixture->client);
    mutexDestroy(&ts->control_mutex);
    rwlockDestroy(&ts->users_lock);
}

// ---------------------------------------------------------------------------
// The healthy path must still arm both timers
// ---------------------------------------------------------------------------

static void caseHealthyTimersAreArmed(void)
{
    twfSetCase("authenticationclient healthy sync and reconnect timers");
    tosResetProcessApi(true);

    authenticationclient_fixture_t fixture;
    fixtureSetup(&fixture);

    authenticationclient_tstate_t *ts = tunnelGetState(fixture.client);

    twfRequire(authenticationclientStartSyncTimer(fixture.client), "a healthy sync timer must report success");
    twfRequire(ts->sync_timer != NULL, "a healthy sync timer must be published");

    authenticationclientScheduleReconnect(fixture.client);
    twfRequire(ts->reconnect_timer != NULL, "a healthy reconnect must arm its timer");

    tosRequireNoProcessApiCall();

    weventSetUserData(ts->sync_timer, NULL);
    wtimerDelete(ts->sync_timer);
    weventSetUserData(ts->reconnect_timer, NULL);
    wtimerDelete(ts->reconnect_timer);

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the sync timer cannot be created
// ---------------------------------------------------------------------------

static void caseSyncTimerFailure(void)
{
    twfSetCase("authenticationclient sync timer failure");
    tosResetProcessApi(true);

    authenticationclient_fixture_t fixture;
    fixtureSetup(&fixture);

    g_timer_fails    = true;
    const bool armed = authenticationclientStartSyncTimer(fixture.client);
    g_timer_fails    = false;

    tosRequireAcceptedRequest(1);

    // Reporting the failure is what makes the startup task stop before it opens
    // the control line.
    twfRequire(! armed, "a failed sync timer must report shutdown-requested to its caller");

    authenticationclient_tstate_t *ts = tunnelGetState(fixture.client);
    twfRequire(ts->sync_timer == NULL, "a failed sync timer must not be published");
    twfRequire(ts->control_line == NULL, "a failed sync timer must not open the control line");
    twfRequireEqualU32(fixture.trace.next_init, 0, "a failed sync timer must not initialize an upstream line");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the reconnect timer cannot be created
// ---------------------------------------------------------------------------

static void caseReconnectTimerFailure(void)
{
    twfSetCase("authenticationclient reconnect timer failure");
    tosResetProcessApi(true);

    authenticationclient_fixture_t fixture;
    fixtureSetup(&fixture);

    g_timer_fails = true;
    authenticationclientScheduleReconnect(fixture.client);
    g_timer_fails = false;

    tosRequireAcceptedRequest(1);

    authenticationclient_tstate_t *ts = tunnelGetState(fixture.client);
    twfRequire(ts->reconnect_timer == NULL, "a failed reconnect timer must not be published");
    twfRequireEqualU32(fixture.trace.next_init, 0, "a failed reconnect must not open a control line anyway");

    // The control mutex is released before the request, so it is still usable.
    mutexLock(&ts->control_mutex);
    mutexUnlock(&ts->control_mutex);

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedSyncHandoffBody(void *argument)
{
    discard argument;

    authenticationclient_fixture_t fixture;
    fixtureSetup(&fixture);

    g_timer_fails = true;
    discard authenticationclientStartSyncTimer(fixture.client);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("authenticationclient sync timer failure with a refused handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff sync timer failure", refusedSyncHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 startup task cannot create the ping timer
// ---------------------------------------------------------------------------

// File scope: the published GSTATE shortcuts point into this environment, so it
// must outlive the case that pumps worker 0.
static tos_worker_env_t g_env;

static void casePingTimerFailureStopsStartup(void)
{
    twfSetCase("authenticationclient ping timer failure");
    tosResetProcessApi(true);

    tosWorkerEnvSetup(&g_env, 1, kTestLargeBufferSize, kTwfDefaultSmallBufferSize);

    twf_trace_t trace;
    memoryZero(&trace, sizeof(trace));

    tunnel_t *client = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    twfRequire(client != NULL, "failed to create the AuthenticationClient tunnel");
    tunnelBind(client, twfCreateNextTunnel(&trace));

    authenticationclient_tstate_t *ts = tunnelGetState(client);
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->ping_interval_ms = kTestSyncIntervalMs;
    ts->pull_interval_ms = kTestSyncIntervalMs;

    // onStart only enqueues the worker-0 task; nothing has run yet.
    authenticationclientTunnelOnStart(client);
    tosRequireNoProcessApiCall();

    g_timer_fails = true;
    tosPumpWorker(&g_env, 0);
    g_timer_fails = false;

    tosRequireAcceptedRequest(1);

    // The startup task must stop at the failed ping timer: no sync timer, no
    // control line, nothing sent to the neighbour.
    twfRequire(ts->ping_timer == NULL, "a failed ping timer must not be published");
    twfRequire(ts->sync_timer == NULL, "a failed ping timer must not fall through to the sync timer");
    twfRequire(ts->control_line == NULL, "a failed ping timer must not open the control line");
    twfRequireEqualU32(trace.next_init, 0, "a failed ping timer must not initialize an upstream line");

    mutexDestroy(&ts->control_mutex);
    rwlockDestroy(&ts->users_lock);
    tosWorkerEnvTeardown(&g_env);
}

int main(void)
{
    caseHealthyTimersAreArmed();
    caseSyncTimerFailure();
    caseReconnectTimerFailure();
    caseRefusedHandoffAborts();
    casePingTimerFailureStopsStartup();

    printf("authenticationclient_orderly_shutdown_test: all cases passed\n");
    return 0;
}

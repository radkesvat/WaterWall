/*
 * PacketsToStream sensitive-mode timeout timer failure injection.
 *
 * A sensitive-mode ping that cannot be supervised would leave its worker
 * waiting for a pong that no timer will ever time out. The heartbeat has been
 * built but not forwarded at that point, so the send path still owns it: it
 * must recycle that buffer, leave both the timer slot and the pong state
 * untouched, request an orderly shutdown and return without forwarding
 * anything or scheduling an output-line recreation.
 */
#include "PacketsToStream/structure.h"

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
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    kTestIntervalMs      = 50,
    kTestToleranceMs     = 150
};

typedef struct packetstostream_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *p2s;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_line;
    line_t          *stream_line;
    line_t          *packet_line_slot[1];
    wtimer_t        *timeout_timer_slot[1];
    wtimer_t        *worker_timer_slot[1];
    wtimer_t        *heartbeat_timer;
} packetstostream_fixture_t;

static void fixtureSetup(packetstostream_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(fixture->p2s != NULL, "failed to create the PacketsToStream tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->p2s, fixture->next);

    packetstostream_tstate_t *ts = tunnelGetState(fixture->p2s);
    ts->sensitive_mode           = true;
    ts->interval_ms              = kTestIntervalMs;
    ts->tolerance_ms             = kTestToleranceMs;
    ts->worker_timers            = fixture->worker_timer_slot;
    ts->worker_timeout_timers    = fixture->timeout_timer_slot;

    // A one-worker chain that only has to answer tunnelchainGetWorkerPacketLine().
    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the test chain");
    fixture->chain->workers_count = 1;
    fixture->p2s->chain           = fixture->chain;

    fixture->packet_line         = twfLineCreate(fixture->p2s->lstate_size);
    fixture->packet_line_slot[0] = fixture->packet_line;
    fixture->chain->packet_lines = fixture->packet_line_slot;

    // A live output line, so the ping path never has to create one.
    fixture->stream_line = twfLineCreate(fixture->p2s->lstate_size);

    packetstostream_lstate_t *ls = lineGetState(fixture->packet_line, fixture->p2s);
    packetstostreamLinestateInitialize(ls, lineGetBufferPool(fixture->packet_line));
    ls->line = fixture->stream_line;

    // A real timer, so the production callback finds its tunnel through the
    // event user data exactly as the runtime does.
    fixture->heartbeat_timer =
        __real_wtimerAdd(getWorkerLoop(0), packetstostreamHeartbeatTimerCallback, kTestIntervalMs, INFINITE);
    twfRequire(fixture->heartbeat_timer != NULL, "failed to create the test heartbeat timer");
    weventSetUserData(fixture->heartbeat_timer, fixture->p2s);
}

static void fixtureTeardown(packetstostream_fixture_t *fixture)
{
    weventSetUserData(fixture->heartbeat_timer, NULL);
    wtimerDelete(fixture->heartbeat_timer);

    packetstostream_lstate_t *ls = lineGetState(fixture->packet_line, fixture->p2s);
    packetstostreamLinestateDestroy(ls);

    twfLineDestroy(fixture->stream_line);
    twfLineDestroy(fixture->packet_line);
    memoryFree(fixture->chain);
}

// ---------------------------------------------------------------------------
// The healthy path must stay untouched
// ---------------------------------------------------------------------------

static void caseHealthyPingArmsTheTimer(void)
{
    twfSetCase("packetstostream sensitive ping with a working timer");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);

    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);

    tosRequireNoProcessApiCall();
    twfRequireEqualU32(fixture.trace.next_payload, 1, "a healthy ping must be forwarded once");
    twfRequire(fixture.timeout_timer_slot[0] != NULL, "a healthy ping must arm the timeout timer");

    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    twfRequire(ls->awaiting_pong, "a healthy ping must publish awaiting_pong");

    weventSetUserData(fixture.timeout_timer_slot[0], NULL);
    wtimerDelete(fixture.timeout_timer_slot[0]);
    fixture.timeout_timer_slot[0] = NULL;

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the timeout timer cannot be created
// ---------------------------------------------------------------------------

static void caseTimeoutTimerFailure(void)
{
    twfSetCase("packetstostream sensitive timeout timer failure");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);

    const uint32_t recycles_before = twfRecycleCount();

    g_timer_fails = true;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    g_timer_fails = false;

    tosRequireAcceptedRequest(1);

    // The heartbeat was built and is still owned by the send path, so it is
    // recycled exactly once and never handed to the next tunnel.
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the heartbeat must be recycled exactly once");
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the unsupervised heartbeat must not be forwarded");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a timer failure must not finish the output line");

    // The pong state was never published, so nothing waits for a pong that can
    // no longer time out, and the slot stays empty for worker-stop cleanup.
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    twfRequire(! ls->awaiting_pong, "a failed arm must not publish awaiting_pong");
    twfRequireEqualU32((uint32_t) ls->ping_sent_at_ms, 0, "a failed arm must not publish ping_sent_at_ms");
    twfRequireEqualU32((uint32_t) ls->pong_deadline_ms, 0, "a failed arm must not publish pong_deadline_ms");
    twfRequire(! ls->recreate_scheduled, "a timer failure must not schedule an output-line recreation");
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "the timeout timer slot must stay NULL");
    twfRequire(ls->line == fixture.stream_line, "a timer failure must not drop the output line");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);

    g_timer_fails = true;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("packetstostream timeout timer failure with a refused handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff timer failure", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category B: the per-worker heartbeat timer cannot be created
// ---------------------------------------------------------------------------

// File scope: the published GSTATE shortcuts point into this environment, so it
// must outlive the case that pumps worker 0.
static tos_worker_env_t g_env;

static void caseHeartbeatTimerStartFailure(void)
{
    twfSetCase("packetstostream heartbeat timer failure");
    tosResetProcessApi(true);

    tosWorkerEnvSetup(&g_env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the PacketsToStream tunnel");

    wtimer_t                 *worker_timer_slots[1] = {NULL};
    packetstostream_tstate_t *ts                    = tunnelGetState(p2s);
    ts->sensitive_mode                              = true;
    ts->interval_ms                                 = kTestIntervalMs;
    ts->tolerance_ms                                = kTestToleranceMs;
    ts->worker_timers                               = worker_timer_slots;

    // onStart only enqueues the per-worker task; nothing has run yet.
    packetstostreamTunnelOnStart(p2s);
    tosRequireNoProcessApiCall();

    g_timer_fails = true;
    tosPumpWorker(&g_env, 0);
    g_timer_fails = false;

    tosRequireAcceptedRequest(1);
    twfRequire(worker_timer_slots[0] == NULL, "the failing worker must leave its own slot NULL");

    tosWorkerEnvTeardown(&g_env);
}

int main(void)
{
    caseHealthyPingArmsTheTimer();
    caseTimeoutTimerFailure();
    caseRefusedHandoffAborts();
    caseHeartbeatTimerStartFailure();

    printf("packetstostream_orderly_shutdown_test: all cases passed\n");
    return 0;
}

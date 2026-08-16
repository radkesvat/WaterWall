#include "SpeedTestClient/structure.h"

#include "startup.h"
#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestWorkers       = 2,
    kTestLinePoolItems = 4,
    kTestBufferSize    = 4096
};

typedef struct speedtestclient_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *speed;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    master_pool_t   *line_master;
    line_t          *lines[kTestWorkers];
} speedtestclient_fixture_t;

static bool   fail_next_timer_add;
static bool   track_next_allocation;
static void  *tracked_allocation;
static size_t tracked_free_count;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
void     *__real_memoryAllocate(size_t size);
void     *__wrap_memoryAllocate(size_t size);
void      __real_memoryFree(void *ptr);
void      __wrap_memoryFree(void *ptr);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (fail_next_timer_add)
    {
        fail_next_timer_add = false;
        return NULL;
    }
    return __real_wtimerAdd(loop, cb, timeout_ms, repeat);
}

void *__wrap_memoryAllocate(size_t size)
{
    void *allocation = __real_memoryAllocate(size);
    if (track_next_allocation)
    {
        track_next_allocation = false;
        tracked_allocation    = allocation;
    }
    return allocation;
}

void __wrap_memoryFree(void *ptr)
{
    if (ptr != NULL && ptr == tracked_allocation)
    {
        tracked_free_count++;
    }
    __real_memoryFree(ptr);
}

static void fixtureSetup(speedtestclient_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    fixture->speed = tunnelCreate(NULL, sizeof(speedtestclient_tstate_t), sizeof(speedtestclient_lstate_t));
    twfRequire(fixture->speed != NULL, "failed to create SpeedTestClient fixture tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->speed, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(*fixture->chain) + kTestWorkers * sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate SpeedTestClient fixture chain");
    fixture->chain->workers_count = kTestWorkers;
    fixture->speed->chain         = fixture->chain;
    fixture->next->chain          = fixture->chain;

    fixture->line_master = masterpoolCreateWithCapacity(2 * kTestWorkers * kTestLinePoolItems);
    twfRequire(fixture->line_master != NULL, "failed to create SpeedTestClient line master pool");
    fixture->chain->masterpool_line_pool = fixture->line_master;
    for (wid_t wid = 0; wid < kTestWorkers; ++wid)
    {
        fixture->chain->line_pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            fixture->line_master, sizeof(line_t) + fixture->speed->lstate_size, kTestLinePoolItems);
        twfRequire(fixture->chain->line_pools[wid] != NULL, "failed to create SpeedTestClient worker line pool");
    }

    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    state->connection_count         = kTestWorkers;
    state->start_delay_ms           = 1;
    state->owned_lines              = memoryAllocateZero(kTestWorkers * sizeof(*state->owned_lines));
    twfRequire(state->owned_lines != NULL, "failed to allocate SpeedTestClient owner inventory");
    atomic_init(&state->stopping, false);
    mutexInit(&state->aggregate_mutex);
}

static line_t *publishLine(speedtestclient_fixture_t *fixture, uint32_t stream_id, bool init_sent)
{
    const wid_t wid      = (wid_t) (stream_id % kTestWorkers);
    const wid_t previous = tosSetCurrentWorker(wid);
    line_t     *line     = lineCreateForWorker(wid, fixture->chain->line_pools, wid);
    discard     tosSetCurrentWorker(previous);
    twfRequire(line != NULL, "failed to create SpeedTestClient owned line");

    speedtestclient_lstate_t *line_state = lineGetState(line, fixture->speed);
    speedtestclientLinestateInitialize(line_state, fixture->speed, line, stream_id);
    line_state->upstream_init_sent  = init_sent;
    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    twfRequire(state->owned_lines[stream_id] == NULL, "SpeedTestClient fixture slot was already occupied");
    state->owned_lines[stream_id] = line;
    fixture->lines[stream_id]     = line;
    return line;
}

static void drainWorker(speedtestclient_fixture_t *fixture, wid_t wid)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    speedtestclientTunnelOnWorkerStop(fixture->speed, wid, wwLifecycleProcessShutdown());
    discard tosSetCurrentWorker(previous);
}

static void fixtureTeardown(speedtestclient_fixture_t *fixture)
{
    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    for (uint32_t stream_id = 0; stream_id < state->connection_count; ++stream_id)
    {
        twfRequire(state->owned_lines[stream_id] == NULL, "SpeedTestClient teardown found a live owner slot");
    }
    memoryFree(state->owned_lines);
    state->owned_lines = NULL;
    mutexDestroy(&state->aggregate_mutex);
    for (wid_t wid = 0; wid < kTestWorkers; ++wid)
    {
        genericpoolDestroy(fixture->chain->line_pools[wid]);
    }
    masterpoolDestroy(fixture->line_master);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->speed);
    tosWorkerEnvTeardown(&fixture->env);
}

static void caseWorkerStopDrainsOnlyItsPublishedSlots(void)
{
    twfSetCase("SpeedTestClient worker stop drains its authoritative slots");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    publishLine(&fixture, 0, false);
    publishLine(&fixture, 1, true);
    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);

    drainWorker(&fixture, 0);
    twfRequire(state->owned_lines[0] == NULL, "worker 0 did not clear its slot before close");
    twfRequire(state->owned_lines[1] == fixture.lines[1], "worker 0 drained another worker's slot");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a line that never published Init emitted Finish");

    drainWorker(&fixture, 0);
    twfRequireEqualU32(fixture.trace.next_finish, 0, "repeated worker stop reclosed an empty slot");

    drainWorker(&fixture, 1);
    twfRequire(state->owned_lines[1] == NULL, "worker 1 did not clear its slot before close");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "an initialized line did not emit exactly one Finish");
    drainWorker(&fixture, 1);
    twfRequireEqualU32(fixture.trace.next_finish, 1, "repeated worker stop emitted another Finish");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_master), 0, "worker stop retained an owned line");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void casePreStopRejectsLateCreationAndCleanup(void)
{
    twfSetCase("SpeedTestClient PreStop rejects delayed stream creation");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclientTunnelOnQuiesceRequest(fixture.speed, wwLifecycleStartupRollback());
    uint32_t *stream_id = memoryAllocate(sizeof(*stream_id));
    twfRequire(stream_id != NULL, "failed to allocate delayed stream id");
    *stream_id = 0;
    speedtestclientTestStartStream(&fixture.env.workers[0], fixture.speed, stream_id, NULL);
    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    twfRequire(state->owned_lines[0] == NULL, "late delayed task created a line after PreStop");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_master), 0, "late delayed task retained a line");

    stream_id = memoryAllocate(sizeof(*stream_id));
    twfRequire(stream_id != NULL, "failed to allocate delayed cleanup id");
    *stream_id = 1;
    speedtestclientTestCleanupStartStream(fixture.speed, stream_id, NULL, kWorkerMessageCancelAdmissionClosed);
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static ww_startup_result_t runRequiredStartFailure(void)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    speedtestclientTestRequiredStartFailure("injected startup allocation refusal");
    return wwStartupContextEnd(&startup);
}

static void caseRequiredStartupFailuresPropagateStartupStatus(void)
{
    twfSetCase("SpeedTestClient required startup failures propagate startup status");
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    tosResetProcessApi(true);
    twfRequire(! wwStartupSucceeded(runRequiredStartFailure()), "required startup failure reported success");
    tosRequireNoProcessApiCall();

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;

    tosResetProcessApi(true);
    fail_next_timer_add          = true;
    track_next_allocation        = true;
    tracked_allocation           = NULL;
    tracked_free_count           = 0;
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    speedtestclientTunnelOnStart(fixture.speed);
    twfRequire(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "required task refusal reported startup success");
    twfRequire(tracked_allocation != NULL && tracked_free_count == 1,
               "direct delayed-task refusal did not release the retained stream id exactly once");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseAcceptedQueuedTimerSetupFailureUsesCleanup(void)
{
    twfSetCase("SpeedTestClient accepted queued timer failure uses runtime cleanup");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;
    const wid_t previous_wid        = tosSetCurrentWorker(1);
    track_next_allocation           = true;
    tracked_allocation              = NULL;
    tracked_free_count              = 0;

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    speedtestclientTunnelOnStart(fixture.speed);
    twfRequire(wwStartupSucceeded(wwStartupContextEnd(&startup)), "accepted timer setup reported startup failure");
    twfRequire(tracked_allocation != NULL && tracked_free_count == 0,
               "accepted queued setup released its payload before settlement");

    fail_next_timer_add = true;
    tosPumpWorker(&fixture.env, 0);
    twfRequireEqualU32((uint32_t) tracked_free_count, 1, "accepted setup cleanup did not release the stream id once");
    tosRequireAcceptedRequest(1);

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseWorkerStopDrainsOnlyItsPublishedSlots();
    casePreStopRejectsLateCreationAndCleanup();
    caseRequiredStartupFailuresPropagateStartupStatus();
    caseAcceptedQueuedTimerSetupFailureUsesCleanup();
    puts("SpeedTestClient orderly shutdown tests passed");
    return 0;
}

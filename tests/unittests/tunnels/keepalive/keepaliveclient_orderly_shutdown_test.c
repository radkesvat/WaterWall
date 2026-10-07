/*
 * Covers: KeepAliveClient worker/instance isolation and idle-table lifecycle.
 * Setup: Real runtime/component code with owner, worker, line and buffer fixtures.
 * Cases: embedded worker allocation, lazy table failure, worker/instance isolation,
 * reentrant close of a due sibling or the current line, and late Est after quiescence.
 * Checks: separate worker tables, suppressed closed items, retained current-line
 * references, and owner-worker table destruction after the last borrowed line.
 * Limits: Worker identities are simulated on one thread; no throughput measurements.
 * CTest: waterwall.keepaliveclient_orderly_shutdown_test_unit
 */
#include "KeepAliveClient/structure.h"

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"

static wloop_t *g_failing_loop;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    return loop == g_failing_loop ? NULL : __real_wtimerAdd(loop, cb, timeout_ms, repeat);
}

enum
{
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = 1024,
    kTestWorkerCount     = 2,
    kTestPingIntervalMs  = 60000
};
static tos_worker_env_t g_env;

typedef struct owner_state_s
{
    line_t  *unretained_line;
    uint32_t finish_count;
} owner_state_t;

typedef struct next_state_s
{
    line_t  *line_to_close;
    uint32_t payload_count;
    uint32_t worker_payload_counts[kTestWorkerCount];
} next_state_t;

typedef struct fixture_s
{
    node_t          metadata;
    tunnel_t       *owner, *client, *next;
    twf_line_pool_t lines;
} fixture_t;

static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void ownerFinish(tunnel_t *t, line_t *l)
{
    owner_state_t *state = tunnelGetState(t);
    if (l == state->unretained_line)
        twfRequireEqualU32(twfLineRefCount(l), 1, "idle table retained an unvisited sibling line");
    ++state->finish_count;
    lineDestroy(l);
}

static void nextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    next_state_t *state = tunnelGetState(t);
    twfRequire(lineIsOnCurrentEventWorker(l), "idle callback sent a ping on another worker's line");
    twfRequire(twfLineRefCount(l) >= 3, "idle callback did not retain the current line across Payload");
    ++state->payload_count;
    ++state->worker_payload_counts[lineGetWID(l)];
    lineReuseBuffer(l, buf);
    if (state->line_to_close != NULL)
    {
        line_t *closing      = state->line_to_close;
        state->line_to_close = NULL;
        tunnelPrevDownStreamFinish(t, closing);
    }
}

static void setupWorkers(void)
{
    tosResetProcessApi(true);
    tosWorkerEnvSetup(&g_env, kTestWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
        bufferpoolUpdateAllocationPaddings(g_env.pools[wid],
                                           kKeepAliveFramePrefixSize,
                                           kKeepAliveFramePrefixSize,
                                           kKeepAliveFramePrefixSize,
                                           kKeepAliveFramePrefixSize);
}

static void bindFixture(tunnel_t *owner, tunnel_t *client, tunnel_t *next)
{
    tunnelBind(owner, client);
    tunnelBind(client, next);
    owner->fnFinD                                                           = ownerFinish;
    owner->fnEstD                                                           = noop;
    next->fnInitU                                                           = noop;
    next->fnPayloadU                                                        = nextPayload;
    ((keepaliveclient_tstate_t *) tunnelGetState(client))->ping_interval_ms = kTestPingIntervalMs;
}

static void fixtureSetup(fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    setupWorkers();
    fixture->owner  = tunnelCreate(NULL, sizeof(owner_state_t), 0);
    fixture->client = keepaliveclientTunnelCreate(&fixture->metadata);
    fixture->next   = tunnelCreate(NULL, sizeof(next_state_t), 0);
    twfRequire(fixture->owner != NULL && fixture->client != NULL && fixture->next != NULL, "construct idle fixture");
    bindFixture(fixture->owner, fixture->client, fixture->next);
    twfLinePoolSetup(&fixture->lines, fixture->client->lstate_size, 4);
}

static void fixtureTeardown(fixture_t *fixture)
{
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        keepaliveclientTunnelOnWorkerQuiesce(fixture->client, wid, wwLifecycleProcessShutdown());
    }
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    twfLinePoolTeardown(&fixture->lines);
    keepaliveclientTunnelDestroy(fixture->client, wwLifecycleProcessShutdown());
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->owner);
    tosWorkerEnvTeardown(&g_env);
}

static line_t *fixtureCreateLine(fixture_t *fixture, bool establish)
{
    line_t *l = twfLinePoolCreateLine(&fixture->lines);
    keepaliveclientTunnelUpStreamInit(fixture->client, l);
    if (establish)
        keepaliveclientTunnelDownStreamEst(fixture->client, l);
    return l;
}

static void caseEmbeddedWorkerStateAllocation(void)
{
    twfSetCase("keepaliveclient embedded worker state allocation");
    tosResetProcessApi(true);
    tosWorkerEnvSetup(&g_env, kTosMaxWorkers, kTestLargeBufferSize, kTestSmallBufferSize);
    node_t    metadata = {0};
    tunnel_t *t        = keepaliveclientTunnelCreate(&metadata);
    twfRequire(t != NULL, "construct embedded worker state tunnel");
    keepaliveclient_tstate_t *ts     = tunnelGetState(t);
    const size_t              offset = offsetof(keepaliveclient_tstate_t, worker_states);
    twfRequire((const void *) ts->worker_states == (const uint8_t *) ts + offset,
               "worker states are not embedded in the tunnel allocation");
    twfRequire(tunnelGetStateSize(t) >= offset + kTosMaxWorkers * sizeof(*ts->worker_states),
               "tunnel allocation omits embedded worker slots");
    for (wid_t wid = 0; wid < kTosMaxWorkers; ++wid)
    {
        keepaliveclient_worker_state_t *state = &ts->worker_states[wid];
        twfRequire(state->idle_table == NULL && state->active_lines == 0 && ! state->quiesced,
                   "embedded worker slot was not zero initialized");
        twfRequire(wloopNTimers(g_env.loops[wid]) == 0, "constructor created an idle timer eagerly");
        discard tosSetCurrentWorker(wid);
        keepaliveclientTunnelOnWorkerQuiesce(t, wid, wwLifecycleProcessShutdown());
    }
    keepaliveclientTunnelDestroy(t, wwLifecycleProcessShutdown());
    tosRequireNoProcessApiCall();
    tosWorkerEnvTeardown(&g_env);
}

static void timerFailureBody(void *argument)
{
    discard   argument;
    fixture_t fixture;
    fixtureSetup(&fixture);
    line_t *l      = fixtureCreateLine(&fixture, false);
    g_failing_loop = g_env.loops[0];
    keepaliveclientTunnelDownStreamEst(fixture.client, l);
}

static void caseIdleTableTimerFailure(void)
{
    twfSetCase("keepaliveclient lazy idle table timer failure");
    tosResetProcessApi(true);
    /* The local-table API owns its existing fail-fast allocation contract. */
    tosRequireChildExit("idle table timer failure", timerFailureBody, NULL, kTosChildDirectAbort);
}

static void caseReentrantClose(bool close_current)
{
    twfSetCase(close_current ? "keepaliveclient ping closes current line" : "keepaliveclient ping closes due sibling");
    fixture_t fixture;
    fixtureSetup(&fixture);
    keepaliveclient_tstate_t *ts = tunnelGetState(fixture.client);
    ts->sensitive_mode           = true;
    line_t        *first         = fixtureCreateLine(&fixture, true);
    owner_state_t *owner         = tunnelGetState(fixture.owner);
    next_state_t  *next          = tunnelGetState(fixture.next);
    if (close_current)
        next->line_to_close = first;
    else
    {
        g_env.loops[0]->cur_hrtime += 1000U;
        next->line_to_close    = fixtureCreateLine(&fixture, true);
        owner->unretained_line = next->line_to_close;
    }
    g_env.loops[0]->cur_hrtime += (uint64_t) kTestPingIntervalMs * 1000U;
    localidletableTestRunExpiry(ts->worker_states[0].idle_table);
    twfRequireEqualU32(next->payload_count, 1, "idle table pinged a closed line");
    twfRequireEqualU32(owner->finish_count, 1, "reentrant Finish did not reach the line owner");
    twfRequire(ts->worker_states[0].active_lines == (close_current ? 0U : 1U), "wrong borrowed-line count after close");
    twfRequire(localidletableGetItemCount(ts->worker_states[0].idle_table) == (close_current ? 0U : 2U),
               "reentrant close retained a ping or deadline item");
    if (! close_current)
    {
        twfRequireEqualU32(twfLineRefCount(first), 1, "idle callback leaked its current-line reference");
        keepaliveclientTunnelOnWorkerQuiesce(fixture.client, 0, wwLifecycleProcessShutdown());
        twfRequire(ts->worker_states[0].idle_table != NULL &&
                       localidletableTestIsQuiesced(ts->worker_states[0].idle_table),
                   "quiescence destroyed a table before borrowed lines drained");
        tunnelPrevDownStreamFinish(fixture.next, first);
        twfRequire(ts->worker_states[0].idle_table == NULL, "last owner close did not release the quiesced table");
    }
    fixtureTeardown(&fixture);
}

static void caseQuiescenceBeforeEst(void)
{
    twfSetCase("keepaliveclient late Est after worker quiescence");
    fixture_t fixture;
    fixtureSetup(&fixture);
    line_t                   *l  = fixtureCreateLine(&fixture, false);
    keepaliveclient_tstate_t *ts = tunnelGetState(fixture.client);
    twfRequire(ts->worker_states[0].idle_table == NULL, "Init created a timer before Est");
    keepaliveclientTunnelOnWorkerQuiesce(fixture.client, 0, wwLifecycleProcessShutdown());
    keepaliveclientTunnelDownStreamEst(fixture.client, l);
    g_env.loops[0]->cur_hrtime += (uint64_t) kTestPingIntervalMs * 1000U;
    twfRequire(keepaliveclientSendPingFrame(fixture.client, l) && ts->worker_states[0].idle_table == NULL &&
                   wloopNTimers(g_env.loops[0]) == 0,
               "late Est recreated a timer after quiescence");
    next_state_t *next = tunnelGetState(fixture.next);
    twfRequire(next->payload_count == 0, "late Est admitted a ping after quiescence");
    tunnelPrevDownStreamFinish(fixture.next, l);
    fixtureTeardown(&fixture);
}

static void caseWorkerAndInstanceIsolation(void)
{
    twfSetCase("keepaliveclient worker and instance isolation");
    setupWorkers();
    enum
    {
        kInstances      = 2,
        kLinesPerWorker = 3
    };
    node_t                    metadata[kInstances] = {0};
    tunnel_t                 *owners[kInstances], *clients[kInstances], *nexts[kInstances];
    keepaliveclient_tstate_t *states[kInstances];
    line_t                   *lines[kInstances][kTestWorkerCount][kLinesPerWorker];
    master_pool_t            *master = masterpoolCreateWithCapacity(16);
    generic_pool_t           *pools[kTestWorkerCount];
    twfRequire(master != NULL, "create isolation line master pool");
    for (unsigned instance = 0; instance < kInstances; ++instance)
    {
        owners[instance]  = tunnelCreate(NULL, sizeof(owner_state_t), 0);
        clients[instance] = keepaliveclientTunnelCreate(&metadata[instance]);
        nexts[instance]   = tunnelCreate(NULL, sizeof(next_state_t), 0);
        twfRequire(owners[instance] != NULL && clients[instance] != NULL && nexts[instance] != NULL,
                   "construct isolation tunnels");
        bindFixture(owners[instance], clients[instance], nexts[instance]);
        states[instance] = tunnelGetState(clients[instance]);
    }
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            master, sizeof(line_t) + clients[0]->lstate_size, 8);
        twfRequire(pools[wid] != NULL, "create isolation line pool");
        for (unsigned instance = 0; instance < kInstances; ++instance)
        {
            for (unsigned i = 0; i < kLinesPerWorker; ++i)
            {
                line_t *l = lines[instance][wid][i] = lineCreate(pools, wid);
                lineRef(l);
                keepaliveclientTunnelUpStreamInit(clients[instance], l);
                keepaliveclientTunnelDownStreamEst(clients[instance], l);
            }
            keepaliveclient_worker_state_t *state = &states[instance]->worker_states[wid];
            twfRequire(state->active_lines == kLinesPerWorker &&
                           localidletableGetItemCount(state->idle_table) == kLinesPerWorker,
                       "tracking mixed worker or instance items");
        }
        twfRequire(states[0]->worker_states[wid].idle_table != states[1]->worker_states[wid].idle_table &&
                       wloopNTimers(g_env.loops[wid]) == kInstances,
                   "instances share a worker table or timer");
    }
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        g_env.loops[wid]->cur_hrtime += (uint64_t) kTestPingIntervalMs * 1000U;
        for (unsigned instance = 0; instance < kInstances; ++instance)
        {
            localidletableTestRunExpiry(states[instance]->worker_states[wid].idle_table);
            for (unsigned other = 0; other < kInstances; ++other)
            {
                next_state_t *output = tunnelGetState(nexts[other]);
                for (wid_t worker = 0; worker < kTestWorkerCount; ++worker)
                    twfRequireEqualU32(output->worker_payload_counts[worker],
                                       worker < wid || (worker == wid && other <= instance) ? kLinesPerWorker : 0,
                                       "an idle callback visited another worker or instance");
            }
        }
    }
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        g_env.loops[wid]->cur_hrtime += (uint64_t) kTestPingIntervalMs * 1000U;
        for (unsigned instance = 0; instance < kInstances; ++instance)
        {
            tunnel_t                       *client = clients[instance];
            keepaliveclient_worker_state_t *state  = &states[instance]->worker_states[wid];
            tunnelPrevDownStreamFinish(nexts[instance], lines[instance][wid][1]);
            twfRequireLineStateZeroed(lines[instance][wid][1], client, "removed line retained KeepAlive state");
            lineUnref(lines[instance][wid][1]);
            twfRequire(state->active_lines == 2 && localidletableGetItemCount(state->idle_table) == 2,
                       "line removal retained idle entries");
            localidletableTestRunExpiry(state->idle_table);
            next_state_t *output = tunnelGetState(nexts[instance]);
            twfRequireEqualU32(
                output->worker_payload_counts[wid], 5, "idle table lost a survivor or revisited a closed line");
            /* Exercise cleanup both before and after this tunnel's quiescence hook. */
            if (wid == 0)
                keepaliveclientTunnelOnWorkerQuiesce(client, wid, wwLifecycleProcessShutdown());
            for (int i = 2; i >= 0; i -= 2)
            {
                line_t *l = lines[instance][wid][i];
                twfRequireEqualU32(twfLineRefCount(l), 2, "idle callback leaked a line reference");
                tunnelPrevDownStreamFinish(nexts[instance], l);
                twfRequire(! lineIsAlive(l), "line owner did not destroy the removed line");
                twfRequireLineStateZeroed(l, client, "closed line retained KeepAlive state");
                lineUnref(l);
            }
            keepaliveclientTunnelOnWorkerQuiesce(client, wid, wwLifecycleProcessShutdown());
            twfRequire(state->idle_table == NULL && state->active_lines == 0, "quiesced owner drain retained a table");
            if (wid == 0)
            {
                discard tosSetCurrentWorker(1);
                twfRequire(states[instance]->worker_states[1].idle_table != NULL &&
                               ! localidletableTestIsQuiesced(states[instance]->worker_states[1].idle_table),
                           "quiescence touched another worker's table");
                discard tosSetCurrentWorker(wid);
            }
        }
    }
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    for (unsigned instance = 0; instance < kInstances; ++instance)
    {
        keepaliveclientTunnelDestroy(clients[instance], wwLifecycleProcessShutdown());
        tunnelDestroy(nexts[instance]);
        tunnelDestroy(owners[instance]);
    }
    for (wid_t wid = 0; wid < kTestWorkerCount; ++wid)
        genericpoolDestroy(pools[wid]);
    masterpoolDestroy(master);
    tosWorkerEnvTeardown(&g_env);
}

int main(void)
{
    caseEmbeddedWorkerStateAllocation();
    caseIdleTableTimerFailure();
    caseWorkerAndInstanceIsolation();
    caseReentrantClose(false);
    caseReentrantClose(true);
    caseQuiescenceBeforeEst();
    puts("keepaliveclient_orderly_shutdown_test: all cases passed");
    return 0;
}

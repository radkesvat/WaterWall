/*
 * WireGuardDevice transport-line rejection is retryable, not process-wide.
 *
 * A transport line is an ordinary line, and a neighbouring connector may reject
 * one for an operational reason. That must stay local: no process-exit API, the
 * slot left NULL, and a later call able to create the line successfully. This
 * is the property the startup task depends on when it logs a warning and
 * returns instead of terminating.
 */
#include "WireGuardDevice/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = 1024,
    kTestLinePoolItems   = 8
};

static tos_worker_env_t g_env;

static bool      g_fail_transport_storage;
static int       g_refuse_queue_at = -1;
static uint32_t  g_queue_attempts;
static uint32_t  g_timer_attempts;
static tunnel_t *g_start_tunnel;
static wtimer_t  g_fake_timer;

void                          *__real_memoryAllocateZero(size_t size);
worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
wtimer_t                      *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
void                          *__wrap_memoryAllocateZero(size_t size);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
wtimer_t                      *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

void *__wrap_memoryAllocateZero(size_t size)
{
    if (g_fail_transport_storage)
    {
        g_fail_transport_storage = false;
        twfRequireEqualU32(g_queue_attempts, 0, "WireGuard storage failure queued worker work");
        twfRequireEqualU32(g_timer_attempts, 0, "WireGuard storage failure published its timer");
        twfRequire(tunnelGetState(g_start_tunnel) != NULL, "WireGuard storage failure lost tunnel state");
        twfRequire(((wgd_tstate_t *) tunnelGetState(g_start_tunnel))->transport_lines == NULL,
                   "WireGuard storage failure published a partial line table");
        return NULL;
    }
    return __real_memoryAllocateZero(size);
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    discard wid;
    discard cb;
    discard cleanup;
    discard arg1;
    discard arg2;
    discard arg3;

    const uint32_t attempt = g_queue_attempts++;
    if (g_refuse_queue_at >= 0 && attempt == (uint32_t) g_refuse_queue_at)
    {
        tunnel_chain_t *chain = tunnelGetChain(g_start_tunnel);
        twfRequire(! chain->packet_chain_init_sent,
                   "WireGuard published all-worker packet readiness before admission completed");
        twfRequireEqualU32(g_timer_attempts, 0, "WireGuard admission failure published its timer");
        return false;
    }
    return true;
}

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    discard loop;
    discard cb;
    discard timeout_ms;
    discard repeat;
    ++g_timer_attempts;
    return &g_fake_timer;
}

typedef struct wireguarddevice_fixture_s
{
    twf_trace_t     trace;
    tunnel_t       *wgd;
    tunnel_t       *next;
    tunnel_chain_t *chain;
    line_t         *transport_line_slots[1];
    line_t         *packet_line_slots[1];
    master_pool_t  *line_master;
} wireguarddevice_fixture_t;

// Whether the fake neighbour accepts the transport line Init or rejects it.
static bool g_next_accepts_init = false;

/*
 * A rejection is a downstream Finish, not a lineDestroy(): WireGuardDevice
 * created this line and is the only tunnel allowed to destroy it. Rejecting the
 * way a real neighbour does routes the closure through
 * wireguarddeviceTunnelDownStreamFinish(), so the cleanup under test actually
 * runs instead of being skipped by the fake.
 */
static void fakeNextInit(tunnel_t *t, line_t *l)
{
    twf_trace_t *trace = *(twf_trace_t **) tunnelGetState(t);
    ++trace->next_init;

    if (! g_next_accepts_init)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

static void fixtureSetup(wireguarddevice_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&g_env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    fixture->wgd = tunnelCreate(NULL, sizeof(wgd_tstate_t), sizeof(wgd_lstate_t));
    twfRequire(fixture->wgd != NULL, "failed to create the WireGuardDevice tunnel");
    // The line owner's own Finish handler, which is what releases a rejected
    // transport line.
    fixture->wgd->fnFinD = &wireguarddeviceTunnelDownStreamFinish;

    fixture->next          = twfCreateNextTunnel(&fixture->trace);
    fixture->next->fnInitU = fakeNextInit;
    tunnelBind(fixture->wgd, fixture->next);

    // A one-worker chain with a real line pool, because the retry has to be able
    // to actually create a second line.
    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the test chain");
    fixture->chain->workers_count = 1;
    fixture->line_master          = masterpoolCreateWithCapacity(2 * kTestLinePoolItems);
    twfRequire(fixture->line_master != NULL, "failed to create the test line master pool");
    fixture->chain->line_pools[0] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        fixture->line_master, sizeof(line_t) + fixture->wgd->lstate_size, kTestLinePoolItems);
    fixture->wgd->chain = fixture->chain;

    // WireGuardDevice is dual-role: it also sits on the chain's persistent worker
    // packet line, which is what makes the role check in its Finish handler
    // load-bearing.
    fixture->chain->contains_packet_node = true;
    fixture->packet_line_slots[0]        = lineCreateForWorker(0, fixture->chain->line_pools, 0);
    fixture->chain->packet_lines         = fixture->packet_line_slots;

    wgd_tstate_t *state           = tunnelGetState(fixture->wgd);
    state->tunnel                 = fixture->wgd;
    state->transport_side_is_next = true;
    state->transport_lines        = fixture->transport_line_slots;
}

static void fixtureTeardown(wireguarddevice_fixture_t *fixture)
{
    // Close whatever transport line is still live through the owner's own
    // helper, so the line returns to its pool before the pool is destroyed.
    const wid_t previous_wid = tosSetCurrentWorker(0);
    wireguarddeviceCloseTransportLine(fixture->wgd, 0);
    discard tosSetCurrentWorker(previous_wid);
    twfRequire(fixture->transport_line_slots[0] == NULL, "teardown must close the accepted transport line");

    // tunnelchainDestroy() is the only place a packet line may ever be released.
    lineDestroy(fixture->packet_line_slots[0]);

    genericpoolDestroy(fixture->chain->line_pools[0]);
    masterpoolDestroy(fixture->line_master);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->wgd);
    tosWorkerEnvTeardown(&g_env);
}

// ---------------------------------------------------------------------------
// A rejected transport line is local and retryable
// ---------------------------------------------------------------------------

static void caseRejectionIsRetriedSuccessfully(void)
{
    twfSetCase("wireguarddevice transport line rejected then retried");
    tosResetProcessApi(true);

    wireguarddevice_fixture_t fixture;
    fixtureSetup(&fixture);

    wgd_tstate_t *state = tunnelGetState(fixture.wgd);

    // First attempt: the neighbour rejects this one line.
    g_next_accepts_init = false;
    line_t *rejected    = wireguarddeviceEnsureTransportLine(state, 0);

    tosRequireNoProcessApiCall();
    twfRequire(rejected == NULL, "a rejected transport line must be reported as NULL");
    twfRequire(fixture.transport_line_slots[0] == NULL, "a rejected transport line must leave the slot NULL");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the neighbour must have been asked once");

    // Later output retries and succeeds, which is what makes the startup task's
    // local return correct rather than a silently dead worker.
    g_next_accepts_init = true;
    line_t *accepted    = wireguarddeviceEnsureTransportLine(state, 0);

    tosRequireNoProcessApiCall();
    twfRequire(accepted != NULL, "the retry must create a transport line");
    twfRequire(fixture.transport_line_slots[0] == accepted, "the retry must publish its line");
    twfRequire(lineIsAlive(accepted), "the retried transport line must be alive");
    twfRequireEqualU32(fixture.trace.next_init, 2, "the retry must reach the neighbour again");

    // A third call must reuse the live line instead of creating another.
    line_t *reused = wireguarddeviceEnsureTransportLine(state, 0);
    twfRequire(reused == accepted, "a live transport line must be reused");
    twfRequireEqualU32(fixture.trace.next_init, 2, "reusing a live line must not re-init the neighbour");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// The same handler, on the persistent worker packet line
// ---------------------------------------------------------------------------
//
// A transport line is an ordinary owned line and dies on Finish; the packet line
// belongs to the chain and is destroyed only by tunnelchainDestroy(). One handler
// serves both, so a Finish arriving on the packet line is a neighbour breaking
// the packet-line contract, not a close - it must abort rather than return, and
// it must never destroy the line.

static void packetLineFinishBody(void *argument)
{
    discard argument;

    wireguarddevice_fixture_t fixture;
    fixtureSetup(&fixture);

    const wid_t previous_wid = tosSetCurrentWorker(0);
    wireguarddeviceHandleTransportLineFinish(fixture.wgd, fixture.packet_line_slots[0]);
    discard tosSetCurrentWorker(previous_wid);
}

static void casePacketLineFinishAborts(void)
{
    twfSetCase("wireguarddevice Finish on the worker packet line");

    // The handoff would be accepted, so landing on the direct abort proves this
    // branch never treats a packet line as an orderly runtime failure.
    tosResetProcessApi(true);
    tosRequireChildExit("the packet-line Finish", packetLineFinishBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// An owned transport line, finished by its neighbour
// ---------------------------------------------------------------------------

static void caseTransportLineFinishKillsLine(void)
{
    twfSetCase("wireguarddevice Finish on an owned transport line");
    tosResetProcessApi(true);

    wireguarddevice_fixture_t fixture;
    fixtureSetup(&fixture);

    g_next_accepts_init      = true;
    const wid_t previous_wid = tosSetCurrentWorker(0);
    line_t     *transport    = wireguarddeviceEnsureTransportLine(tunnelGetState(fixture.wgd), 0);
    twfRequire(transport != NULL, "the fixture must create a transport line");

    twfRunOwnerFinish(
        fixture.wgd, transport, wireguarddeviceTunnelDownStreamFinish, "wireguarddeviceTunnelDownStreamFinish");

    tosRequireNoProcessApiCall();
    twfRequire(fixture.transport_line_slots[0] == NULL, "the closed transport line must be detached from its slot");
    twfRequire(lineIsAlive(fixture.packet_line_slots[0]), "closing a transport line must not touch the packet line");

    twfRequireOwnedLineReclaimed(transport, "wireguarddeviceTunnelDownStreamFinish");
    discard tosSetCurrentWorker(previous_wid);

    fixtureTeardown(&fixture);
}

typedef struct wireguarddevice_start_fixture_s
{
    tunnel_t       *wgd;
    tunnel_t       *next;
    tunnel_chain_t *chain;
    line_t        **packet_lines;
} wireguarddevice_start_fixture_t;

static wireguarddevice_start_fixture_t startFixtureCreate(bool transport_side_is_next)
{
    wireguarddevice_start_fixture_t fixture = {0};
    fixture.wgd                             = tunnelCreate(NULL, sizeof(wgd_tstate_t), 0);
    fixture.next                            = tunnelCreate(NULL, 0, 0);
    fixture.chain        = memoryAllocateZero(sizeof(tunnel_chain_t) + 3U * sizeof(generic_pool_t *));
    fixture.packet_lines = memoryAllocateZero(3U * sizeof(*fixture.packet_lines));
    twfRequire(fixture.wgd != NULL && fixture.next != NULL && fixture.chain != NULL && fixture.packet_lines != NULL,
               "failed to allocate the WireGuard startup fixture");

    fixture.chain->workers_count = 3;
    fixture.chain->packet_lines  = fixture.packet_lines;
    for (wid_t wid = 0; wid < fixture.chain->workers_count; ++wid)
    {
        fixture.packet_lines[wid] = (line_t *) (uintptr_t) (wid + 1U);
    }
    fixture.wgd->chain  = fixture.chain;
    fixture.next->chain = fixture.chain;
    tunnelBind(fixture.wgd, fixture.next);

    wgd_tstate_t *state           = tunnelGetState(fixture.wgd);
    state->tunnel                 = fixture.wgd;
    state->transport_side_is_next = transport_side_is_next;
    return fixture;
}

static void startFixtureDestroy(wireguarddevice_start_fixture_t *fixture)
{
    wgd_tstate_t *state = tunnelGetState(fixture->wgd);
    memoryFree(state->transport_lines);
    state->transport_lines      = NULL;
    state->wg_device.loop_timer = NULL;
    memoryFree(fixture->packet_lines);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->wgd);
    memoryZero(fixture, sizeof(*fixture));
}

static void resetStartupInjection(tunnel_t *t)
{
    g_start_tunnel           = t;
    g_fail_transport_storage = false;
    g_refuse_queue_at        = -1;
    g_queue_attempts         = 0;
    g_timer_attempts         = 0;
    memoryZero(&g_fake_timer, sizeof(g_fake_timer));
}

static void allocationFailureBody(void *argument)
{
    discard                         argument;
    wireguarddevice_start_fixture_t fixture = startFixtureCreate(true);
    resetStartupInjection(fixture.wgd);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    g_fail_transport_storage = true;
    wireguarddeviceTunnelOnStart(fixture.wgd);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(! wwStartupSucceeded(result), "WireGuard did not propagate the storage startup failure");
    twfRequireEqualU32((uint32_t) result.exit_code, 1, "WireGuard propagated the wrong startup status");
    startFixtureDestroy(&fixture);
}

typedef struct startup_refusal_case_s
{
    bool transport_side_is_next;
    int  refusal;
} startup_refusal_case_t;

static void startupRefusalBody(void *argument)
{
    const startup_refusal_case_t   *test_case = argument;
    wireguarddevice_start_fixture_t fixture   = startFixtureCreate(test_case->transport_side_is_next);
    resetStartupInjection(fixture.wgd);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    g_refuse_queue_at = test_case->refusal;
    wireguarddeviceTunnelOnStart(fixture.wgd);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(! wwStartupSucceeded(result), "WireGuard did not propagate the queue-admission startup failure");
    twfRequireEqualU32((uint32_t) result.exit_code, 1, "WireGuard propagated the wrong startup status");
    startFixtureDestroy(&fixture);
}

static void caseStartupStorageAndAdmissionAreTransactional(void)
{
    twfSetCase("WireGuard mandatory startup storage and queue admission");
    tosWorkerEnvSetup(&g_env, 3, kTestLargeBufferSize, kTestSmallBufferSize);
    tosResetProcessApi(true);
    allocationFailureBody(NULL);

    for (int worker = 0; worker < 3; ++worker)
    {
        startup_refusal_case_t transport = {.transport_side_is_next = true, .refusal = worker};
        startupRefusalBody(&transport);

        startup_refusal_case_t packet = {.transport_side_is_next = false, .refusal = 3 + worker};
        startupRefusalBody(&packet);
    }

    wireguarddevice_start_fixture_t fixture = startFixtureCreate(false);
    resetStartupInjection(fixture.wgd);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    wireguarddeviceTunnelOnStart(fixture.wgd);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(wwStartupSucceeded(result), "successful WireGuard startup reported a failure");
    wgd_tstate_t *state = tunnelGetState(fixture.wgd);
    twfRequire(state->transport_lines != NULL, "successful startup did not publish the mandatory line table");
    twfRequire(fixture.chain->packet_chain_init_sent, "successful startup did not publish all-worker packet readiness");
    twfRequireEqualU32(g_queue_attempts, 6, "successful startup omitted a per-worker required task");
    twfRequireEqualU32(g_timer_attempts, 1, "successful startup did not publish exactly one timer");
    startFixtureDestroy(&fixture);
    tosWorkerEnvTeardown(&g_env);
}

int main(void)
{
    caseStartupStorageAndAdmissionAreTransactional();
    caseRejectionIsRetriedSuccessfully();
    caseTransportLineFinishKillsLine();
    casePacketLineFinishAborts();

    printf("wireguarddevice_orderly_shutdown_test: all cases passed\n");
    return 0;
}

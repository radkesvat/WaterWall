/*
 * PacketSender deadline timer failure injection.
 *
 * The send loop paces itself against a shared monotonic schedule: when the next
 * packet's deadline has not arrived it arms a one-shot timer and returns. If
 * that timer cannot be created the worker can neither pace nor resume, so the
 * failure must request an orderly shutdown and stop the loop. The dangerous
 * regression is a timer failure being read as "the deadline arrived", which
 * would send every remaining packet as fast as the loop can spin.
 */
#include "PacketSender/structure.h"

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
    // Long enough that packet 1's deadline is always still in the future.
    kTestDurationMs = 1000000
};

typedef struct packetsender_fixture_s
{
    twf_worker_env_t            env;
    twf_trace_t                 trace;
    tunnel_t                   *sender;
    tunnel_t                   *next;
    tunnel_chain_t             *chain;
    line_t                     *packet_line;
    line_t                     *packet_line_slot[1];
    packetsender_worker_state_t worker_slots[1];
    packetsender_source_range_t source_ranges[1];
    uint8_t                     packet_bytes[2];
    worker_t                    worker;
} packetsender_fixture_t;

static void fixtureSetup(packetsender_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->sender = tunnelCreate(NULL, sizeof(packetsender_tstate_t), sizeof(packetsender_lstate_t));
    twfRequire(fixture->sender != NULL, "failed to create the PacketSender tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->sender, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the test chain");
    fixture->chain->workers_count = 1;
    fixture->sender->chain        = fixture->chain;

    fixture->packet_line         = twfLineCreate(fixture->sender->lstate_size);
    fixture->packet_line_slot[0] = fixture->packet_line;
    fixture->chain->packet_lines = fixture->packet_line_slot;

    packetsender_tstate_t *state   = tunnelGetState(fixture->sender);
    state->duration_ms             = kTestDurationMs;
    state->total_packets           = 2;
    state->source_ranges           = fixture->source_ranges;
    state->source_range_count      = 1;
    state->source_count            = 1;
    state->packets_per_ip          = 2;
    state->protocol_mode           = kPacketSenderProtocolIcmp;
    state->fixed_packet_length     = 1;
    state->bytes_per_source        = sizeof(fixture->packet_bytes);
    state->bytes_per_source_repeat = 1;
    state->packet_bytes            = fixture->packet_bytes;
    state->workers_count           = 1;
    state->active_workers          = 1;
    state->workers                 = fixture->worker_slots;
    // Same monotonic base packetsenderPrepareRuntime publishes, so no time has
    // elapsed against the schedule yet.
    state->schedule_start_ms = getHRTimeUs() / 1000U;

    // This worker owns only packet 1, whose deadline is the full duration away,
    // so the very first loop iteration has to wait rather than send.
    packetsender_worker_state_t *slot = &fixture->worker_slots[0];
    slot->tunnel                      = fixture->sender;
    slot->wid                         = 0;
    slot->packet_index_begin          = 1;
    slot->packet_index_end            = 2;
    slot->next_packet_index           = 1;

    fixture->worker.wid  = 0;
    fixture->worker.loop = getWorkerLoop(0);

    fixture->source_ranges[0].base_host = UINT32_C(0xC6336401);
    fixture->source_ranges[0].count     = 1;
}

static void fixtureTeardown(packetsender_fixture_t *fixture)
{
    twfLineDestroy(fixture->packet_line);
    memoryFree(fixture->chain);
}

// ---------------------------------------------------------------------------
// The healthy path must still pace itself
// ---------------------------------------------------------------------------

static void caseHealthyWorkerArmsTheTimer(void)
{
    twfSetCase("packetsender deadline wait with a working timer");
    tosResetProcessApi(true);

    packetsender_fixture_t fixture;
    fixtureSetup(&fixture);

    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);

    tosRequireNoProcessApiCall();
    twfRequire(fixture.worker_slots[0].timer != NULL, "a healthy wait must arm the deadline timer");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the deadline has not arrived, so nothing may be sent");

    weventSetUserData(fixture.worker_slots[0].timer, NULL);
    wtimerDelete(fixture.worker_slots[0].timer);
    fixture.worker_slots[0].timer = NULL;

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Downstream Finish must stop a pending timer
// ---------------------------------------------------------------------------

static void caseDownstreamFinishCancelsPendingTimer(void)
{
    twfSetCase("packetsender downstream Finish cancels a pending timer");
    tosResetProcessApi(true);

    packetsender_fixture_t fixture;
    fixtureSetup(&fixture);

    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);

    packetsender_worker_state_t *slot = &fixture.worker_slots[0];
    twfRequire(slot->timer != NULL, "the pending packet must have armed its timer");
    twfRequireEqualU32((uint32_t) fixture.env.loop->ntimers, 1, "the worker loop must own the pending timer");

    packetsenderTunnelDownStreamFinish(fixture.sender, fixture.packet_line);

    tosRequireNoProcessApiCall();
    twfRequire(slot->stopped, "downstream Finish must stop this worker");
    twfRequire(slot->timer == NULL, "downstream Finish must clear the worker timer slot");
    twfRequireEqualU32((uint32_t) fixture.env.loop->ntimers, 0, "downstream Finish must delete the pending timer");
    twfRequire(lineIsAlive(fixture.packet_line), "PacketSender must not destroy the chain-owned packet line");

    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a stopped worker must not restart sending");
    twfRequire(slot->timer == NULL, "a stopped worker must not re-arm its timer");
    twfRequireNoLeakedBuffers();

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// A payload may emit Finish re-entrantly
// ---------------------------------------------------------------------------

static tunnel_t *g_reentrant_finish_sender = NULL;

static void finishSenderDuringPayload(tunnel_t *next, line_t *l, sbuf_t *buf)
{
    twfNextPayload(next, l, buf);
    packetsenderTunnelDownStreamFinish(g_reentrant_finish_sender, l);
}

static void caseReentrantFinishStopsReadyBatch(void)
{
    twfSetCase("packetsender re-entrant downstream Finish stops a ready batch");
    tosResetProcessApi(true);

    packetsender_fixture_t fixture;
    fixtureSetup(&fixture);

    packetsender_tstate_t       *state = tunnelGetState(fixture.sender);
    packetsender_worker_state_t *slot  = &fixture.worker_slots[0];

    const uint64_t now_ms    = getHRTimeUs() / 1000U;
    state->duration_ms       = 1;
    state->schedule_start_ms = (now_ms > 2U) ? (now_ms - 2U) : 0;
    slot->packet_index_begin = 0;
    slot->packet_index_end   = 2;
    slot->next_packet_index  = 0;

    g_reentrant_finish_sender = fixture.sender;
    fixture.next->fnPayloadU  = finishSenderDuringPayload;

    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);

    g_reentrant_finish_sender = NULL;

    tosRequireNoProcessApiCall();
    twfRequireEqualU32(fixture.trace.next_payload, 1, "no payload may follow the re-entrant Finish");
    twfRequire(slot->stopped, "the re-entrant Finish must stop this worker");
    twfRequireEqualU32(
        (uint32_t) slot->next_packet_index, 1, "the payload accepted before Finish must be counted exactly once");
    twfRequire(slot->timer == NULL, "the stopped worker must not retain or arm a timer");
    twfRequire(lineIsAlive(fixture.packet_line), "PacketSender must leave the worker packet line alive");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&state->completed_workers),
                       0,
                       "a stopped worker must not be reported as fully transmitted");
    twfRequireNoLeakedBuffers();

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the deadline timer cannot be created
// ---------------------------------------------------------------------------

static void caseDeadlineTimerFailure(void)
{
    twfSetCase("packetsender deadline timer failure");
    tosResetProcessApi(true);

    packetsender_fixture_t fixture;
    fixtureSetup(&fixture);

    const uint32_t recycles_before = twfRecycleCount();

    g_timer_fails = true;
    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);
    g_timer_fails = false;

    tosRequireAcceptedRequest(1);

    // A timer failure must never be read as "the deadline arrived": the queued
    // packet stays queued and the worker never reports itself finished.
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a timer failure must not send the pending packet");
    twfRequireEqualU32(
        (uint32_t) fixture.worker_slots[0].next_packet_index, 1, "a timer failure must not advance next_packet_index");
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&((packetsender_tstate_t *) tunnelGetState(fixture.sender))->completed_workers),
        0,
        "a timer failure must not mark the worker complete");
    twfRequire(fixture.worker_slots[0].timer == NULL, "the failed timer slot must stay NULL");
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 0, "no packet buffer may be allocated after the failure");
    twfRequireNoLeakedBuffers();

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    packetsender_fixture_t fixture;
    fixtureSetup(&fixture);

    g_timer_fails = true;
    packetsenderStartWorker(&fixture.worker, fixture.sender, NULL, NULL);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("packetsender deadline timer failure with a refused handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff timer failure", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    caseHealthyWorkerArmsTheTimer();
    caseDownstreamFinishCancelsPendingTimer();
    caseReentrantFinishStopsReadyBatch();
    caseDeadlineTimerFailure();
    caseRefusedHandoffAborts();

    printf("packetsender_orderly_shutdown_test: all cases passed\n");
    return 0;
}

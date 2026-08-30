/*
 * Disturber packet-line lifecycle coverage.
 *
 * Disturber is a transparent packet transform.  A packet Finish must travel in
 * the same direction, retained out-of-order traffic must be settled, and a
 * delayed task admitted before Finish must not later publish toward the closed
 * side.  Packet line state is also worker-affine and must be drained by that
 * worker without destroying the chain-owned line.
 */
#include "Disturber/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kDisturberTestWorkerCount = 2,
    kDisturberTestLargeBuffer = 8192,
    kDisturberTestSmallBuffer = 1024,
};

typedef struct disturber_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *disturber;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_lines[kDisturberTestWorkerCount];
} disturber_fixture_t;

static void fixtureSetup(disturber_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, kDisturberTestWorkerCount, kDisturberTestLargeBuffer, kDisturberTestSmallBuffer);

    fixture->prev      = twfCreatePrevTunnel(&fixture->trace);
    fixture->disturber = tunnelCreate(NULL, sizeof(disturber_tstate_t), sizeof(disturber_lstate_t));
    fixture->next      = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->disturber != NULL, "failed to create the Disturber tunnel");
    tunnelBind(fixture->prev, fixture->disturber);
    tunnelBind(fixture->disturber, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + kDisturberTestWorkerCount * sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the packet-line fixture chain");
    fixture->chain->workers_count        = kDisturberTestWorkerCount;
    fixture->chain->contains_packet_node = true;
    fixture->chain->finalized            = true;
    fixture->chain->packet_lines         = fixture->packet_lines;
    fixture->disturber->chain            = fixture->chain;

    for (wid_t wid = 0; wid < kDisturberTestWorkerCount; ++wid)
    {
        line_t *line               = twfLineCreate(fixture->disturber->lstate_size);
        line->wid                  = wid;
        fixture->packet_lines[wid] = line;

        const wid_t previous_wid = tosSetCurrentWorker(wid);
        disturberLinestateInitialize(lineGetState(line, fixture->disturber));
        discard tosSetCurrentWorker(previous_wid);
    }

    disturber_tstate_t *state = tunnelGetState(fixture->disturber);
    state->disturb_upstream   = true;
    state->disturb_downstream = true;
}

static void fixtureTeardown(disturber_fixture_t *fixture)
{
    /* Production onWorkerStop drains packet state before tunnel Destroy, while
     * the chain-owned packet lines remain published. Mirror that order here:
     * Destroy verifies those live lines and must never inspect freed fixture
     * line memory. */
    for (wid_t wid = 0; wid < kDisturberTestWorkerCount; ++wid)
    {
        line_t *line = fixture->packet_lines[wid];
        if (line == NULL)
        {
            continue;
        }

        const wid_t previous_wid = tosSetCurrentWorker(wid);
        disturberLinestateDestroy(line, lineGetState(line, fixture->disturber));
        discard tosSetCurrentWorker(previous_wid);
    }

    disturberTunnelDestroy(fixture->disturber, wwLifecycleProcessShutdown());
    fixture->disturber = NULL;

    for (wid_t wid = 0; wid < kDisturberTestWorkerCount; ++wid)
    {
        line_t *line = fixture->packet_lines[wid];
        if (line == NULL)
        {
            continue;
        }

        /* This frees only the bare test fixture after all runtime assertions.
         * Production packet lines stay alive until tunnelchainDestroy(). */
        twfLineDestroy(line);
    }

    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->prev);
    tosWorkerEnvTeardown(&fixture->env);
}

static sbuf_t *fixturePayload(line_t *line, uint8_t value)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 1);
    sbufGetMutablePtr(buf)[0] = value;
    return buf;
}

static void caseUpstreamFinishSuppressesScheduledDelayedPayload(void)
{
    twfSetCase("disturber upstream packet Finish suppresses a scheduled delayed payload");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state   = tunnelGetState(fixture.disturber);
    state->chance_payload_delay = 100;
    state->delay_min_ms         = 1;
    state->delay_max_ms         = 1;

    line_t        *line            = fixture.packet_lines[0];
    const uint32_t recycles_before = twfRecycleCount();

    sbuf_t *payload = fixturePayload(line, UINT8_C(0xA1));
    disturberTunnelUpStreamPayload(fixture.disturber, line, payload);
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the delayed payload ran inline instead of being scheduled");
    twfRequire(twfLineRefCount(line) > 1, "the scheduled payload did not retain the packet line");
    twfRequireEqualU32(
        (uint32_t) fixture.env.loops[0]->ntimers, 1, "the delayed payload did not arm its owner-worker timer");

    disturberTunnelUpStreamFinish(fixture.disturber, line);
    twfRequireEqualU32(fixture.trace.next_finish, 1, "upstream packet Finish was not forwarded toward next");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "upstream packet Finish was reflected toward prev");
    twfRequire(((disturber_lstate_t *) lineGetState(line, fixture.disturber))->upstream.finished,
               "upstream packet Finish did not close the upstream publish direction");
    twfRequire(lineIsAlive(line), "Disturber destroyed the chain-owned packet line on upstream Finish");

    /* Let the real owner-worker timer become due, then drive its callback.
     * The callback must settle the retained buffer rather than publish it after
     * Finish. */
    wwSleepMS(20);
    tosPumpWorker(&fixture.env, 0);

    twfRequireEqualU32(
        fixture.trace.next_payload, 0, "a delayed payload admitted before Finish was forwarded after Finish");
    /* Waking the test event loop also recycles its eventfd read buffer. The
     * ledger proves the exact payload left local ownership without coupling the
     * assertion to that unrelated loop housekeeping. */
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, payload),
               "the suppressed delayed payload was not settled");
    twfRequire(twfRecycleCount() > recycles_before, "the scheduled payload did not reach a recycle path");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseDownstreamFinishSettlesHeldPayload(void)
{
    twfSetCase("disturber downstream packet Finish settles a held payload");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state          = tunnelGetState(fixture.disturber);
    state->chance_payload_out_of_order = 100;

    line_t        *line            = fixture.packet_lines[1];
    const wid_t    previous_wid    = tosSetCurrentWorker(1);
    const uint32_t recycles_before = twfRecycleCount();

    disturberTunnelDownStreamPayload(fixture.disturber, line, fixturePayload(line, UINT8_C(0xB2)));
    disturber_lstate_t *ls = lineGetState(line, fixture.disturber);
    twfRequire(ls->downstream.held_payload != NULL, "out-of-order downstream payload was not held");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "the held downstream payload was forwarded early");

    disturberTunnelDownStreamFinish(fixture.disturber, line);
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "downstream packet Finish was not forwarded toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "downstream packet Finish was reflected toward next");
    twfRequire(ls->downstream.finished, "downstream packet Finish did not close the downstream publish direction");
    twfRequire(ls->downstream.held_payload == NULL, "downstream held payload survived Finish");
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "downstream held payload was not recycled exactly once");
    twfRequire(lineIsAlive(line), "Disturber destroyed the chain-owned packet line on downstream Finish");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void caseUpstreamFinishSuppressesQueuedDownstreamReflection(void)
{
    twfSetCase("disturber upstream packet Finish suppresses queued downstream reflection");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state   = tunnelGetState(fixture.disturber);
    state->chance_payload_delay = 100;
    state->delay_min_ms         = 1;
    state->delay_max_ms         = 1;

    line_t *line    = fixture.packet_lines[0];
    sbuf_t *payload = fixturePayload(line, UINT8_C(0xB3));
    disturberTunnelDownStreamPayload(fixture.disturber, line, payload);
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "the delayed downstream payload ran inline");

    disturberTunnelUpStreamFinish(fixture.disturber, line);
    disturber_lstate_t *ls = lineGetState(line, fixture.disturber);
    twfRequire(ls->upstream.finished && ls->downstream.finished,
               "upstream packet Finish did not terminalize both publication directions");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "upstream packet Finish did not propagate toward next");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "upstream packet Finish reflected toward prev");

    wwSleepMS(20);
    tosPumpWorker(&fixture.env, 0);

    twfRequireEqualU32(
        fixture.trace.prev_payload, 0, "queued downstream payload reflected toward the upstream Finish sender");
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, payload),
               "the suppressed downstream payload was not settled");
    twfRequire(lineIsAlive(line), "cross-direction suppression destroyed the chain-owned packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseDownstreamFinishSuppressesQueuedUpstreamReflection(void)
{
    twfSetCase("disturber downstream packet Finish suppresses queued upstream reflection");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state   = tunnelGetState(fixture.disturber);
    state->chance_payload_delay = 100;
    state->delay_min_ms         = 1;
    state->delay_max_ms         = 1;

    line_t *line    = fixture.packet_lines[0];
    sbuf_t *payload = fixturePayload(line, UINT8_C(0xB4));
    disturberTunnelUpStreamPayload(fixture.disturber, line, payload);
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the delayed upstream payload ran inline");

    disturberTunnelDownStreamFinish(fixture.disturber, line);
    disturber_lstate_t *ls = lineGetState(line, fixture.disturber);
    twfRequire(ls->upstream.finished && ls->downstream.finished,
               "downstream packet Finish did not terminalize both publication directions");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "downstream packet Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "downstream packet Finish reflected toward next");

    wwSleepMS(20);
    tosPumpWorker(&fixture.env, 0);

    twfRequireEqualU32(
        fixture.trace.next_payload, 0, "queued upstream payload reflected toward the downstream Finish sender");
    twfRequire(! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, payload),
               "the suppressed upstream payload was not settled");
    twfRequire(lineIsAlive(line), "cross-direction suppression destroyed the chain-owned packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseWorkerStopSettlesPacketStateOnOwnerWorker(void)
{
    twfSetCase("disturber worker Stop settles packet state on worker 1");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state          = tunnelGetState(fixture.disturber);
    state->chance_payload_out_of_order = 100;

    line_t        *line            = fixture.packet_lines[1];
    const wid_t    previous_wid    = tosSetCurrentWorker(1);
    const uint32_t recycles_before = twfRecycleCount();

    disturberTunnelUpStreamPayload(fixture.disturber, line, fixturePayload(line, UINT8_C(0xC3)));
    twfRequire(((disturber_lstate_t *) lineGetState(line, fixture.disturber))->upstream.held_payload != NULL,
               "the owner-worker fixture did not retain an upstream payload");

    disturberTunnelOnWorkerStop(fixture.disturber, 1, wwLifecycleProcessShutdown());

    twfRequireLineStateZeroed(line, fixture.disturber, "worker Stop left Disturber packet state behind");
    twfRequireEqualU32(
        twfRecycleCount() - recycles_before, 1, "worker Stop did not recycle the owner worker's retained packet");
    twfRequire(lineIsAlive(line), "worker Stop destroyed the chain-owned packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    /* Idempotence is needed for a partially initialized packet slot. */
    disturberTunnelOnWorkerStop(fixture.disturber, 1, wwLifecycleProcessShutdown());
    twfRequire(lineIsAlive(line), "a repeated worker Stop destroyed the packet line");

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void caseWorkerStopAllowsFinalizedStreamOnlySlot(void)
{
    twfSetCase("disturber worker Stop tolerates a finalized stream-only packet slot");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t *saved_packet_line           = fixture.packet_lines[1];
    fixture.packet_lines[1]             = NULL;
    fixture.chain->contains_packet_node = false;
    const wid_t previous_wid            = tosSetCurrentWorker(1);

    disturberTunnelOnWorkerStop(fixture.disturber, 1, wwLifecycleProcessShutdown());

    discard tosSetCurrentWorker(previous_wid);
    fixture.packet_lines[1]             = saved_packet_line;
    fixture.chain->contains_packet_node = true;
    twfRequire(lineIsAlive(saved_packet_line), "worker Stop destroyed a finalized stream-only packet slot");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseValidNormalLineInPacketChainKeepsNormalFinishRole(void)
{
    twfSetCase("disturber normal line in a packet-containing chain keeps normal Finish role");
    tosResetProcessApi(true);

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t             *normal_line = twfLineCreate(fixture.disturber->lstate_size);
    disturber_lstate_t *ls          = lineGetState(normal_line, fixture.disturber);
    disturberLinestateInitialize(ls);
    ls->upstream.held_payload = fixturePayload(normal_line, UINT8_C(0xD1));

    const uint32_t recycles_before = twfRecycleCount();
    disturberTunnelUpStreamFinish(fixture.disturber, normal_line);

    twfRequireEqualU32(fixture.trace.next_finish, 1, "normal upstream Finish did not propagate toward next");
    twfRequireLineStateZeroed(normal_line, fixture.disturber, "normal Finish retained Disturber line state");
    twfRequireEqualU32(
        twfRecycleCount() - recycles_before, 1, "normal Finish did not recycle its retained payload exactly once");
    twfRequire(lineIsAlive(normal_line), "Disturber destroyed a borrowed normal line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    twfLineDestroy(normal_line);
    fixtureTeardown(&fixture);
}

typedef enum disturber_finalized_geometry_case_e
{
    kDisturberFinalizedGeometryMissingSlots,
    kDisturberFinalizedGeometryMissingPacketSlot,
    kDisturberFinalizedGeometryOutOfRangeWorker,
    kDisturberFinalizedGeometryWrongCurrentWorker,
    kDisturberFinalizedGeometryUnexpectedStreamOnlyPacketSlot,
    kDisturberFinalizedGeometryPacketFinishMissingSlots,
    kDisturberFinalizedGeometryPacketFinishMissingPacketSlot,
    kDisturberFinalizedGeometryPacketFinishWrongSlotOwner,
    kDisturberFinalizedGeometryPacketFinishOnStreamOnlyTopology,
    kDisturberFinalizedGeometryPacketFinishWrongCurrentWorker,
    kDisturberFinalizedGeometryLineStateDestroyWrongCurrentWorker,
    kDisturberFinalizedGeometryDestroyMissingSlots,
    kDisturberFinalizedGeometryDestroyMissingPacketSlot,
    kDisturberFinalizedGeometryDestroyWrongSlotOwner,
    kDisturberFinalizedGeometryDestroyUnexpectedStreamOnlyPacketSlot,
} disturber_finalized_geometry_case_e;

static void finalizedGeometryAbortBody(void *argument)
{
    const disturber_finalized_geometry_case_e geometry = (disturber_finalized_geometry_case_e) (uintptr_t) argument;

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);
    line_t *packet_line_0 = fixture.packet_lines[0];

    switch (geometry)
    {
    case kDisturberFinalizedGeometryMissingSlots:
        fixture.chain->packet_lines = NULL;
        disturberTunnelOnWorkerStop(fixture.disturber, 0, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryMissingPacketSlot:
        fixture.packet_lines[0] = NULL;
        disturberTunnelOnWorkerStop(fixture.disturber, 0, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryOutOfRangeWorker:
        disturberTunnelOnWorkerStop(fixture.disturber, kDisturberTestWorkerCount, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryWrongCurrentWorker:
        discard tosSetCurrentWorker(0);
        disturberTunnelOnWorkerStop(fixture.disturber, 1, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryUnexpectedStreamOnlyPacketSlot:
        fixture.chain->contains_packet_node = false;
        disturberTunnelOnWorkerStop(fixture.disturber, 0, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryPacketFinishMissingSlots:
        fixture.chain->packet_lines = NULL;
        disturberTunnelUpStreamFinish(fixture.disturber, packet_line_0);
        break;
    case kDisturberFinalizedGeometryPacketFinishMissingPacketSlot:
        fixture.packet_lines[0] = NULL;
        disturberTunnelUpStreamFinish(fixture.disturber, packet_line_0);
        break;
    case kDisturberFinalizedGeometryPacketFinishWrongSlotOwner:
        packet_line_0->wid = 1;
        disturberTunnelUpStreamFinish(fixture.disturber, packet_line_0);
        break;
    case kDisturberFinalizedGeometryPacketFinishOnStreamOnlyTopology:
        fixture.chain->contains_packet_node = false;
        disturberTunnelUpStreamFinish(fixture.disturber, fixture.packet_lines[0]);
        break;
    case kDisturberFinalizedGeometryPacketFinishWrongCurrentWorker:
        discard tosSetCurrentWorker(0);
        disturberPacketLineFinish(fixture.disturber, fixture.packet_lines[1], kDisturberPayloadDirectionUpstream);
        break;
    case kDisturberFinalizedGeometryLineStateDestroyWrongCurrentWorker:
        discard tosSetCurrentWorker(0);
        disturberLinestateDestroy(fixture.packet_lines[1], lineGetState(fixture.packet_lines[1], fixture.disturber));
        break;
    case kDisturberFinalizedGeometryDestroyMissingSlots:
        fixture.chain->packet_lines = NULL;
        disturberTunnelDestroy(fixture.disturber, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryDestroyMissingPacketSlot:
        fixture.packet_lines[0] = NULL;
        disturberTunnelDestroy(fixture.disturber, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryDestroyWrongSlotOwner:
        packet_line_0->wid = 1;
        disturberTunnelDestroy(fixture.disturber, wwLifecycleProcessShutdown());
        break;
    case kDisturberFinalizedGeometryDestroyUnexpectedStreamOnlyPacketSlot:
        fixture.chain->contains_packet_node = false;
        disturberTunnelDestroy(fixture.disturber, wwLifecycleProcessShutdown());
        break;
    }
}

static void caseFinalizedPacketGeometryAborts(void)
{
    twfSetCase("disturber finalized packet geometry is release-fatal");
    tosResetProcessApi(true);

    tosRequireChildExit("missing finalized packet-line slots",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryMissingSlots,
                        kTosChildDirectAbort);
    tosRequireChildExit("a missing finalized packet line",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryMissingPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("an out-of-range finalized packet worker",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryOutOfRangeWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("a foreign worker Stop callback",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryWrongCurrentWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("a stream-only finalized packet slot",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryUnexpectedStreamOnlyPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("runtime packet Finish with missing finalized packet-line slots",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryPacketFinishMissingSlots,
                        kTosChildDirectAbort);
    tosRequireChildExit("runtime packet Finish with a missing finalized packet line",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryPacketFinishMissingPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("runtime packet Finish with a mis-owned finalized packet slot",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryPacketFinishWrongSlotOwner,
                        kTosChildDirectAbort);
    tosRequireChildExit("a packet Finish on a stream-only topology",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryPacketFinishOnStreamOnlyTopology,
                        kTosChildDirectAbort);
    tosRequireChildExit("a foreign worker packet Finish callback",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryPacketFinishWrongCurrentWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("foreign worker packet state destruction",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryLineStateDestroyWrongCurrentWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy missing finalized packet-line slots",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryDestroyMissingSlots,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy missing a finalized packet line",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryDestroyMissingPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy with a mis-owned finalized packet slot",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryDestroyWrongSlotOwner,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy with a stream-only finalized packet slot",
                        finalizedGeometryAbortBody,
                        (void *) (uintptr_t) kDisturberFinalizedGeometryDestroyUnexpectedStreamOnlyPacketSlot,
                        kTosChildDirectAbort);

    tosResetProcessApi(true);
}

static void residualPacketStateDestroyBody(void *argument)
{
    discard argument;

    disturber_fixture_t fixture;
    fixtureSetup(&fixture);

    disturber_tstate_t *state          = tunnelGetState(fixture.disturber);
    state->chance_payload_out_of_order = 100;

    line_t     *line         = fixture.packet_lines[1];
    const wid_t previous_wid = tosSetCurrentWorker(1);
    disturberTunnelUpStreamPayload(fixture.disturber, line, fixturePayload(line, UINT8_C(0xD4)));
    discard tosSetCurrentWorker(previous_wid);

    /* Destroy runs as worker 0 after worker 1 has gone away in production. It
     * must diagnose residue instead of touching worker 1's pool. */
    disturberTunnelDestroy(fixture.disturber, wwLifecycleProcessShutdown());
}

static void caseDestroyRejectsUndrainedFinalizedPacketState(void)
{
    twfSetCase("disturber Destroy rejects undrained finalized packet state");
    tosResetProcessApi(true);
    tosRequireChildExit("the undrained packet state", residualPacketStateDestroyBody, NULL, kTosChildDirectAbort);
    tosResetProcessApi(true);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();

    caseUpstreamFinishSuppressesScheduledDelayedPayload();
    caseDownstreamFinishSettlesHeldPayload();
    caseUpstreamFinishSuppressesQueuedDownstreamReflection();
    caseDownstreamFinishSuppressesQueuedUpstreamReflection();
    caseWorkerStopSettlesPacketStateOnOwnerWorker();
    caseWorkerStopAllowsFinalizedStreamOnlySlot();
    caseValidNormalLineInPacketChainKeepsNormalFinishRole();
    caseFinalizedPacketGeometryAborts();
    caseDestroyRejectsUndrainedFinalizedPacketState();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("disturber_packet_lifecycle_test: all cases passed");
    return 0;
}

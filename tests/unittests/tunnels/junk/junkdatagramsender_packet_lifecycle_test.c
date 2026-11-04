/*
 * Covers: JunkDatagramSender packet and borrowed normal-line publication lifetime.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: packet Finish, live normal-line Finish in both directions, nested normal Finish with/without
 * delayed copies, active publication, owner death before delayed execution, constructor Est forwarding.
 * Checks: No publication after local Finish, exact buffer/reference settlement, zeroed normal state,
 * directional Finish propagation and chain-owned packet survival.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.junkdatagramsender_packet_lifecycle_unit
 */
/* A live line does not authorize output after this node's state is destroyed. */

#include "JunkDatagramSender/structure.h"

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"

enum
{
    kJunkTestLargeBuffer = 8192,
    kJunkTestSmallBuffer = 1024,
};

typedef struct junk_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *junk;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    twf_line_pool_t  line_pool;
    line_t          *line;
    line_t          *packet_lines[1];
    bool             packet_role;
} junk_fixture_t;

static junk_fixture_t *g_fixture;

/* Duplication allocates through getters in buffer_pool.c itself, which GNU
 * --wrap cannot intercept from within that same translation unit. Keep those
 * scheduled copies in the existing acquisition/settlement ledger too. */
sbuf_t *__real_sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *buf);
sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *buf);

sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *buf)
{
    return twfTrackAcquired(__real_sbufDuplicateByPool(pool, buf));
}

static void fixtureSetup(junk_fixture_t *fixture, bool packet_role)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, 1, kJunkTestLargeBuffer, kJunkTestSmallBuffer);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->junk = tunnelCreate(NULL, sizeof(junkdatagramsender_tstate_t), sizeof(junkdatagramsender_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->junk != NULL, "failed to create the JunkDatagramSender fixture tunnel");
    tunnelBind(fixture->prev, fixture->junk);
    tunnelBind(fixture->junk, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the JunkDatagramSender packet chain");
    fixture->chain->workers_count        = 1;
    fixture->chain->contains_packet_node = packet_role;
    fixture->chain->finalized            = true;
    fixture->chain->packet_lines         = fixture->packet_lines;
    fixture->junk->chain                 = fixture->chain;

    fixture->packet_role = packet_role;
    if (packet_role)
    {
        fixture->line            = twfLineCreate(fixture->junk->lstate_size);
        fixture->packet_lines[0] = fixture->line;
    }
    else
    {
        /* The fixture creates and owns this normal line. Neither recording
         * neighbour owns it, so their Finish callbacks may keep draining. */
        twfLinePoolSetup(&fixture->line_pool, fixture->junk->lstate_size, 2);
        fixture->line = twfLinePoolCreateLine(&fixture->line_pool);
    }
    twfRequire(junkdatagramsenderIsWorkerPacketLine(fixture->junk, fixture->line) == packet_role,
               "fixture line role does not match the chain's packet slot");

    junkdatagramsender_tstate_t *ts = tunnelGetState(fixture->junk);
    ts->selected_protocol_mask      = UINT64_C(1) << kJunkDatagramSenderProtocolDns;
    ts->packet_count_min            = 1;
    ts->packet_count_max            = 1;
    ts->keep_sending_max_ms         = 1;
    ts->resend_again_times          = 1;

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelUpStreamInit(fixture->junk, fixture->line);
    discard tosSetCurrentWorker(previous_wid);
    g_fixture = fixture;
}

static void fixtureTeardown(junk_fixture_t *fixture)
{
    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelOnWorkerStop(fixture->junk, 0, wwLifecycleStartupRollback());
    if (fixture->line != NULL)
    {
        twfRequireLineStateZeroed(fixture->line, fixture->junk, "fixture cleanup found nonzero line state");
        twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "fixture cleanup found an unsettled task reference");
        if (fixture->packet_role)
        {
            /* This bare allocation represents chain-owned packet storage. */
            twfLineDestroy(fixture->line);
        }
        else
        {
            lineDestroy(fixture->line);
        }
    }
    if (! fixture->packet_role)
    {
        twfLinePoolTeardown(&fixture->line_pool);
    }
    twfRequireNoLeakedBuffers();
    discard tosSetCurrentWorker(previous_wid);

    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->junk);
    tunnelDestroy(fixture->prev);
    tosWorkerEnvTeardown(&fixture->env);
    g_fixture = NULL;
}

static sbuf_t *fixturePayload(line_t *line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 1);
    sbufGetMutablePtr(buf)[0] = UINT8_C(0xA5);
    return buf;
}

static void finishFromFirstJunk(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    junk_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && next == fixture->next, "re-entrant JunkDatagramSender callback lost its fixture");
    twfNextPayload(next, line, buf);
    if (fixture->trace.next_payload == 1)
    {
        junkdatagramsenderTunnelDownStreamFinish(fixture->junk, line);
    }
}

static void caseReentrantPacketFinishStopsImmediateProgress(void)
{
    twfSetCase("JunkDatagramSender re-entrant packet Finish stops immediate progress");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, true);
    fixture.next->fnPayloadU = finishFromFirstJunk;

    junkdatagramsender_tstate_t *ts = tunnelGetState(fixture.junk);
    ts->keep_sending_max_ms         = 0;

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));

    twfRequireEqualU32(fixture.trace.next_payload, 1, "payload progress continued after re-entrant packet Finish");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "re-entrant downstream Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "re-entrant downstream Finish reflected toward its sender");
    twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 0, "re-entrant case unexpectedly armed a timer");
    twfRequire(lineIsAlive(fixture.line), "re-entrant Finish destroyed the packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void casePacketFinishSuppressesDelayedJunk(void)
{
    twfSetCase("JunkDatagramSender packet Finish suppresses delayed junk");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, true);

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));

    twfRequireEqualU32(
        fixture.trace.next_payload, 2, "the immediate junk and original packet were not both published before Finish");
    twfRequireEqualU32(
        (uint32_t) fixture.env.loops[0]->ntimers, 1, "the delayed junk copy did not arm its owner-worker timer");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 2, "the delayed junk copy did not retain the packet line");

    junkdatagramsenderTunnelDownStreamFinish(fixture.junk, fixture.line);
    junkdatagramsender_lstate_t *ls = lineGetState(fixture.line, fixture.junk);
    twfRequire(! ls->upstream_publication_open && ! ls->downstream_publication_open,
               "packet Finish did not terminalize both delayed publication directions");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "downstream packet Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "downstream packet Finish reflected toward next");
    twfRequire(lineIsAlive(fixture.line), "JunkDatagramSender destroyed the chain-owned packet line");

    wwSleepMS(20);
    tosPumpWorker(&fixture.env, 0);

    twfRequireEqualU32(fixture.trace.next_payload, 2, "delayed junk was published after packet-line Finish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "delayed junk retained its task reference after settlement");
    twfRequire(lineIsAlive(fixture.line), "delayed settlement destroyed the packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void fixtureFinish(junk_fixture_t *fixture, bool upstream)
{
    if (upstream)
    {
        junkdatagramsenderTunnelUpStreamFinish(fixture->junk, fixture->line);
    }
    else
    {
        junkdatagramsenderTunnelDownStreamFinish(fixture->junk, fixture->line);
    }
    twfRequireEqualU32(fixture->trace.next_finish, upstream ? 1 : 0, "Finish propagation toward next was incorrect");
    twfRequireEqualU32(fixture->trace.prev_finish, upstream ? 0 : 1, "Finish propagation toward prev was incorrect");
    twfRequire(lineIsAlive(fixture->line), "a borrowing JunkDatagramSender destroyed the normal line");
    twfRequireLineStateZeroed(fixture->line, fixture->junk, "normal Finish did not zero the aligned local state");
}

static void fixtureQueueBothDirections(junk_fixture_t *fixture)
{
    junkdatagramsenderTunnelUpStreamPayload(fixture->junk, fixture->line, fixturePayload(fixture->line));

    /* The public directional helper is also used by production's upstream
     * Payload handler. Its caller holds the same temporary callout reference. */
    lineRef(fixture->line);
    const bool progress =
        junkdatagramsenderSendJunk(fixture->junk, fixture->line, kJunkDatagramSenderDirectionDownstream);
    twfRequire(progress && lineIsAlive(fixture->line), "active downstream junk generation was interrupted");
    lineUnref(fixture->line);

    twfRequireEqualU32(fixture->trace.next_payload, 2, "upstream junk and application payload did not publish");
    twfRequireEqualU32(fixture->trace.prev_payload, 1, "downstream immediate junk did not publish");
    twfRequireEqualU32((uint32_t) fixture->env.loops[0]->ntimers, 2, "both delayed directions were not armed");
    twfRequireEqualU32(twfLineRefCount(fixture->line), 3, "each delayed direction must hold exactly one reference");
    twfRequireEqualU32(g_twf_buffers.live_count, 2, "each delayed direction must retain exactly one buffer");
    twfRequireEqualU32(g_twf_buffers.total_acquired, 5, "unexpected active junk buffer acquisitions");
    twfRequireEqualU32(twfRecycleCount(), 3, "immediate output buffers did not settle exactly once");
}

static void fixturePumpDelayed(junk_fixture_t *fixture)
{
    wwSleepMS(20);
    tosPumpWorker(&fixture->env, 0);
    twfRequireEqualU32((uint32_t) fixture->env.loops[0]->ntimers, 0, "delayed copies left their timers armed");
}

static void caseNormalFinishSuppressesDelayedJunk(bool upstream)
{
    twfSetCase(upstream ? "JunkDatagramSender upstream normal Finish suppresses both delayed directions"
                        : "JunkDatagramSender downstream normal Finish suppresses both delayed directions");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, false);
    fixtureQueueBothDirections(&fixture);
    fixtureFinish(&fixture, upstream);

    twfRequireEqualU32(twfLineRefCount(fixture.line), 3, "Finish prematurely settled scheduler-owned references");
    twfRequireEqualU32(g_twf_buffers.live_count, 2, "Finish prematurely settled scheduler-owned copies");
    fixturePumpDelayed(&fixture);

    twfRequireEqualU32(fixture.trace.next_payload, 2, "upstream delayed junk published after normal Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "downstream delayed junk published after normal Finish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "normal delayed tasks did not return their references");
    twfRequireEqualU32(twfRecycleCount(), 5, "normal delayed buffers did not settle exactly once");
    twfRequire(g_twf_buffers.last_recycle_pool == lineGetBufferPool(fixture.line),
               "normal delayed copy was not recycled through its line's pool");

    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));
    junkdatagramsenderTunnelDownStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));
    twfRequireEqualU32(fixture.trace.next_payload, 2, "upstream input published after normal Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "downstream input published after normal Finish");
    twfRequireEqualU32(fixture.trace.next_finish, upstream ? 1 : 0, "late work added or reflected upstream Finish");
    twfRequireEqualU32(fixture.trace.prev_finish, upstream ? 0 : 1, "late work added or reflected downstream Finish");
    twfRequireEqualU32(twfRecycleCount(), 7, "closed publication did not settle both incoming buffers");
    twfRequireLineStateZeroed(fixture.line, fixture.junk, "late work modified destroyed normal state");
    twfRequire(lineIsAlive(fixture.line), "delayed settlement destroyed the borrowed normal line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseReentrantNormalFinishStopsImmediateProgress(bool delayed)
{
    twfSetCase(delayed ? "JunkDatagramSender nested normal Finish stops batch and delayed copy"
                       : "JunkDatagramSender nested normal Finish stops batch without delays");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, false);
    fixture.next->fnPayloadU        = finishFromFirstJunk;
    junkdatagramsender_tstate_t *ts = tunnelGetState(fixture.junk);
    ts->packet_count_min = ts->packet_count_max = 3;
    ts->keep_sending_max_ms                     = delayed ? 1 : 0;

    const uint32_t baseline = twfLineRefCount(fixture.line);
    sbuf_t        *original = fixturePayload(fixture.line);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.line, original);

    twfRequireEqualU32(
        fixture.trace.next_payload, 1, "junk batch or original payload continued after nested normal Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "nested normal Finish reflected a payload downstream");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "nested normal Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "nested normal Finish reflected toward its sender");
    twfRequireLineStateZeroed(fixture.line, fixture.junk, "nested normal Finish did not zero the local state");
    twfRequire(lineIsAlive(fixture.line), "nested normal Finish destroyed a borrowed line");
    twfRequireLastRecycle(
        original, lineGetBufferPool(fixture.line), "interrupted batch did not recycle its original buffer");
    twfRequireEqualU32(
        g_twf_buffers.total_acquired, delayed ? 3 : 2, "interrupted batch generated more than one junk packet");
    twfRequireEqualU32(twfRecycleCount(), 2, "immediate junk and retained original did not settle exactly once");
    twfRequireEqualU32(twfLineRefCount(fixture.line),
                       baseline + (delayed ? 1 : 0),
                       "interrupted batch leaked its temporary reference");
    twfRequireEqualU32(g_twf_buffers.live_count, delayed ? 1 : 0, "interrupted batch retained an unexpected buffer");

    if (delayed)
    {
        twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 1, "first junk did not schedule its delayed copy");
        fixturePumpDelayed(&fixture);
        twfRequireEqualU32(fixture.trace.next_payload, 1, "nested normal Finish allowed its delayed copy to publish");
        twfRequireEqualU32(twfRecycleCount(), 3, "nested delayed copy did not settle exactly once");
    }
    else
    {
        twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 0, "delays-disabled batch armed a timer");
    }
    twfRequireEqualU32(twfLineRefCount(fixture.line), baseline, "interrupted batch tasks retained the normal line");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "nested late work added downstream Finish");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "nested late work reflected upstream Finish");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseNormalActivePublication(void)
{
    twfSetCase("JunkDatagramSender Init opens ordinary and delayed normal-line publication");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, false);
    twfRequireEqualU32(fixture.trace.next_init, 1, "Init did not reach the recording next neighbour");
    fixtureQueueBothDirections(&fixture);
    fixturePumpDelayed(&fixture);

    twfRequireEqualU32(fixture.trace.next_payload, 3, "active upstream delayed junk did not publish");
    twfRequireEqualU32(fixture.trace.prev_payload, 2, "active downstream delayed junk did not publish");
    junkdatagramsenderTunnelDownStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));
    twfRequireEqualU32(fixture.trace.prev_payload, 3, "active downstream application payload did not publish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "active delayed tasks retained their line references");
    twfRequireEqualU32(g_twf_buffers.total_acquired, 6, "active output acquired unexpected buffers");
    twfRequireEqualU32(twfRecycleCount(), 6, "active output buffers did not settle exactly once");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    fixtureFinish(&fixture, true);
    fixtureTeardown(&fixture);
}

static void caseOwnerDestroysBeforeDelayedJunk(void)
{
    twfSetCase("JunkDatagramSender owner destroys normal line before delayed execution");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture, false);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.line, fixturePayload(fixture.line));
    twfRequireEqualU32(twfLineRefCount(fixture.line), 2, "delayed copy did not retain the normal line");

    /* Preserve one observer reference while the fixture's real creator
     * reference is dropped, so scheduler cancellation can be checked safely. */
    lineRef(fixture.line);
    fixtureFinish(&fixture, false);
    lineDestroy(fixture.line);
    twfRequire(! lineIsAlive(fixture.line), "normal-line owner did not close its line");
    fixturePumpDelayed(&fixture);

    twfRequireEqualU32(fixture.trace.next_payload, 2, "scheduler published junk on a dead normal line");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "scheduler cancellation retained its normal-line reference");
    twfRequireEqualU32(g_twf_buffers.total_acquired, 3, "unexpected owner-death buffer acquisitions");
    twfRequireEqualU32(twfRecycleCount(), 3, "owner-death cancellation did not settle every buffer once");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardown(&fixture);
}

static void caseConstructorPreservesUpstreamEst(void)
{
    junk_fixture_t fixture;
    fixtureSetup(&fixture, true);
    cJSON *settings = cJSON_CreateObject();
    twfRequire(settings != NULL, "failed to allocate constructor settings");
    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = junkdatagramsenderTunnelCreate(&node);
    twfRequire(t != NULL, "failed to create the production tunnel");
    t->next = fixture.next;
    t->fnEstU(t, fixture.line);
    twfRequireEqualU32(fixture.trace.next_est, 1, "production tunnel lost upstream Est forwarding");
    tunnelDestroy(t);
    cJSON_Delete(settings);
    fixtureTeardown(&fixture);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();

    caseConstructorPreservesUpstreamEst();
    caseReentrantPacketFinishStopsImmediateProgress();
    casePacketFinishSuppressesDelayedJunk();
    caseNormalActivePublication();
    caseReentrantNormalFinishStopsImmediateProgress(false);
    caseReentrantNormalFinishStopsImmediateProgress(true);
    caseNormalFinishSuppressesDelayedJunk(true);
    caseNormalFinishSuppressesDelayedJunk(false);
    caseOwnerDestroysBeforeDelayedJunk();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("junkdatagramsender_packet_lifecycle_test: all cases passed");
    return 0;
}

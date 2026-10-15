/*
 * Covers: packetstostream orderly shutdown; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: packet-source recovery after stream replacement, reentrant Resume and packet ordering,
 * caseHealthyPingArmsTheTimer, caseTimeoutTimerFailure,
 * caseDueTimeoutTimerRearmRefusalClearsSlot, caseRecreateRefusalRemainsRetryableUntilWorkerStop,
 * caseWorkerStopClosesOwnedOutputLine, casePacketWorkerStopSettlesOwnerState,
 * caseDestroyRejectsUndrainedFinalizedPacketState, caseDestroyRejectsFinalizedChainWithoutPacketLines;
 * the driver lists the remaining cases
 * Checks: Assertion labels include: a healthy ping must be forwarded once; a healthy ping must arm the
 * timeout timer; a healthy ping must publish awaiting_pong; the heartbeat must be recycled exactly once
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.packetstostream_orderly_shutdown_test_unit
 */
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

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"

// ---------------------------------------------------------------------------
// wtimerAdd injection
// ---------------------------------------------------------------------------

static bool         g_timer_fails                  = false;
static bool         g_timer_reset_closes_admission = false;
static unsigned int g_recreate_refusals;
static unsigned int g_recreate_submissions;

wtimer_t                 *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t                 *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
bool                      __real_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
bool                      __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
line_task_submit_result_e __real_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    if (g_timer_fails)
    {
        return NULL;
    }
    return __real_wtimerAdd(loop, cb, timeout_ms, repeat);
}

bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    if (g_timer_reset_closes_admission)
    {
        g_timer_reset_closes_admission = false;
        twfRequire(wloopCloseNormalAdmission(weventGetLoop(timer)), "failed to close admission before timer reset");
    }
    return __real_wtimerReset(timer, timeout_ms);
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    g_recreate_submissions += 1U;
    if (g_recreate_refusals == 0)
    {
        return __real_lineScheduleTask(line, task, t, on_cancel);
    }

    --g_recreate_refusals;
    lineRef(line);
    if (on_cancel != NULL)
    {
        on_cancel(t, line, kLineTaskCancelEnqueueFailure);
    }
    lineUnref(line);
    return kLineTaskSubmitRejectedSettled;
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
    tunnel_t        *prev;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_line;
    line_t          *stream_line;
    line_t          *packet_line_slot[1];
    wtimer_t        *timeout_timer_slot[1];
    wtimer_t        *worker_timer_slot[1];
    wtimer_t        *heartbeat_timer;
    twf_line_pool_t  stream_line_pool;
} packetstostream_fixture_t;

static void fixtureSetup(packetstostream_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(fixture->p2s != NULL, "failed to create the PacketsToStream tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    tunnelBind(fixture->prev, fixture->p2s);
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
    fixture->chain->workers_count        = 1;
    fixture->chain->finalized            = true;
    fixture->chain->contains_packet_node = true;
    fixture->p2s->chain                  = fixture->chain;

    fixture->packet_line         = twfLineCreate(fixture->p2s->lstate_size);
    fixture->packet_line_slot[0] = fixture->packet_line;
    fixture->chain->packet_lines = fixture->packet_line_slot;

    // A live pool-backed output line, so both ordinary fixture teardown and
    // the production owner-close path exercise lineDestroy() faithfully.
    twfLinePoolSetup(&fixture->stream_line_pool, fixture->p2s->lstate_size, 4);
    fixture->chain->line_pools[0] = fixture->stream_line_pool.pools[0];
    fixture->stream_line = twfLinePoolCreateLine(&fixture->stream_line_pool);

    packetstostream_lstate_t *ls = lineGetState(fixture->packet_line, fixture->p2s);
    packetstostreamLinestateInitialize(ls, lineGetBufferPool(fixture->packet_line));
    ls->line = fixture->stream_line;

    // A real timer, so the production callback finds its tunnel through the
    // event user data exactly as the runtime does.
    fixture->heartbeat_timer =
        __real_wtimerAdd(getWorkerLoop(0), packetstostreamHeartbeatTimerCallback, kTestIntervalMs, INFINITE);
    twfRequire(fixture->heartbeat_timer != NULL, "failed to create the test heartbeat timer");
    weventSetUserData(fixture->heartbeat_timer, fixture->p2s);
    fixture->worker_timer_slot[0] = fixture->heartbeat_timer;
}

static void fixtureTeardown(packetstostream_fixture_t *fixture)
{
    weventSetUserData(fixture->heartbeat_timer, NULL);
    wtimerDelete(fixture->heartbeat_timer);
    fixture->worker_timer_slot[0] = NULL;

    if (fixture->timeout_timer_slot[0] != NULL)
    {
        weventSetUserData(fixture->timeout_timer_slot[0], NULL);
        wtimerDelete(fixture->timeout_timer_slot[0]);
        fixture->timeout_timer_slot[0] = NULL;
    }

    packetstostream_lstate_t *ls = lineGetState(fixture->packet_line, fixture->p2s);
    packetstostreamLinestateDestroy(ls);

    if (fixture->stream_line != NULL)
    {
        lineDestroy(fixture->stream_line);
    }
    twfLinePoolTeardown(&fixture->stream_line_pool);
    twfLineDestroy(fixture->packet_line);
    memoryFree(fixture->chain);
}

static packetstostream_fixture_t *g_flow_fixture;
static bool                       g_packet_source_paused;
static bool                       g_pause_during_init;
static bool                       g_finish_during_init;
static bool                       g_send_during_init;
static bool                       g_finish_during_payload;
static bool                       g_send_on_resume;
static bool                       g_finish_on_resume;

static sbuf_t *flowPacket(uint8_t tag)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(g_flow_fixture->packet_line));
    sbufSetLength(buf, IP_HLEN + 1);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, IP_HLEN + 1);
    raw[0] = 0x45;
    PUT_BE16(raw + 2, IP_HLEN + 1);
    raw[8]       = 64;
    raw[9]       = 0xFD;
    raw[IP_HLEN] = tag;
    return buf;
}

static void closeFlowOutput(void)
{
    line_t *stream_line = g_flow_fixture->stream_line;
    twfRequire(stream_line != NULL, "the flow fixture must have an output line to close");
    lineRef(stream_line);
    // Exercise the lazy retry paths as well as the queued recreation entry point.
    g_recreate_refusals = 1;
    packetstostreamTunnelDownStreamFinish(g_flow_fixture->p2s, stream_line);
    twfRequire(! lineIsAlive(stream_line), "Finish must destroy the owned normal stream");
    lineUnref(stream_line);
    g_flow_fixture->stream_line = NULL;
}

static void flowNextInit(tunnel_t *t, line_t *l)
{
    twfNextInit(t, l);
    g_flow_fixture->stream_line = l;
    if (g_finish_during_init)
    {
        g_finish_during_init = false;
        closeFlowOutput();
        return;
    }
    if (g_pause_during_init)
    {
        packetstostreamTunnelDownStreamPause(g_flow_fixture->p2s, l);
        packetstostreamTunnelDownStreamPause(g_flow_fixture->p2s, l);
    }
    if (g_send_during_init)
    {
        g_send_during_init = false;
        sbuf_t *packet     = flowPacket('B');
        PUT_BE16((uint8_t *) sbufGetMutablePtr(packet) + 10, 0x1234);
        packetstostreamTunnelUpStreamPayload(g_flow_fixture->p2s, g_flow_fixture->packet_line, packet);
    }
}

static void flowNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfNextPayload(t, l, buf);
    if (g_finish_during_payload)
    {
        g_finish_during_payload = false;
        closeFlowOutput();
    }
}

static void flowPrevPause(tunnel_t *t, line_t *l)
{
    twfRequire(l == g_flow_fixture->packet_line, "Pause must target the persistent packet line");
    g_packet_source_paused = true;
    twfPrevPause(t, l);
}

static void flowPrevResume(tunnel_t *t, line_t *l)
{
    twfRequire(l == g_flow_fixture->packet_line, "Resume must target the persistent packet line");
    g_packet_source_paused = false;
    twfPrevResume(t, l);
    if (g_send_on_resume)
    {
        g_send_on_resume = false;
        packetstostreamTunnelUpStreamPayload(g_flow_fixture->p2s, l, flowPacket('B'));
    }
    if (g_finish_on_resume)
    {
        g_finish_on_resume = false;
        closeFlowOutput();
    }
}

static void flowFixtureSetup(packetstostream_fixture_t *fixture)
{
    fixtureSetup(fixture);
    g_flow_fixture            = fixture;
    g_packet_source_paused    = false;
    g_pause_during_init       = false;
    g_finish_during_init      = false;
    g_send_during_init        = false;
    g_finish_during_payload   = false;
    g_send_on_resume          = false;
    g_finish_on_resume        = false;
    fixture->next->fnInitU    = flowNextInit;
    fixture->next->fnPayloadU = flowNextPayload;
    fixture->prev->fnPauseD   = flowPrevPause;
    fixture->prev->fnResumeD  = flowPrevResume;
}

static void caseDroppedPacketConsumesChecksumRequest(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        twfSetCase(mode == 0   ? "packetstostream oversized drop consumes checksum request"
                   : mode == 1 ? "packetstostream paused drop consumes checksum request"
                               : "packetstostream failed Init consumes checksum request");
        tosResetProcessApi(true);
        packetstostream_fixture_t fixture;
        flowFixtureSetup(&fixture);
        uint8_t captured[IP_HLEN + 1];
        fixture.trace.capture          = captured;
        fixture.trace.capture_capacity = sizeof(captured);

        sbuf_t *dropped;
        if (mode == 0)
        {
            dropped = bufferpoolGetLargeBuffer(lineGetBufferPool(fixture.packet_line));
            sbufSetLength(dropped, kMaxAllowedPacketLength + 1);
            memoryZero(sbufGetMutablePtr(dropped), sbufGetLength(dropped));
        }
        else
        {
            dropped = flowPacket('A');
            if (mode == 1)
                packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
            else
            {
                closeFlowOutput();
                g_finish_during_init = true;
            }
        }
        lineSetRecalculateChecksum(fixture.packet_line, true);
        packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, dropped);
        const bool pending_after_drop = lineGetRecalculateChecksum(fixture.packet_line);
        twfRequireEqualU32(fixture.trace.capture_len, 0, "the refused packet was forwarded");
        if (mode == 1)
            packetstostreamTunnelDownStreamResume(fixture.p2s, fixture.stream_line);

        sbuf_t *next = flowPacket('B');
        PUT_BE16((uint8_t *) sbufGetMutablePtr(next) + 10, 0x1234);
        packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, next);
        twfRequireEqualU32(fixture.trace.capture_len, sizeof(captured), "the next packet was not forwarded");
        twfRequire(GET_BE16(captured + 10) == 0x1234,
                   "a dropped packet's checksum request modified the next unflagged packet");
        twfRequire(! pending_after_drop && ! lineGetRecalculateChecksum(fixture.packet_line),
                   "a refused packet retained its checksum request");
        fixtureTeardown(&fixture);
        twfRequireNoLeakedBuffers();
        tosRequireNoProcessApiCall();
    }
}

static void caseInitReentryKeepsChecksumRequestOnItsPacket(void)
{
    twfSetCase("packetstostream Init reentry cannot steal the current packet's checksum request");
    tosResetProcessApi(true);
    packetstostream_fixture_t fixture;
    flowFixtureSetup(&fixture);
    uint8_t captured[2 * (IP_HLEN + 1)];
    fixture.trace.capture          = captured;
    fixture.trace.capture_capacity = sizeof(captured);
    closeFlowOutput();
    g_send_during_init = true;

    sbuf_t *packet = flowPacket('A');
    PUT_BE16((uint8_t *) sbufGetMutablePtr(packet) + 10, 0x1234);
    lineSetRecalculateChecksum(fixture.packet_line, true);
    packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, packet);
    twfRequireEqualU32(fixture.trace.capture_len, sizeof(captured), "Init reentry did not deliver both packets");
    twfRequire(captured[IP_HLEN] == 'B' && captured[2 * IP_HLEN + 1] == 'A', "unexpected reentrant packet order");
    twfRequire(GET_BE16(captured + 10) == 0x1234, "Init reentry consumed another packet's checksum request");
    twfRequire(inet_chksum(captured + IP_HLEN + 1, IP_HLEN) == 0,
               "the original flagged packet was forwarded without checksum repair");
    twfRequire(! lineGetRecalculateChecksum(fixture.packet_line), "the checksum request survived delivery");
    fixtureTeardown(&fixture);
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
}

static void caseReplacementReleasesPacketSource(void)
{
    for (unsigned int paused_init = 0; paused_init < 2; ++paused_init)
    {
        twfSetCase("packetstostream replacement retains only its own Pause");
        tosResetProcessApi(true);
        packetstostream_fixture_t fixture;
        flowFixtureSetup(&fixture);
        packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);

        packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
        packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
        packetstostreamTunnelDownStreamEst(fixture.p2s, fixture.stream_line);
        packetstostreamTunnelDownStreamEst(fixture.p2s, fixture.stream_line);
        twfRequire(g_packet_source_paused, "repeated Est must not release packet-source Pause");
        closeFlowOutput();
        twfRequire(g_packet_source_paused, "reset must not resume a source without a replacement");

        g_pause_during_init    = paused_init != 0;
        ls->recreate_scheduled = true;
        packetstostreamRecreateOutputLineTask(fixture.p2s, fixture.packet_line);
        twfRequire(ls->line == fixture.stream_line && fixture.stream_line != NULL,
                   "recreation must attach the newly initialized stream");
        twfRequire(g_packet_source_paused == (paused_init != 0),
                   "replacement must resume only if its Init left it unpaused");
        packetstostreamTunnelDownStreamResume(fixture.p2s, fixture.stream_line);
        packetstostreamTunnelDownStreamResume(fixture.p2s, fixture.stream_line);
        twfRequire(! g_packet_source_paused, "Resume must release the replacement's own Pause");
        twfRequire(strcmp(fixture.trace.seq, paused_init ? "ueeIur" : "ueeIr") == 0,
                   "repeated endpoint signals must be idempotent and preserve mapped Est");

        fixtureTeardown(&fixture);
        twfRequireNoLeakedBuffers();
        tosRequireNoProcessApiCall();
    }
}

static void caseLazyReplacementPreservesOutputOrder(void)
{
    for (unsigned int heartbeat = 0; heartbeat < 2; ++heartbeat)
    {
        twfSetCase("packetstostream settles current output before Resume releases newer packets");
        tosResetProcessApi(true);
        packetstostream_fixture_t fixture;
        flowFixtureSetup(&fixture);
        uint8_t captured[128];
        fixture.trace.capture          = captured;
        fixture.trace.capture_capacity = sizeof(captured);
        packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
        closeFlowOutput();
        g_send_on_resume = true;

        if (heartbeat)
        {
            packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
        }
        else
        {
            packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, flowPacket('A'));
        }

        const uint32_t first_length = heartbeat ? kHeartbeatPacketSize : IP_HLEN + 1;
        twfRequire(strcmp(fixture.trace.seq, "uIPrP") == 0,
                   "the active packet or ping must precede Resume and its synchronously released packet");
        twfRequireEqualU32(
            fixture.trace.capture_len, first_length + IP_HLEN + 1, "both complete packets must reach the replacement");
        twfRequire(captured[IP_HLEN] == (heartbeat ? kSensitivePingByte : 'A') &&
                       captured[first_length + IP_HLEN] == 'B',
                   "Resume must not reorder the active output and queued packet");
        twfRequire(! g_packet_source_paused, "lazy replacement must release the old stream's Pause");

        fixtureTeardown(&fixture);
        twfRequireNoLeakedBuffers();
        tosRequireNoProcessApiCall();
    }
}

static void caseReplacementCallbacksMayClose(void)
{
    twfSetCase("packetstostream replacement callbacks may synchronously close their owned stream");
    tosResetProcessApi(true);
    packetstostream_fixture_t fixture;
    flowFixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
    closeFlowOutput();

    g_finish_during_init = true;
    packetstostreamTunnelUpStreamInit(fixture.p2s, fixture.packet_line);
    twfRequire(ls->line == NULL && g_packet_source_paused, "failed Init must not resume the packet source");
    g_finish_during_payload = true;
    packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, flowPacket('A'));
    twfRequire(ls->line == NULL && g_packet_source_paused,
               "a payload-closed replacement must not resume the packet source");
    g_finish_on_resume = true;
    packetstostreamTunnelUpStreamInit(fixture.p2s, fixture.packet_line);
    twfRequire(ls->line == NULL && fixture.stream_line == NULL, "Resume must safely permit synchronous stream closure");
    twfRequire(strcmp(fixture.trace.seq, "uIIPIr") == 0, "closed replacements must receive no later callbacks");
    twfRequire(lineIsAlive(fixture.packet_line), "replacement closure must preserve the persistent packet line");

    fixtureTeardown(&fixture);
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
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

    packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
    packetstostreamTunnelDownStreamPause(fixture.p2s, fixture.stream_line);
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);

    tosRequireNoProcessApiCall();
    twfRequireEqualU32(fixture.trace.next_payload, 1, "a healthy ping must be forwarded once");
    twfRequire(fixture.timeout_timer_slot[0] != NULL, "a healthy ping must arm the timeout timer");

    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    twfRequire(ls->awaiting_pong, "a healthy ping must publish awaiting_pong");
    twfRequire(ls->paused, "a due heartbeat must pass through Pause without releasing packet admission");

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

static void caseDueTimeoutTimerRearmRefusalClearsSlot(void)
{
    twfSetCase("packetstostream due timeout timer rearm refusal");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);

    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    ls->awaiting_pong            = true;
    ls->pong_deadline_ms         = wloopNowMS(fixture.env.loop) + 1000U;

    wtimer_t *timer = __real_wtimerAdd(fixture.env.loop, packetstostreamTimeoutTimerCallback, 1U, 1);
    twfRequire(timer != NULL, "failed to create the timeout timer fixture");
    fixture.timeout_timer_slot[0] = timer;
    weventSetUserData(timer, fixture.p2s);

    const uint32_t timers_before = fixture.env.loop->ntimers;
    wwSleepMS(2);
    g_timer_reset_closes_admission = true;
    discard wloopProcessEvents(fixture.env.loop, 0);

    tosRequireNoProcessApiCall();
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "reset refusal retained the timeout timer slot");
    twfRequire(ls->awaiting_pong, "reset refusal must leave line settlement to shutdown");
    twfRequireEqualU32((uint32_t) fixture.env.loop->ntimers,
                       timers_before - 1U,
                       "the event loop did not reclaim the due one-shot timer exactly once");

    fixtureTeardown(&fixture);
}

static void caseRecreateRefusalRemainsRetryableUntilWorkerStop(void)
{
    twfSetCase("packetstostream recreate refusal remains retryable until worker Stop");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);

    g_recreate_refusals    = 2;
    g_recreate_submissions = 0;
    packetstostreamScheduleRecreateOutputLine(fixture.p2s, fixture.packet_line, ls);

    twfRequire(! ls->recreate_scheduled, "first recreate refusal left the retry latch set");
    twfRequire(lineIsAlive(fixture.packet_line), "first recreate refusal destroyed the persistent packet line");
    twfRequireEqualU32(g_recreate_submissions, 1, "first recreate attempt submitted the wrong number of tasks");

    /* A later packet or heartbeat reaches the same helper. The cleared latch
     * must permit exactly one new attempt instead of permanently blackholing
     * this worker. */
    packetstostreamScheduleRecreateOutputLine(fixture.p2s, fixture.packet_line, ls);
    twfRequire(! ls->recreate_scheduled, "retry refusal left the recreate latch set");
    twfRequireEqualU32(g_recreate_submissions, 2, "later activity did not retry recreate exactly once");
    twfRequireEqualU32(g_recreate_refusals, 0, "recreate retry did not consume both settled refusals");

    packetstostreamTunnelOnWorkerStop(fixture.p2s, 0, wwLifecycleProcessShutdown());
    twfRequire(lineIsAlive(fixture.packet_line), "worker Stop destroyed the chain-owned packet line");
    twfRequireLineStateZeroed(fixture.packet_line, fixture.p2s, "worker Stop retained recreate or parser state");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "worker Stop did not close the owned output line once");
    fixture.stream_line = NULL;

    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Owned normal lines must be dead before chain-pool teardown
// ---------------------------------------------------------------------------

static void caseWorkerStopClosesOwnedOutputLine(void)
{
    twfSetCase("packetstostream worker stop closes its output line");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    fixtureSetup(&fixture);

    packetstostreamTunnelOnWorkerStop(fixture.p2s, 0, wwLifecycleProcessShutdown());

    tosRequireNoProcessApiCall();
    twfRequireEqualU32(fixture.trace.next_finish, 1, "worker stop must finish the owned output line exactly once");

    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    twfRequire(ls->line == NULL, "worker stop retained the owned output line in packet-line state");
    twfRequire(! ls->recreate_scheduled, "worker stop left output-line recreation scheduled");
    twfRequireLineStateZeroed(fixture.packet_line, fixture.p2s, "worker stop retained packet-line parser state");

    /* onWorkerStop performed the owner's logical and physical release. */
    fixture.stream_line = NULL;
    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Packet-line state must be drained by the exact owning worker
// ---------------------------------------------------------------------------

static void casePacketWorkerStopSettlesOwnerState(void)
{
    enum
    {
        kWorkerCount = 2
    };

    twfSetCase("packetstostream packet worker Stop settles worker-affine state");
    tosResetProcessApi(true);

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the packet worker-stop PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + kWorkerCount * sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the packet worker-stop PacketsToStream chain");
    line_t *packet_lines[kWorkerCount] = {0};
    chain->workers_count               = kWorkerCount;
    chain->finalized                   = true;
    chain->contains_packet_node        = true;
    chain->packet_lines                = packet_lines;
    p2s->chain                         = chain;

    const uint32_t recycles_before = twfRecycleCount();
    for (wid_t wid = 0; wid < kWorkerCount; ++wid)
    {
        line_t *line      = twfLineCreate(p2s->lstate_size);
        line->wid         = wid;
        packet_lines[wid] = line;

        const wid_t               previous_wid = tosSetCurrentWorker(wid);
        packetstostream_lstate_t *ls           = lineGetState(line, p2s);
        packetstostreamLinestateInitialize(ls, lineGetBufferPool(line));

        sbuf_t *retained = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
        sbufSetLength(retained, 1);
        bufferstreamPush(&ls->read_stream, retained);

        packetstostreamTunnelOnWorkerStop(p2s, wid, wwLifecycleProcessShutdown());

        twfRequireLineStateZeroed(line, p2s, "packet worker Stop left PacketsToStream state behind");
        twfRequire(lineIsAlive(line), "packet worker Stop destroyed the chain-owned packet line");
        discard tosSetCurrentWorker(previous_wid);
    }

    twfRequireEqualU32(
        twfRecycleCount() - recycles_before, kWorkerCount, "packet worker Stop did not recycle every retained buffer");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    /* onDestroy runs after owner-worker drains and must not revisit their pools. */
    packetstostreamTunnelDestroy(p2s, wwLifecycleProcessShutdown());
    for (wid_t wid = 0; wid < kWorkerCount; ++wid)
    {
        twfLineDestroy(packet_lines[wid]);
    }
    memoryFree(chain);
    tosWorkerEnvTeardown(&env);
}

static void residualPacketStateDestroyBody(void *argument)
{
    discard argument;

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the residual PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the residual PacketsToStream chain");
    line_t *packet_lines[1]     = {twfLineCreate(p2s->lstate_size)};
    chain->workers_count        = 1;
    chain->finalized            = true;
    chain->contains_packet_node = true;
    chain->packet_lines         = packet_lines;
    p2s->chain                  = chain;

    packetstostream_lstate_t *ls = lineGetState(packet_lines[0], p2s);
    packetstostreamLinestateInitialize(ls, lineGetBufferPool(packet_lines[0]));
    bufferstreamPush(&ls->read_stream, bufferpoolGetSmallBuffer(lineGetBufferPool(packet_lines[0])));

    packetstostreamTunnelDestroy(p2s, wwLifecycleProcessShutdown());
}

static void caseDestroyRejectsUndrainedFinalizedPacketState(void)
{
    twfSetCase("packetstostream Destroy rejects undrained finalized packet state");
    tosResetProcessApi(true);
    tosRequireChildExit("the undrained packet state", residualPacketStateDestroyBody, NULL, kTosChildDirectAbort);
    tosResetProcessApi(true);
}

static void missingPacketArrayDestroyBody(void *argument)
{
    discard argument;

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the missing-array PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the missing-array PacketsToStream chain");
    chain->workers_count        = 1;
    chain->finalized            = true;
    chain->contains_packet_node = true;
    p2s->chain                  = chain;

    packetstostreamTunnelDestroy(p2s, wwLifecycleProcessShutdown());
}

static void wrongOwnerPacketLineDestroyBody(void *argument)
{
    discard argument;

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the wrong-owner PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the wrong-owner PacketsToStream chain");
    line_t *packet_lines[1]     = {twfLineCreate(p2s->lstate_size)};
    packet_lines[0]->wid        = 1;
    chain->workers_count        = 1;
    chain->finalized            = true;
    chain->contains_packet_node = true;
    chain->packet_lines         = packet_lines;
    p2s->chain                  = chain;

    packetstostreamTunnelDestroy(p2s, wwLifecycleProcessShutdown());
}

static void caseDestroyRejectsFinalizedChainWithoutPacketLines(void)
{
    twfSetCase("packetstostream Destroy rejects a finalized chain without packet lines");
    tosResetProcessApi(true);
    tosRequireChildExit("the missing packet-line array", missingPacketArrayDestroyBody, NULL, kTosChildDirectAbort);
    tosRequireChildExit("a wrong-owner packet-line slot", wrongOwnerPacketLineDestroyBody, NULL, kTosChildDirectAbort);
    tosResetProcessApi(true);
}

static void outOfRangeWorkerStopBody(void *argument)
{
    discard argument;

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the out-of-range PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the out-of-range PacketsToStream chain");
    line_t *packet_lines[1]     = {twfLineCreate(p2s->lstate_size)};
    chain->workers_count        = 1;
    chain->finalized            = true;
    chain->contains_packet_node = true;
    chain->packet_lines         = packet_lines;
    p2s->chain                  = chain;

    discard tosSetCurrentWorker(1);
    packetstostreamTunnelOnWorkerStop(p2s, 1, wwLifecycleProcessShutdown());
}

static void caseWorkerStopRejectsFinalizedOutOfRangeWorker(void)
{
    twfSetCase("packetstostream worker Stop rejects an out-of-range finalized worker");
    tosResetProcessApi(true);
    tosRequireChildExit("the out-of-range packet-line worker", outOfRangeWorkerStopBody, NULL, kTosChildDirectAbort);
    tosResetProcessApi(true);
}

static void streamOnlyFinalizedPacketGeometryBody(void *argument)
{
    const bool destroy = argument != NULL;

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(p2s != NULL, "failed to create the stream-only geometry PacketsToStream fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the stream-only geometry PacketsToStream chain");
    line_t *packet_lines[1] = {twfLineCreate(p2s->lstate_size)};
    chain->workers_count    = 1;
    chain->finalized        = true;
    /* A non-NULL slot cannot coexist with a finalized stream-only chain. */
    chain->packet_lines = packet_lines;
    p2s->chain          = chain;

    if (destroy)
    {
        tosWorkerEnvTeardown(&env);
        packetstostreamTunnelDestroy(p2s, wwLifecycleProcessShutdown());
        return;
    }

    packetstostreamTunnelOnWorkerStop(p2s, 0, wwLifecycleProcessShutdown());
}

static void caseFinalizedStreamOnlyPacketGeometryAborts(void)
{
    twfSetCase("packetstostream finalized stream-only packet geometry aborts");
    tosResetProcessApi(true);
    tosRequireChildExit("stream-only packet geometry at worker Stop",
                        streamOnlyFinalizedPacketGeometryBody,
                        NULL,
                        kTosChildDirectAbort);
    tosRequireChildExit("stream-only packet geometry at Destroy",
                        streamOnlyFinalizedPacketGeometryBody,
                        (void *) "destroy",
                        kTosChildDirectAbort);
    tosResetProcessApi(true);
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
    if (getenv("WATERWALL_TSAN_POSITIVE_ONLY") != NULL)
    {
        caseDueTimeoutTimerRearmRefusalClearsSlot();
        puts("packetstostream_orderly_shutdown_test: TSAN-positive case passed");
        return 0;
    }

    caseInitReentryKeepsChecksumRequestOnItsPacket();
    caseDroppedPacketConsumesChecksumRequest();
    caseReplacementReleasesPacketSource();
    caseLazyReplacementPreservesOutputOrder();
    caseReplacementCallbacksMayClose();
    caseHealthyPingArmsTheTimer();
    caseTimeoutTimerFailure();
    caseDueTimeoutTimerRearmRefusalClearsSlot();
    caseRecreateRefusalRemainsRetryableUntilWorkerStop();
    caseWorkerStopClosesOwnedOutputLine();
    casePacketWorkerStopSettlesOwnerState();
    caseDestroyRejectsUndrainedFinalizedPacketState();
    caseDestroyRejectsFinalizedChainWithoutPacketLines();
    caseWorkerStopRejectsFinalizedOutOfRangeWorker();
    caseFinalizedStreamOnlyPacketGeometryAborts();
    caseRefusedHandoffAborts();
    caseHeartbeatTimerStartFailure();

    printf("packetstostream_orderly_shutdown_test: all cases passed\n");
    return 0;
}

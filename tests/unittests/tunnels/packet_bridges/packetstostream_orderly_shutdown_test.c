/*
 * Covers: packetstostream heartbeat deadlines, stream replacement, and orderly shutdown.
 *
 * Setup: Real worker, line, timer, and neighbour code with a controlled monotonic clock in deadline cases.
 *
 * Cases: Timely, missing, and late PONGs, pending timer reuse, callback reentry, timer refusal, and worker stop.
 *
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
// Timer and clock injection
// ---------------------------------------------------------------------------

static bool         g_timer_fails                  = false;
static bool         g_timer_reset_closes_admission = false;
static bool         g_timer_reset_was_pending;
static unsigned int g_recreate_refusals;
static unsigned int g_recreate_submissions;
static uint64_t     g_now_us;
static uint64_t     g_deadline_arm_delay_us;

wtimer_t                 *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t                 *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t                 *__real_wtimerAddDeadline(wloop_t *loop, wtimer_cb cb, uint32_t delay_ms);
wtimer_t                 *__wrap_wtimerAddDeadline(wloop_t *loop, wtimer_cb cb, uint32_t delay_ms);
bool                      __real_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
bool                      __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
unsigned long long        __real_getHRTimeUs(void);
unsigned long long        __wrap_getHRTimeUs(void);
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

wtimer_t *__wrap_wtimerAddDeadline(wloop_t *loop, wtimer_cb cb, uint32_t delay_ms)
{
    if (g_timer_fails)
    {
        return NULL;
    }
    wtimer_t *timer = __real_wtimerAddDeadline(loop, cb, delay_ms);
    g_now_us += g_deadline_arm_delay_us;
    return timer;
}

unsigned long long __wrap_getHRTimeUs(void)
{
    return g_now_us == 0 ? __real_getHRTimeUs() : g_now_us;
}

bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    g_timer_reset_was_pending = timer->pending;
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
    tos_worker_env_t env;
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
    tosWorkerEnvSetup(&fixture->env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    fixture->p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(fixture->p2s != NULL, "failed to create the PacketsToStream tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    tunnelBind(fixture->prev, fixture->p2s);
    tunnelBind(fixture->p2s, fixture->next);

    packetstostream_tstate_t *ts = tunnelGetState(fixture->p2s);
    ts->transport_offer          = kAddressContextTransportBoth;
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
    fixture->stream_line          = twfLinePoolCreateLine(&fixture->stream_line_pool);

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
    twfRequireNoLeakedBuffers();
    tosWorkerEnvTeardown(&fixture->env);
    twfLinePoolTeardown(&fixture->stream_line_pool);
    twfLineDestroy(fixture->packet_line);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->p2s);
    tunnelDestroy(fixture->next);
    g_now_us = 0;
}

static void heartbeatFixtureSetup(packetstostream_fixture_t *fixture)
{
    g_now_us = 1000000;
    fixtureSetup(fixture);
    // The test decides when to send PINGs while the reply timer runs on the real loop.
    twfRequire(__real_wtimerReset(fixture->heartbeat_timer, 10 * kTestToleranceMs), "failed to defer heartbeat tick");
}

static void deliverPong(packetstostream_fixture_t *fixture, line_t *stream_line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));
    sbufSetLength(buf, kHeartbeatPacketSize);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, IP_HLEN);
    raw[0] = 0x45;
    PUT_BE16(raw + 2, kHeartbeatPacketSize);
    raw[8] = 64;
    raw[9] = kHeartbeatProtocol;
    IPH_CHKSUM_SET((struct ip_hdr *) raw, inet_chksum(raw, IP_HLEN));
    memorySet(raw + IP_HLEN, kSensitivePongByte, kSensitivePayloadSize);
    packetstostreamTunnelDownStreamPayload(fixture->p2s, stream_line, buf);
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
    const packetstostream_tstate_t *ts = tunnelGetState(g_flow_fixture->p2s);
    twfRequire(addresscontextGetTransportOffer(lineGetDestinationAddressContext(l)) == ts->transport_offer,
               "new output line changed the configured transport offer");
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
    twfRequire(! sbufGetRecalculateChecksum(buf), "packet repair request entered the serialized stream");
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
        sbufSetRecalculateChecksum(dropped, true);
        packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, dropped);
        twfRequireEqualU32(fixture.trace.capture_len, 0, "the refused packet was forwarded");
        if (mode == 1)
            packetstostreamTunnelDownStreamResume(fixture.p2s, fixture.stream_line);

        sbuf_t *next = flowPacket('B');
        PUT_BE16((uint8_t *) sbufGetMutablePtr(next) + 10, 0x1234);
        packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, next);
        twfRequireEqualU32(fixture.trace.capture_len, sizeof(captured), "the next packet was not forwarded");
        twfRequire(GET_BE16(captured + 10) == 0x1234,
                   "a dropped packet's checksum request modified the next unflagged packet");

        fixtureTeardown(&fixture);
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
    sbufSetRecalculateChecksum(packet, true);
    packetstostreamTunnelUpStreamPayload(fixture.p2s, fixture.packet_line, packet);
    twfRequireEqualU32(fixture.trace.capture_len, sizeof(captured), "Init reentry did not deliver both packets");
    twfRequire(captured[IP_HLEN] == 'B' && captured[2 * IP_HLEN + 1] == 'A', "unexpected reentrant packet order");
    twfRequire(GET_BE16(captured + 10) == 0x1234, "Init reentry consumed another packet's checksum request");
    twfRequire(inet_chksum(captured + IP_HLEN + 1, IP_HLEN) == 0,
               "the original flagged packet was forwarded without checksum repair");

    fixtureTeardown(&fixture);
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
        packetstostream_tstate_t *ts = tunnelGetState(fixture.p2s);
        ts->transport_offer          = heartbeat ? kAddressContextTransportUdp : kAddressContextTransportTcp;
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
    tosRequireNoProcessApiCall();
}

// ---------------------------------------------------------------------------
// Sensitive-mode heartbeat behavior
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

static void caseTimelyPongAfterStaleCache(void)
{
    twfSetCase("packetstostream prompt PONG after pre-send worker delay");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    heartbeatFixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);

    // Simulate earlier work in the same loop turn, leaving its cached clock behind.
    g_now_us += (kTestToleranceMs + 50) * 1000ULL;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    twfRequireEqualU32(fixture.trace.next_payload, 1, "the delayed worker must still send a PING");
    twfRequire(ls->awaiting_pong, "the first PING must start a wait");

    g_now_us += 20 * 1000ULL;
    discard wloopProcessEvents(fixture.env.loops[0], 0);
    deliverPong(&fixture, fixture.stream_line);
    twfRequire(! ls->awaiting_pong, "the timely PONG must clear the wait");
    twfRequire(ls->line == fixture.stream_line && lineIsAlive(fixture.stream_line),
               "pre-send worker time must not shorten the PONG tolerance");

    twfRequire(fixture.timeout_timer_slot[0] != NULL, "a timely PONG must allow its timer to wake harmlessly");
    g_now_us = fixture.timeout_timer_slot[0]->next_timeout;
    discard wloopProcessEvents(fixture.env.loops[0], 0);
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "the obsolete wake must release its timer slot");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a timely PONG must preserve the same stream");

    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseDeadlineRetiresStream(bool deliver_at_deadline)
{
    twfSetCase(deliver_at_deadline ? "packetstostream PONG at the deadline" : "packetstostream missing PONG");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    heartbeatFixtureSetup(&fixture);
    packetstostream_lstate_t *ls              = lineGetState(fixture.packet_line, fixture.p2s);
    line_t                   *original_stream = fixture.stream_line;
    lineRef(original_stream);

    // In the missing-PONG case the timer arms half a millisecond before handoff.
    g_deadline_arm_delay_us = deliver_at_deadline ? 0 : 500;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    g_deadline_arm_delay_us    = 0;
    const uint64_t deadline_us = g_now_us + kTestToleranceMs * 1000ULL;
    twfRequire(ls->awaiting_pong && ls->pong_deadline_us == deadline_us,
               "PING handoff must start a full reply interval");
    packetstostreamTunnelDownStreamPause(fixture.p2s, original_stream);

    wtimer_t *timer = fixture.timeout_timer_slot[0];
    twfRequire(timer != NULL, "the PING must have a timeout timer");
    if (deliver_at_deadline)
    {
        // No loop step here. The parser must observe the boundary even with a stale cache.
        g_now_us = deadline_us;
        deliverPong(&fixture, original_stream);
    }
    else
    {
        g_now_us = timer->next_timeout;
        twfRequire(g_now_us < deadline_us, "the fixture must make the timer wake before the reply deadline");
        discard wloopProcessEvents(fixture.env.loops[0], 0);
        twfRequire(ls->awaiting_pong && lineIsAlive(original_stream), "an early wake must preserve the wait");
        twfRequire(fixture.timeout_timer_slot[0] == timer && timer->next_timeout == g_now_us + 1000,
                   "an early wake must rearm for the remaining partial millisecond");
        g_now_us = timer->next_timeout;
        discard wloopProcessEvents(fixture.env.loops[0], 0);
    }

    twfRequire(! lineIsAlive(original_stream) && ! ls->awaiting_pong, "expiry must retire the original stream");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "expiry must finish the original stream exactly once");
    twfRequire(lineIsAlive(fixture.packet_line), "expiry must preserve the chain-owned packet line");

    tosPumpWorker(&fixture.env, 0);
    fixture.stream_line = ls->line;
    twfRequire(fixture.stream_line != NULL && fixture.stream_line != original_stream &&
                   lineIsAlive(fixture.stream_line),
               "expiry must produce a live replacement stream");
    lineUnref(original_stream);
    twfRequireEqualU32(fixture.trace.next_init, 1, "expiry must initialize one replacement stream");
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    twfRequire(ls->awaiting_pong, "the replacement must be able to start a new wait");
    twfRequireEqualU32(fixture.trace.next_payload, 2, "the replacement must send a new PING");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "the old wait must not finish the replacement");

    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseSecondPingSupersedesPendingWake(void)
{
    twfSetCase("packetstostream second PING supersedes a pending wake");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    heartbeatFixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    wtimer_t *timer = fixture.timeout_timer_slot[0];
    twfRequire(timer != NULL, "the first PING must have a timeout timer");

    g_now_us += 20 * 1000ULL;
    deliverPong(&fixture, fixture.stream_line);
    twfRequire(! ls->awaiting_pong, "the first PONG must clear its wait");

    // Both timers become pending in the same turn. The later heartbeat is dispatched first.
    wloopUpdateTime(fixture.env.loops[0]);
    const uint32_t next_tick_ms = (uint32_t) ((timer->next_timeout - g_now_us) / 1000) + 1;
    twfRequire(__real_wtimerReset(fixture.heartbeat_timer, next_tick_ms), "failed to position the next heartbeat tick");
    g_now_us                  = fixture.heartbeat_timer->next_timeout;
    g_timer_reset_was_pending = false;
    discard wloopProcessEvents(fixture.env.loops[0], 0);

    twfRequire(g_timer_reset_was_pending, "the second PING must reuse the already pending reply timer");
    twfRequireEqualU32(fixture.trace.next_payload, 2, "the second PING must be forwarded once");
    twfRequire(ls->awaiting_pong && fixture.timeout_timer_slot[0] == timer,
               "the earlier wake must preserve the second wait and timer");

    g_now_us += (kTestToleranceMs - 1) * 1000ULL;
    deliverPong(&fixture, fixture.stream_line);
    twfRequire(! ls->awaiting_pong, "the second PONG must clear its wait");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "both timely PONGs must preserve the stream");

    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void replyDuringPing(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(packetstostreamFrameMatchesFillByte(buf, kSensitivePingByte), "expected a PING before the inline reply");
    twfNextPayload(t, l, buf);
    packetstostream_lstate_t *ls = lineGetState(g_flow_fixture->packet_line, g_flow_fixture->p2s);
    twfRequire(ls->awaiting_pong, "the wait must be published before the PING handoff");
    deliverPong(g_flow_fixture, l);
}

static void caseHeartbeatHandoffMayReenter(void)
{
    twfSetCase("packetstostream PING handoff permits synchronous PONG and Finish");
    tosResetProcessApi(true);

    g_now_us = 1000000;
    packetstostream_fixture_t fixture;
    flowFixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    fixture.next->fnPayloadU     = replyDuringPing;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    twfRequire(! ls->awaiting_pong && ls->line == fixture.stream_line,
               "an inline PONG must complete the wait without closing the stream");

    fixture.next->fnPayloadU = flowNextPayload;
    g_finish_during_payload  = true;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    twfRequire(ls->line == NULL && ! ls->awaiting_pong && fixture.timeout_timer_slot[0] == NULL,
               "an inline Finish must close the stream and clear its wait and timer");
    twfRequire(lineIsAlive(fixture.packet_line), "an inline Finish must preserve the packet line");

    tosRequireNoProcessApiCall();
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
    twfRequire(ls->ping_sent_at_us == 0 && ls->pong_deadline_us == 0, "a failed arm must not publish timestamps");
    twfRequire(! ls->recreate_scheduled, "a timer failure must not schedule an output-line recreation");
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "the timeout timer slot must stay NULL");
    twfRequire(ls->line == fixture.stream_line, "a timer failure must not drop the output line");

    fixtureTeardown(&fixture);
}

static void caseTimeoutTimerReuseFailure(void)
{
    twfSetCase("packetstostream sensitive timeout timer reuse failure");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    heartbeatFixtureSetup(&fixture);
    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);
    deliverPong(&fixture, fixture.stream_line);
    twfRequire(fixture.timeout_timer_slot[0] != NULL && ! ls->awaiting_pong,
               "a completed heartbeat must leave a timer to reuse");

    const uint32_t recycles_before = twfRecycleCount();
    g_timer_reset_closes_admission = true;
    packetstostreamHeartbeatTimerCallback(fixture.heartbeat_timer);

    tosRequireAcceptedRequest(1);
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "a refused reset must recycle the unsent PING");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "a refused reset must not forward the second PING");
    twfRequire(! ls->awaiting_pong && ls->ping_sent_at_us == 0 && ls->pong_deadline_us == 0,
               "a refused reset must leave no published wait");
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "a refused reset must clear the unused timer slot");
    twfRequire(ls->line == fixture.stream_line && lineIsAlive(fixture.stream_line),
               "a refused reset must leave the stream for worker shutdown");

    fixtureTeardown(&fixture);
}

static void caseDueTimeoutTimerRearmRefusalClearsSlot(void)
{
    twfSetCase("packetstostream due timeout timer rearm refusal");
    tosResetProcessApi(true);

    packetstostream_fixture_t fixture;
    heartbeatFixtureSetup(&fixture);

    packetstostream_lstate_t *ls = lineGetState(fixture.packet_line, fixture.p2s);
    ls->awaiting_pong            = true;
    ls->ping_sent_at_us          = g_now_us;
    ls->pong_deadline_us         = g_now_us + kTestToleranceMs * 1000ULL;

    wloop_t  *loop  = fixture.env.loops[0];
    wtimer_t *timer = __real_wtimerAddDeadline(loop, packetstostreamTimeoutTimerCallback, 1);
    twfRequire(timer != NULL, "failed to create the timeout timer fixture");
    fixture.timeout_timer_slot[0] = timer;
    weventSetUserData(timer, fixture.p2s);

    const uint32_t timers_before   = wloopNTimers(loop);
    g_now_us                       = timer->next_timeout;
    g_timer_reset_closes_admission = true;
    discard wloopProcessEvents(loop, 0);

    tosRequireNoProcessApiCall();
    twfRequire(fixture.timeout_timer_slot[0] == NULL, "reset refusal retained the timeout timer slot");
    twfRequire(! ls->awaiting_pong && ls->ping_sent_at_us == 0 && ls->pong_deadline_us == 0,
               "reset refusal must settle the wait before the timer is reclaimed");
    twfRequire(ls->line == fixture.stream_line && lineIsAlive(fixture.stream_line),
               "reset refusal must leave the stream for worker shutdown");
    twfRequireEqualU32(
        wloopNTimers(loop), timers_before - 1U, "the event loop did not reclaim the due one-shot timer exactly once");

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
    caseTimelyPongAfterStaleCache();
    caseDeadlineRetiresStream(false);
    caseDeadlineRetiresStream(true);
    caseSecondPingSupersedesPendingWake();
    caseHeartbeatHandoffMayReenter();
    caseTimeoutTimerFailure();
    caseTimeoutTimerReuseFailure();
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

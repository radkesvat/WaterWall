/*
 * Covers: MuxClient Ping/Pong parent health, rendezvous selection, and soft retirement.
 * Setup: Included by muxclient_capacity_dispatch_test.c; real owner-worker state,
 * owned parents, borrowed children, and explicit monotonic/wall-clock values.
 * CTest: waterwall.muxclient_capacity_dispatch_unit
 */
#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

static void healthTime(muxclient_capacity_fixture_t *f, uint64_t milliseconds)
{
    f->env.loop->cur_hrtime = milliseconds * 1000U;
}

static void healthSend(muxclient_capacity_fixture_t *f, line_t *child)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(f->env.pool);
    sbufSetLength(buf, 4);
    sbufWrite(buf, "data", 4);
    muxclientTunnelUpStreamPayload(f->mux, child, buf);
}

static line_t *healthProbe(muxclient_capacity_fixture_t *f)
{
    f->trace.len              = 0;
    line_t             *child = fixtureOpenChild(f);
    muxclient_lstate_t *ls    = lineGetState(child, f->mux);
    twfRequire(ls->parent != NULL, "health probe was refused");
    line_t *parent = ls->parent->l;
    fixtureFinishChild(f, child);
    return parent;
}

/* Selection fixtures start with an already confirmed peer. Protocol discovery is tested separately. */
static void healthStartPing(muxclient_capacity_fixture_t *f, muxclient_lstate_t *parent)
{
    if (! lineIsEstablished(parent->l))
        muxclientTunnelDownStreamEst(f->mux, parent->l);
    parent->parent_state->peer_keepalive  = true;
    parent->parent_state->next_ping_at_ms = 0;
    muxclientKeepaliveWorkerTick(f->mux, 0);
    twfRequire(parent->parent_state->awaiting_pong, "probe was not sent");
}

static void caseParentHealthClockAndSelection(void)
{
    twfSetCase("selection uses matching Pong and monotonic time, not user traffic or child count");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 2);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 0);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    line_t *other = ts->fixed_parent_lines[0] == parent->l ? ts->fixed_parent_lines[1] : ts->fixed_parent_lines[0];
    healthSend(&f, child);
    twfRequire(! parent->parent_state->awaiting_pong, "Data started the probe clock");
    healthStartPing(&f, parent);
    twfRequire(parent->parent_state->ping_sent_at_ms == 0, "monotonic zero is not a valid send time");
    healthTime(&f, 1000);
    healthSend(&f, child);
    sendParentFrame(&f, parent->l, ((muxclient_lstate_t *) lineGetState(child, f.mux))->connection_id, kMuxFlagData, 7);
    sendParentFrame(&f, parent->l, parent->parent_state->ping_token + 1, kMuxFlagPong, 0);
    twfRequire(parent->parent_state->awaiting_pong && parent->parent_state->ping_sent_at_ms == 0,
               "Data or wrong Pong changed the outstanding probe");
    healthTime(&f, 2499);
    bool saw_parent = false, saw_other = false;
    for (unsigned i = 0; i < 16; ++i)
    {
        line_t *chosen = healthProbe(&f);
        saw_parent |= chosen == parent->l;
        saw_other |= chosen == other;
    }
    twfRequire(saw_parent && saw_other, "rendezvous excluded a healthy busier parent");
    healthTime(&f, 2500);
    f.env.loop->cur_time_ms += 3600000;
    for (unsigned i = 0; i < 16; ++i)
        twfRequire(healthProbe(&f) == other, "suspect parent beat a healthy parent");
    twfRequire(! parent->selection_retired, "wall-clock jump caused retirement");
    uint8_t header[kMuxFrameLength];
    writeFrameHeader(header, 0, kMuxFlagPong, parent->parent_state->ping_token);
    for (unsigned part = 0; part < 2; ++part)
    {
        sbuf_t *buf = bufferpoolGetSmallBuffer(f.env.pool);
        sbufSetLength(buf, 4);
        sbufWrite(buf, header + 4 * part, 4);
        muxclientTunnelDownStreamPayload(f.mux, parent->l, buf);
        twfRequire(parent->parent_state->awaiting_pong == (part == 0), "partial Pong acknowledged too early");
    }
    healthTime(&f, 100000);
    for (unsigned i = 0; i < 8; ++i)
        discard healthProbe(&f);
    twfRequire(! parent->selection_retired, "idle parent retired without a missing probe");
    f.trace.len = 0;
    fixtureTeardown(&f);
}

static void caseParentSoftReplacement(bool blocked_output)
{
    twfSetCase("one fixed parent replaces softly, bounds retired ownership, and preserves active children");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 1000);
    line_t             *first       = fixtureOpenChild(&f);
    muxclient_lstate_t *first_child = lineGetState(first, f.mux);
    line_t             *old_parent  = first_child->parent->l;
    lineRef(old_parent);
    healthStartPing(&f, first_child->parent);
    healthTime(&f, 11000);
    line_t *second      = fixtureOpenChild(&f);
    line_t *replacement = ((muxclient_lstate_t *) lineGetState(second, f.mux))->parent->l;
    twfRequire(replacement != old_parent && lineIsAlive(first) && first_child->parent->l == old_parent,
               "soft replacement moved or closed the existing child");
    twfRequireEqualU32(ts->worker_states[0].stall_retired_parents, 1, "retired parent was not counted");
    sendParentFrame(&f, old_parent, first_child->connection_id, kMuxFlagData, 7);
    twfRequireEqualU32(f.trace.prev_payload, 1, "retired parent stopped delivering existing traffic");
    healthStartPing(&f, ((muxclient_lstate_t *) lineGetState(second, f.mux))->parent);
    healthTime(&f, 71000);
    line_t *third = fixtureOpenChild(&f);
    twfRequire(((muxclient_lstate_t *) lineGetState(third, f.mux))->parent->l == replacement,
               "retired-parent cap allowed another replacement");
    twfRequireEqualU32(f.trace.next_init, 2, "soft recovery grew the parent pool without a bound");
    twfRequire(f.trace.prev_finish == 0 && lineIsAlive(first), "long one-way traffic was forcibly killed");
    if (blocked_output)
        muxclientTunnelDownStreamPause(f.mux, old_parent);
    fixtureFinishChild(&f, first);
    twfRequire(! lineIsAlive(old_parent) && ts->worker_states[0].stall_retired_parents == 0,
               "expired retired parent waited for Resume after its final child left");
    lineUnref(old_parent);
    line_t *fourth = fixtureOpenChild(&f);
    twfRequire(((muxclient_lstate_t *) lineGetState(fourth, f.mux))->parent->l != replacement,
               "released retirement capacity was not reusable");
    fixtureTeardown(&f);
}

static line_t *health_other_parent;
static bool    health_quiesce;
static line_t *health_new_child;
static bool    health_destroy_child;

static void healthClosingParent(tunnel_t *next, line_t *parent)
{
    twfNextFinish(next, parent);
    if (health_new_child != NULL)
    {
        line_t *child    = health_new_child;
        health_new_child = NULL;
        muxclientTunnelUpStreamFinish(g_client_fixture->mux, child);
        if (health_destroy_child)
            lineDestroy(child);
    }
    if (health_other_parent != NULL)
    {
        line_t *other       = health_other_parent;
        health_other_parent = NULL;
        muxclientTunnelDownStreamFinish(g_client_fixture->mux, other);
    }
    if (health_quiesce)
        muxclientTunnelOnWorkerQuiesce(g_client_fixture->mux, 0, wwLifecycleProcessShutdown());
}

static void caseIdleStalledParent(unsigned action)
{
    twfSetCase("idle stalled cleanup survives sibling closure and worker quiescence");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 2);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 1000);
    line_t *child      = fixtureOpenChild(&f);
    line_t *old_parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent->l;
    lineRef(old_parent);
    healthStartPing(&f, lineGetState(old_parent, f.mux));
    healthTime(&f, 11000);
    muxclientTunnelDownStreamPause(f.mux, old_parent);
    fixtureFinishChild(&f, child);
    health_other_parent =
        ts->fixed_parent_lines[0] == old_parent ? ts->fixed_parent_lines[1] : ts->fixed_parent_lines[0];
    health_quiesce = action == 1;
    f.next->fnFinU = healthClosingParent;
    healthTime(&f, 11000);
    line_t *fresh = twfLinePoolCreateLine(&f.child_lines);
    fixtureTrackChild(&f, fresh);
    health_new_child             = action >= 2 ? fresh : NULL;
    health_destroy_child         = action == 2;
    const uint32_t before_est    = f.trace.prev_est;
    const uint32_t before_finish = f.trace.prev_finish;
    muxclientTunnelUpStreamInit(f.mux, fresh);
    twfRequire(! lineIsAlive(old_parent), "idle stalled parent retained blocked output");
    lineUnref(old_parent);
    if (action != 0)
        twfRequireLineStateZeroed(fresh, f.mux, "quiescence admitted a new child");
    else
        twfRequire(((muxclient_lstate_t *) lineGetState(fresh, f.mux))->parent != NULL,
                   "sibling close left the replacement selection invalid");
    if (action >= 2)
        twfRequire(f.trace.prev_est == before_est && f.trace.prev_finish == before_finish &&
                       lineIsAlive(fresh) == (action == 3),
                   "selection reflected callbacks after source Finish or revived its child");
    health_quiesce = false;
    fixtureTeardown(&f);
}

static void caseParentHealthDisabled(void)
{
    twfSetCase("disabled keepalive suppresses probes and replacement");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    healthSend(&f, child);
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(! parent->parent_state->awaiting_pong, "disabled keepalive sent a probe");
    healthTime(&f, UINT64_C(10000000));
    twfRequire(healthProbe(&f) == parent->l && ! parent->selection_retired, "disabled health policy replaced a parent");
    fixtureTeardown(&f);
}

static void healthImmediateReply(tunnel_t *next, line_t *parent_l, sbuf_t *buf)
{
    twfNextPayload(next, parent_l, buf);
    muxclient_lstate_t *parent = lineGetState(parent_l, g_client_fixture->mux);
    sendParentFrame(g_client_fixture, parent_l, parent->parent_state->ping_token, kMuxFlagPong, 0);
}

static void caseParentHealthReentrantReply(void)
{
    twfSetCase("synchronous reply clears health state published before the send callback");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts     = tunnelGetState(f.mux);
    ts->keepalive              = true;
    ts->ping_interval_ms       = 1000;
    ts->pong_timeout_ms        = 10000;
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    f.next->fnPayloadU         = healthImmediateReply;
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(! parent->parent_state->awaiting_pong && parent->parent_state->peer_keepalive,
               "inline Pong failed to confirm support or clear the probe");
    f.next->fnPayloadU = twfNextPayload;
    fixtureTeardown(&f);
}

static void caseSpliceBatchHealth(void)
{
#if WW_HAVE_SPLICE
    twfSetCase("large splice Data does not start the Ping watchdog");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 1234);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    sbuf_t             *buf    = bufferpoolGetSpliceBuffer(f.env.pool);
    twfRequire(buf != NULL, "splice health fixture could not allocate a pipe");
    const int fd = sbufSpliceMetadata(buf).pipefd[1];
    if (fcntl(fd, F_SETPIPE_SZ, kMuxMaxDataFrameLength) < (int) kMuxMaxDataFrameLength)
    {
        lineReuseBuffer(child, buf);
        fixtureTeardown(&f);
        return; // Same host prerequisite as the existing maximum-pipe batch cases.
    }
    uint8_t *bytes = memoryAllocateZero(kMuxMaxDataFrameLength);
    twfRequire(write(fd, bytes, kMuxMaxDataFrameLength) == (ssize_t) kMuxMaxDataFrameLength,
               "could not populate the splice batch");
    memoryFree(bytes);
    buf->capacity = buf->l_pad + kMuxMaxDataFrameLength;
    sbufSetLength(buf, kMuxMaxDataFrameLength);
    sbufShiftLeft(buf, 1);
    sbufGetMutablePtr(buf)[0] = 1;
    muxclientTunnelUpStreamPayload(f.mux, child, buf);
    twfRequire(! parent->parent_state->awaiting_pong, "splice upload incorrectly started the Ping watchdog");
    fixtureTeardown(&f);
#endif
}

static void caseParentProbeDiscoveryAndPause(void)
{
    twfSetCase("probe discovery, one outstanding token, interval, Pause, and late Pong recovery");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 0);
    line_t                   *child  = fixtureOpenChild(&f);
    muxclient_lstate_t       *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    muxclient_parent_state_t *state  = parent->parent_state;
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(! state->awaiting_pong, "probe sent before transport Est");
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    const uint32_t first = state->ping_token;
    healthTime(&f, 9999);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(state->ping_token == first, "more than one probe outstanding");
    healthTime(&f, 10000);
    twfRequire(healthProbe(&f) == parent->l, "unsupported peer was replaced");
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(state->ping_token != first && ! state->peer_keepalive, "discovery did not retry");
    sendParentFrame(&f, parent->l, first, kMuxFlagPong, 0);
    twfRequire(state->awaiting_pong && ! state->peer_keepalive, "stale discovery Pong accepted");
    sendParentFrame(&f, parent->l, state->ping_token, kMuxFlagPong, 0);
    twfRequire(state->peer_keepalive && ! state->awaiting_pong, "matching Pong failed discovery");
    healthTime(&f, 10999);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(! state->awaiting_pong, "ping interval ignored");
    healthTime(&f, 11000);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    sendParentFrame(&f, parent->l, state->ping_token, kMuxFlagPong, 0);
    healthTime(&f, 12000);
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    healthSend(&f, child);
    const size_t   queued      = bufferqueueGetBufCount(&state->output.pending);
    const uint32_t before_ping = f.trace.next_payload;
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(state->awaiting_pong && f.trace.next_payload == before_ping + 1 &&
                   bufferqueueGetBufCount(&state->output.pending) == queued && queued != 0,
               "paused parent blocked its probe or drained application output");
    const uint32_t active_token = state->ping_token;
    healthTime(&f, 21999);
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(state->ping_token == active_token && ! parent->selection_retired,
               "paused parent duplicated its probe or retired before the deadline");
    twfRequire(muxclientUnansweredPingMS(ts, state, 21999) == 9999, "Pause froze the reply deadline");
    healthTime(&f, 22000);
    const uint32_t before_init = f.trace.next_init;
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(parent->selection_retired && ts->fixed_parent_lines[0] == NULL && lineIsAlive(child) &&
                   f.trace.next_init == before_init && state->output.transport_paused,
               "timer did not retire a paused parent without replacing it or killing its child");
    sendParentFrame(&f, parent->l, active_token, kMuxFlagPong, 0);
    twfRequire(parent->selection_retired && ! state->awaiting_pong,
               "late matching Pong restored a retired parent to selection");
    muxclientTunnelDownStreamResume(f.mux, parent->l);
    muxclientTunnelDownStreamResume(f.mux, parent->l);
    twfRequire(parent->selection_retired, "Resume restored an expired parent to selection");
    fixtureTeardown(&f);
}

static void healthCloseSnapshot(tunnel_t *next, line_t *parent_l, sbuf_t *buf)
{
    twfNextPayload(next, parent_l, buf);
    muxclient_capacity_fixture_t *f = g_client_fixture;
    if (health_other_parent != NULL)
    {
        line_t *other       = health_other_parent;
        health_other_parent = NULL;
        muxclientHandleParentLoss(f->mux, other, true);
    }
    muxclientHandleParentLoss(f->mux, parent_l, true);
    muxclientTunnelOnWorkerQuiesce(f->mux, 0, wwLifecycleProcessShutdown());
}

static void caseParentProbeSnapshotReentrancy(void)
{
    twfSetCase("probe callback may destroy itself, another snapshot parent, and quiesce");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 2);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    discard fixtureOpenChild(&f);
    for (unsigned i = 0; i < 2; ++i)
        muxclientTunnelDownStreamEst(f.mux, ts->fixed_parent_lines[i]);
    health_other_parent = ts->fixed_parent_lines[1];
    f.next->fnPayloadU  = healthCloseSnapshot;
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(ts->worker_states[0].owned_parents == NULL, "snapshot retained closed parents");
    f.next->fnPayloadU = twfNextPayload;
    fixtureTeardown(&f);
}

static void caseParentProbeOtherModes(uint8_t mode)
{
    twfSetCase("timer/counter selection also replaces an unanswered confirmed parent with a one-parent bound");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, mode, 0);
    muxclient_tstate_t *ts   = tunnelGetState(f.mux);
    ts->concurrency_capacity = 100;
    ts->concurrency_duration = UINT32_MAX;
    ts->keepalive            = true;
    ts->ping_interval_ms     = 1000;
    ts->pong_timeout_ms      = 10000;
    healthTime(&f, 0);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    healthStartPing(&f, parent);
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    healthTime(&f, 10000);
    const uint32_t before_init = f.trace.next_init;
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(parent->selection_retired && ts->unsatisfied_lines[0] == NULL && lineIsAlive(child) &&
                   f.trace.next_init == before_init,
               "paused non-fixed parent did not retire on the worker timer");
    line_t             *second      = fixtureOpenChild(&f);
    muxclient_lstate_t *replacement = ((muxclient_lstate_t *) lineGetState(second, f.mux))->parent;
    twfRequire(replacement != parent && parent->selection_retired && lineIsAlive(child),
               "missing Pong did not retire softly");
    healthStartPing(&f, replacement);
    healthTime(&f, 20000);
    twfRequire(healthProbe(&f) == replacement->l && ts->worker_states[0].stall_retired_parents == 1,
               "non-fixed recovery exceeded its bound");
    fixtureTeardown(&f);
}

static void caseIdleParentTimeoutWhilePaused(void)
{
    twfSetCase("worker timer closes an idle expired parent and blocked final output without Resume");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 10000;
    healthTime(&f, 1000);
    line_t             *child    = fixtureOpenChild(&f);
    muxclient_lstate_t *parent   = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    line_t             *parent_l = parent->l;
    lineRef(parent_l);
    healthStartPing(&f, parent);
    muxclientTunnelDownStreamPause(f.mux, parent_l);
    fixtureFinishChild(&f, child);
    twfRequire(lineIsAlive(parent_l) && bufferqueueGetBufCount(&parent->parent_state->output.pending) != 0,
               "idle timeout fixture lost its paused final output");
    healthTime(&f, 10999);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(lineIsAlive(parent_l), "idle parent closed before its reply deadline");
    healthTime(&f, 11000);
    muxclientKeepaliveWorkerTick(f.mux, 0);
    twfRequire(! lineIsAlive(parent_l) && ts->fixed_parent_lines[0] == NULL && f.trace.next_init == 1,
               "idle expired parent waited for Resume or created a timer-owned replacement");
    lineUnref(parent_l);
    fixtureTeardown(&f);
}

/*
 * Covers: MuxClient Ping/Pong parent health, rendezvous selection, and soft retirement.
 * Setup: Included by muxclient_capacity_dispatch_test.c; real owner-worker state,
 * owned parents, borrowed children, and explicit monotonic/wall-clock values.
 * Expiry is invoked through the existing idle-table test seam; logical deadline
 * checks do not measure real timer wakeup precision or performance.
 * CTest: waterwall.muxclient_capacity_dispatch_unit
 */
#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

static void healthTime(muxclient_capacity_fixture_t *f, uint64_t milliseconds)
{
    muxclient_tstate_t *ts = tunnelGetState(f->mux);
    /* Cold timer creation refreshes the loop clock. Install it before setting
     * deterministic time; separate lifecycle cases exercise lazy creation. */
    if (ts->keepalive && ts->worker_states[0].keepalive_table == NULL)
        ts->worker_states[0].keepalive_table = localIdleTableCreate(f->env.loop);
    f->env.loop->cur_hrtime = milliseconds * 1000U;
}

static void healthTick(tunnel_t *t)
{
    muxclient_tstate_t *ts    = tunnelGetState(t);
    local_idle_table_t *table = ts->worker_states[0].keepalive_table;
    if (table != NULL && ! localidletableTestIsQuiesced(table))
        localidletableTestRunExpiry(table);
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
    muxclientTunnelDownStreamEst(f->mux, parent->l);
    muxclientDisarmKeepalive(parent);
    parent->parent_state->peer_keepalive  = true;
    parent->parent_state->next_ping_at_ms = wloopNowMonotonicMS(f->env.loop);
    muxclientArmKeepalive(f->mux, parent);
    healthTick(f->mux);
    twfRequire(parent->parent_state->awaiting_pong, "probe was not sent");
}

static void healthTickDuringWrite(tunnel_t *next, line_t *parent_l, sbuf_t *buf)
{
    twfNextPayload(next, parent_l, buf);
    healthTick(g_client_fixture->mux);
    muxclient_lstate_t *parent = lineGetState(parent_l, g_client_fixture->mux);
    twfRequire(! parent->parent_state->awaiting_pong,
               "reentrant timer started a deadline for a probe behind an active output callback");
}

static void caseParentFirstProbeWaitsForInterval(bool marked_by_next)
{
    twfSetCase("first probe waits a full interval after Est without stalling the parent");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 10000;
    ts->pong_timeout_ms    = 1000;
    healthTime(&f, 1000);
    line_t                   *child  = fixtureOpenChild(&f);
    muxclient_lstate_t       *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    muxclient_parent_state_t *state  = parent->parent_state;
    /* A downstream junction may mark its shared line before forwarding Est. */
    if (marked_by_next)
        lineMarkEstablished(parent->l);
    healthTime(&f, 100000);
    healthTick(f.mux);
    twfRequire(! state->awaiting_pong, "first probe ran before transport Est");
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    healthTick(f.mux);
    twfRequire(state->ping_token == 0 && ! state->awaiting_pong, "Est triggered an immediate first probe");
    healthTime(&f, 105000);
    twfRequire(healthProbe(&f) == parent->l && muxclientUnansweredPingMS(ts, state, 105000) == 0 &&
                   ! parent->selection_retired && lineIsAlive(child),
               "waiting for the first probe stalled the parent or blocked new children");
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    const uint32_t before_ping = f.trace.next_payload;
    healthTime(&f, 109999);
    healthTick(f.mux);
    twfRequire(f.trace.next_payload == before_ping && ! state->awaiting_pong && ! parent->selection_retired,
               "first probe escaped its interval or its unsent deadline retired the parent");
    healthTime(&f, 110000);
    healthTick(f.mux);
    healthTime(&f, 120000);
    healthTick(f.mux);
    twfRequire(f.trace.next_payload == before_ping && ! state->awaiting_pong && ! parent->selection_retired,
               "paused unsent probe was emitted or started a reply deadline");
    muxclientTunnelDownStreamResume(f.mux, parent->l);
    f.next->fnPayloadU = healthTickDuringWrite;
    healthSend(&f, child);
    f.next->fnPayloadU            = twfNextPayload;
    const uint32_t before_handoff = f.trace.next_payload;
    healthTime(&f, 121000);
    healthTick(f.mux);
    twfRequire(f.trace.next_payload == before_handoff + 1 && state->awaiting_pong && state->ping_sent_at_ms == 121000 &&
                   ! parent->selection_retired && lineIsAlive(child),
               "Resume lost the due first probe or started its deadline before handoff");
    fixtureTeardown(&f);
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
    healthTick(f.mux);
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
    healthTime(&f, 0);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    f.next->fnPayloadU         = healthImmediateReply;
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    healthTime(&f, 1000);
    healthTick(f.mux);
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
    healthTick(f.mux);
    twfRequire(! state->awaiting_pong, "probe sent before transport Est");
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    healthTime(&f, 1000);
    healthTick(f.mux);
    const uint32_t first = state->ping_token;
    twfRequire(state->awaiting_pong, "first discovery probe missed its interval");
    healthTime(&f, 10999);
    healthTick(f.mux);
    twfRequire(state->ping_token == first, "more than one probe outstanding");
    healthTime(&f, 11000);
    twfRequire(healthProbe(&f) == parent->l, "unsupported peer was replaced");
    healthTick(f.mux);
    twfRequire(state->ping_token != first && ! state->peer_keepalive, "discovery did not retry");
    sendParentFrame(&f, parent->l, first, kMuxFlagPong, 0);
    twfRequire(state->awaiting_pong && ! state->peer_keepalive, "stale discovery Pong accepted");
    sendParentFrame(&f, parent->l, state->ping_token, kMuxFlagPong, 0);
    twfRequire(state->peer_keepalive && ! state->awaiting_pong, "matching Pong failed discovery");
    healthTime(&f, 11999);
    healthTick(f.mux);
    twfRequire(! state->awaiting_pong, "ping interval ignored");
    healthTime(&f, 12000);
    healthTick(f.mux);
    sendParentFrame(&f, parent->l, state->ping_token, kMuxFlagPong, 0);
    healthTime(&f, 13000);
    const uint32_t before_ping = f.trace.next_payload;
    healthTick(f.mux);
    twfRequire(state->awaiting_pong && f.trace.next_payload == before_ping + 1, "due probe was not handed onward");
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    healthSend(&f, child);
    const size_t queued = bufferqueueGetBufCount(&state->output.pending);
    healthTick(f.mux);
    twfRequire(state->awaiting_pong && f.trace.next_payload == before_ping + 1 &&
                   bufferqueueGetBufCount(&state->output.pending) == queued && queued != 0,
               "paused parent duplicated its outstanding probe or drained application output");
    const uint32_t active_token = state->ping_token;
    healthTime(&f, 22999);
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    healthTick(f.mux);
    twfRequire(state->ping_token == active_token && ! parent->selection_retired,
               "paused parent duplicated its probe or retired before the deadline");
    twfRequire(muxclientUnansweredPingMS(ts, state, 22999) == 9999, "Pause froze the reply deadline");
    healthTime(&f, 23000);
    const uint32_t before_init = f.trace.next_init;
    healthTick(f.mux);
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
    healthTime(&f, 0);
    discard fixtureOpenChild(&f);
    muxclientTunnelDownStreamEst(f.mux, ts->fixed_parent_lines[0]);
    healthTime(&f, 1);
    muxclientTunnelDownStreamEst(f.mux, ts->fixed_parent_lines[1]);
    health_other_parent = ts->fixed_parent_lines[1];
    f.next->fnPayloadU  = healthCloseSnapshot;
    healthTime(&f, 1001);
    healthTick(f.mux);
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
    healthTick(f.mux);
    twfRequire(parent->selection_retired && ts->worker_states[0].unsatisfied_line == NULL && lineIsAlive(child) &&
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
    healthTick(f.mux);
    twfRequire(lineIsAlive(parent_l), "idle parent closed before its reply deadline");
    healthTime(&f, 11000);
    healthTick(f.mux);
    twfRequire(! lineIsAlive(parent_l) && ts->fixed_parent_lines[0] == NULL && f.trace.next_init == 1,
               "idle expired parent waited for Resume or created a timer-owned replacement");
    lineUnref(parent_l);
    fixtureTeardown(&f);
}

static void caseSeparatePingAndReplyItems(void)
{
    twfSetCase("Pong cancels only its reply item and preserves the next ping schedule");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 90000;
    healthTime(&f, 1000);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    muxclient_parent_state_t *state = parent->parent_state;
    local_idle_item_t        *ping  = state->ping_item;
    twfRequire(ping != NULL && state->pong_deadline_item == NULL, "Est did not arm exactly one ping obligation");
    healthTime(&f, 2000);
    healthTick(f.mux);
    twfRequire(state->ping_item == ping && state->pong_deadline_item != NULL &&
                   localidletableTestGetDeadline(ping) == 3000 &&
                   localidletableTestGetDeadline(state->pong_deadline_item) == 92000,
               "ping and reply obligations did not get separate deadlines");
    healthTime(&f, 2500);
    sendParentFrame(&f, parent->l, state->ping_token, kMuxFlagPong, 0);
    twfRequire(state->ping_item == ping && state->pong_deadline_item == NULL &&
                   localidletableTestGetDeadline(ping) == 3000 &&
                   localidletableGetItemCount(ts->worker_states[0].keepalive_table) == 1,
               "matching Pong moved the ping deadline or retained its reply item");
    healthTime(&f, 3000);
    healthTick(f.mux);
    twfRequire(state->awaiting_pong && state->ping_sent_at_ms == 3000 &&
                   localidletableTestGetDeadline(state->pong_deadline_item) == 93000,
               "acknowledging a long watchdog postponed the next ping");
    healthTime(&f, 4000);
    healthTick(f.mux);
    twfRequire(state->ping_token == 2 && localidletableTestGetDeadline(state->pong_deadline_item) == 93000,
               "waiting ping extended the independent reply deadline");
    fixtureTeardown(&f);
}

static void caseCappedTimeoutRetriesWithoutSelection(void)
{
    twfSetCase("a capped timeout retries after retirement capacity is released without new child selection");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 1000;
    ts->pong_timeout_ms    = 1000;
    healthTime(&f, 1000);
    line_t             *first = fixtureOpenChild(&f);
    muxclient_lstate_t *old   = ((muxclient_lstate_t *) lineGetState(first, f.mux))->parent;
    healthStartPing(&f, old);
    healthTime(&f, 2000);
    healthTick(f.mux);
    twfRequire(old->selection_retired, "initial timeout did not occupy retirement capacity");
    line_t             *second      = fixtureOpenChild(&f);
    muxclient_lstate_t *replacement = ((muxclient_lstate_t *) lineGetState(second, f.mux))->parent;
    healthStartPing(&f, replacement);
    healthTime(&f, 3000);
    healthTick(f.mux);
    twfRequire(! replacement->selection_retired && replacement->parent_state->pong_deadline_item != NULL,
               "capped timeout retired another parent or forgot its pending expiry");
    const uint32_t initialized = f.trace.next_init;
    fixtureFinishChild(&f, first);
    twfRequire(ts->worker_states[0].stall_retired_parents == 0, "old parent did not release retirement capacity");
    healthTime(&f, 4000);
    healthTick(f.mux);
    twfRequire(replacement->selection_retired && lineIsAlive(second) && f.trace.next_init == initialized &&
                   replacement->parent_state->ping_item == NULL &&
                   replacement->parent_state->pong_deadline_item == NULL,
               "deferred timeout needed selection, created a replacement, or retained retired health items");
    fixtureTeardown(&f);
}

static void caseReplyDeadlinePrecedesNextPing(void)
{
    twfSetCase("subsecond reply expiry retires a paused parent before its longer ping interval");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(f.mux);
    ts->keepalive          = true;
    ts->ping_interval_ms   = 10000;
    ts->pong_timeout_ms    = 100;
    healthTime(&f, 1000);
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    healthStartPing(&f, parent);
    twfRequire(localidletableTestGetDeadline(parent->parent_state->pong_deadline_item) == 1100 &&
                   localidletableTestGetDeadline(parent->parent_state->ping_item) == 11000,
               "short reply timeout was tied to the next ping");
    muxclientTunnelDownStreamPause(f.mux, parent->l);
    healthTime(&f, 1099);
    healthTick(f.mux);
    twfRequire(! parent->selection_retired, "parent retired before its elapsed reply timeout");
    healthTime(&f, 1100);
    healthTick(f.mux);
    twfRequire(parent->selection_retired && lineIsAlive(child),
               "separate short reply obligation waited for a ping or terminated the child");
    fixtureTeardown(&f);
}

static void caseKeepaliveTableAdmission(bool quiesce_before_est)
{
    twfSetCase("keepalive table starts lazily at Est and quiescence prevents late admission");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts     = tunnelGetState(f.mux);
    ts->keepalive              = true;
    ts->ping_interval_ms       = 1000;
    ts->pong_timeout_ms        = 10000;
    line_t             *child  = fixtureOpenChild(&f);
    muxclient_lstate_t *parent = ((muxclient_lstate_t *) lineGetState(child, f.mux))->parent;
    twfRequire(ts->worker_states[0].keepalive_table == NULL, "Init eagerly created a keepalive table");
    if (quiesce_before_est)
        muxclientTunnelOnWorkerQuiesce(f.mux, 0, wwLifecycleProcessShutdown());
    muxclientTunnelDownStreamEst(f.mux, parent->l);
    if (quiesce_before_est)
    {
        twfRequire(ts->worker_states[0].keepalive_table == NULL && parent->parent_state->ping_item == NULL,
                   "late Est admitted a table or ping after quiescence");
    }
    else
    {
        local_idle_table_t *table = ts->worker_states[0].keepalive_table;
        twfRequire(table != NULL && parent->parent_state->ping_item != NULL && f.trace.next_payload == 0,
                   "Est failed lazy scheduling or sent an immediate probe");
        uint64_t deadline = localidletableTestGetDeadline(parent->parent_state->ping_item);
        twfRequire(deadline == wloopNowMonotonicMS(f.env.loop) + 1000,
                   "cold timer clock refresh shortened the first ping interval");
        muxclientTunnelDownStreamEst(f.mux, parent->l);
        twfRequire(ts->worker_states[0].keepalive_table == table &&
                       localidletableTestGetDeadline(parent->parent_state->ping_item) == deadline,
                   "repeated Est reset the lazy schedule");
    }
    fixtureTeardown(&f);
}

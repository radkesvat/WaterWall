#include "structure.h"

#include "loggers/network_logger.h"

uint64_t muxclientUnansweredPingMS(const muxclient_tstate_t *ts, const muxclient_parent_state_t *state, uint64_t now)
{
    if (! ts->keepalive || ! state->peer_keepalive || ! state->awaiting_pong)
        return 0;
    return now >= state->ping_sent_at_ms ? now - state->ping_sent_at_ms : 0;
}

static void muxclientProbeParent(tunnel_t *t, line_t *l)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    if (! lineIsAlive(l) || ts->worker_states[lineGetWID(l)].quiescing)
        return;
    muxclient_lstate_t *parent = lineGetState(l, t);
    if (parent->parent_state == NULL || parent->parent_finishing || parent->selection_retired)
        return;
    muxclient_parent_state_t *state = parent->parent_state;
    if (! state->transport_established)
        return;
    const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
    if (state->awaiting_pong)
    {
        if (state->peer_keepalive || now - state->ping_sent_at_ms < ts->pong_timeout_ms)
            return;
        // No confirmed support yet: retry discovery without penalizing the parent.
        state->awaiting_pong = false;
    }
    if (now < state->next_ping_at_ms)
        return;

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    ++state->ping_token;
    muxMakeMuxFrame(buf, state->ping_token, kMuxFlagPing);
    // Publish before forwarding: a response or Finish may arrive synchronously.
    state->awaiting_pong   = true;
    state->ping_sent_at_ms = now;
    state->next_ping_at_ms = now + ts->ping_interval_ms;
    discard muxclientSendParentOutput(t, l, buf, NULL, kMuxFlagPing);
}

void muxclientKeepaliveWorkerTick(tunnel_t *t, wid_t wid)
{
    assert(currentThreadIsEventWorkerWID(wid));
    muxclient_tstate_t *ts = tunnelGetState(t);
    assert(wid < ts->workers_count);
    if (! ts->keepalive || ts->worker_states[wid].quiescing)
        return;
    const bool   fixed = ts->concurrency_mode == kConcurrencyModeFixedConnectionsCount;
    const size_t count = fixed ? ts->fixed_connections_count : 1;
    line_t     **slots = fixed ? &ts->fixed_parent_lines[(size_t) wid * count] : &ts->unsatisfied_lines[wid];
    size_t       bytes;
    if (! memoryTryComputeArraySize(count, sizeof(line_t *), &bytes))
    {
        LOGF("MuxClient: keepalive snapshot geometry overflow");
        abortProgramNow(1);
    }
    line_t **snapshot = memoryAllocate(bytes);
    if (snapshot == NULL)
    {
        LOGW("MuxClient: keepalive snapshot allocation failed");
        return;
    }
    // A callback can close any sibling or reuse a selection slot. Hold every entry first.
    for (size_t i = 0; i < count; ++i)
    {
        snapshot[i] = slots[i];
        if (snapshot[i] != NULL)
            lineRef(snapshot[i]);
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (snapshot[i] != NULL)
        {
            if (lineIsAlive(snapshot[i]) && slots[i] == snapshot[i])
                muxclientRetireUnresponsiveParent(t, ts, wid, &slots[i]);
            if (lineIsAlive(snapshot[i]))
                muxclientProbeParent(t, snapshot[i]);
            lineUnref(snapshot[i]);
        }
    }
    memoryFree(snapshot);
}

static void muxclientKeepaliveTimer(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t != NULL)
        muxclientKeepaliveWorkerTick(t, getLoopEventWorkerWID(weventGetLoop(timer)));
}

static void muxclientStartKeepalive(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard                   arg2;
    discard                   arg3;
    worker_t                 *worker = worker_ptr;
    tunnel_t                 *t      = arg1;
    muxclient_tstate_t       *ts     = tunnelGetState(t);
    muxclient_worker_state_t *state  = &ts->worker_states[worker->wid];
    if (state->quiescing)
        return;
    assert(state->keepalive_timer == NULL);
    const uint32_t interval = min((uint32_t) kMuxKeepaliveCheckMs, min(ts->ping_interval_ms, ts->pong_timeout_ms));
    state->keepalive_timer  = wtimerAdd(worker->loop, muxclientKeepaliveTimer, interval, INFINITE);
    if (state->keepalive_timer == NULL)
    {
        LOGF("MuxClient: failed to create keepalive timer");
        if (! requestProgramShutdown(1))
            abortProgramNow(1);
        return;
    }
    weventSetUserData(state->keepalive_timer, t);
}

void muxclientTunnelOnStart(tunnel_t *t)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->keepalive)
        return;
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (sendWorkerMessageForceQueueWithCleanup(wid, muxclientStartKeepalive, NULL, t, NULL, NULL) !=
            kWorkerMessageSubmitAccepted)
        {
            LOGF("MuxClient: failed to admit keepalive startup on worker %u", (unsigned int) wid);
            startupFailureRecord(1);
            return;
        }
    }
}

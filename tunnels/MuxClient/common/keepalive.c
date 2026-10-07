#include "structure.h"

#include "loggers/network_logger.h"

static void muxclientPingExpired(local_idle_item_t *item);
static void muxclientPongDeadlineExpired(local_idle_item_t *item);

static void muxclientRemoveKeepaliveItem(local_idle_item_t **slot)
{
    local_idle_item_t *item = *slot;
    if (item == NULL)
        return;
    *slot              = NULL;
    const bool removed = localidletableRemoveIdleItem(item->table, item);
    assert(removed);
    discard removed;
}

static local_idle_item_t *muxclientCreateKeepaliveItem(muxclient_lstate_t *parent, local_idle_item_t **slot,
                                                       LocalIdleExpireCallBack callback, uint64_t age_ms)
{
    _Static_assert(sizeof(uintptr_t) <= sizeof(hash_t), "MuxClient keepalive item keys must fit pointers");
    assert(lineIsOnCurrentEventWorker(parent->l) && *slot == NULL);
    muxclient_tstate_t *ts    = tunnelGetState(parent->parent_state->t);
    local_idle_table_t *table = ts->worker_states[lineGetWID(parent->l)].keepalive_table;
    local_idle_item_t  *item  = localidletableCreateItem(table, (hash_t) (uintptr_t) slot, parent, callback, age_ms);
    if (UNLIKELY(item == NULL))
    {
        LOGF("MuxClient: duplicate keepalive item key");
        abortProgramNow(1);
    }
    return item;
}

void muxclientDisarmKeepalive(muxclient_lstate_t *parent)
{
    assert(lineIsOnCurrentEventWorker(parent->l));
    muxclientRemoveKeepaliveItem(&parent->parent_state->ping_item);
    muxclientRemoveKeepaliveItem(&parent->parent_state->pong_deadline_item);
}

void muxclientAcknowledgePong(muxclient_parent_state_t *state)
{
    muxclientRemoveKeepaliveItem(&state->pong_deadline_item);
    state->awaiting_pong = false;
}

uint64_t muxclientUnansweredPingMS(const muxclient_tstate_t *ts, const muxclient_parent_state_t *state, uint64_t now)
{
    if (! ts->keepalive || ! state->peer_keepalive || ! state->awaiting_pong)
        return 0;
    return now >= state->ping_sent_at_ms ? now - state->ping_sent_at_ms : 0;
}

static bool muxclientProbeParent(tunnel_t *t, line_t *l)
{
    assert(lineIsOnCurrentEventWorker(l));
    muxclient_tstate_t *ts = tunnelGetState(t);
    if (! lineIsAlive(l))
        return false;
    muxclient_lstate_t *parent = lineGetState(l, t);
    if (ts->worker_states[lineGetWID(l)].quiescing || parent->parent_finishing || parent->selection_retired)
        return true;
    muxclient_parent_state_t *state = parent->parent_state;
    assert(state != NULL && state->transport_established);
    const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
    if (state->awaiting_pong || now < state->next_ping_at_ms)
        return true;
    /* An unsent probe retains its due time without entering the FIFO or
     * starting a reply deadline. */
    if (state->output.transport_paused || state->output.pumping || bufferqueueGetBufCount(&state->output.pending) != 0)
        return true;

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    ++state->ping_token;
    muxMakeMuxFrame(buf, state->ping_token, kMuxFlagPing);
    // Publish the token and deadline before a synchronous Pong or Finish.
    state->awaiting_pong      = true;
    state->ping_sent_at_ms    = now;
    state->next_ping_at_ms    = now + ts->ping_interval_ms;
    state->pong_deadline_item = muxclientCreateKeepaliveItem(
        parent, &state->pong_deadline_item, muxclientPongDeadlineExpired, ts->pong_timeout_ms);
    return muxclientSendParentOutput(t, l, buf, NULL, kMuxFlagPing);
}

static void muxclientRearmPing(muxclient_lstate_t *parent)
{
    muxclient_parent_state_t *state = parent->parent_state;
    if (state == NULL || state->ping_item == NULL)
        return;
    const uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(parent->l)));
    const uint64_t age = state->next_ping_at_ms > now ? state->next_ping_at_ms - now : kMuxKeepaliveRetryMs;
    localidletableKeepIdleItemForAtleast(state->ping_item->table, state->ping_item, age);
}

static void muxclientPingExpired(local_idle_item_t *item)
{
    muxclient_lstate_t *parent = item->userdata;
    tunnel_t           *t      = parent->parent_state->t;
    line_t             *l      = parent->l;
    assert(lineIsOnCurrentEventWorker(l));
    assert(parent->parent_state->ping_item == item);
    /* Only this exact line needs a reference. Reentrant sibling removal takes
     * that sibling out of the table before the heap visits it. */
    lineRef(l);
    if (muxclientProbeParent(t, l))
        muxclientRearmPing(parent);
    lineUnref(l);
}

static void muxclientPongDeadlineExpired(local_idle_item_t *item)
{
    muxclient_lstate_t       *parent = item->userdata;
    muxclient_parent_state_t *state  = parent->parent_state;
    tunnel_t                 *t      = state->t;
    line_t                   *l      = parent->l;
    assert(lineIsOnCurrentEventWorker(l));
    assert(state->awaiting_pong && state->pong_deadline_item == item);
    lineRef(l);
    if (! state->peer_keepalive)
    {
        // An unconfirmed peer may have keepalive disabled: retry discovery.
        muxclientAcknowledgePong(state);
        if (muxclientProbeParent(t, l))
            muxclientRearmPing(parent);
    }
    else
    {
        assert(state->selection_slot != NULL && *state->selection_slot == l);
        muxclient_tstate_t *ts = tunnelGetState(t);
        muxclientRetireUnresponsiveParent(t, ts, lineGetWID(l), state->selection_slot);
        if (lineIsAlive(l) && parent->parent_state != NULL && parent->parent_state->pong_deadline_item == item)
        {
            /* Retirement capacity can be occupied. Retry without moving the
             * original send time, including while output is paused. */
            localidletableKeepIdleItemForAtleast(item->table, item, kMuxKeepaliveRetryMs);
        }
    }
    lineUnref(l);
}

void muxclientArmKeepalive(tunnel_t *t, muxclient_lstate_t *parent)
{
    assert(lineIsOnCurrentEventWorker(parent->l));
    muxclient_tstate_t       *ts     = tunnelGetState(t);
    muxclient_worker_state_t *worker = &ts->worker_states[lineGetWID(parent->l)];
    muxclient_parent_state_t *state  = parent->parent_state;
    assert(state->transport_established && state->ping_item == NULL);
    if (! ts->keepalive || worker->quiescing || parent->selection_retired)
        return;
    wloop_t       *loop = getWorkerLoop(lineGetWID(parent->l));
    const uint64_t now  = wloopNowMonotonicMS(loop);
    const uint64_t age  = state->next_ping_at_ms > now ? state->next_ping_at_ms - now : 0;
    if (worker->keepalive_table == NULL)
    {
        worker->keepalive_table = localIdleTableCreate(loop);
        // Installing the table timer refreshes the owner's cached loop clock.
        state->next_ping_at_ms = wloopNowMonotonicMS(loop) + age;
    }
    state->ping_item = muxclientCreateKeepaliveItem(parent, &state->ping_item, muxclientPingExpired, age);
}

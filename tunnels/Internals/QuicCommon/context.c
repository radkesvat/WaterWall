#include "runtime.h"

#include "loggers/network_logger.h"

quic_context_t *quicGetContext(tunnel_t *t, line_t *l)
{
    assert(lineIsAlive(l) && lineIsOnCurrentWorker(l));
    quic_lstate_t *state = lineGetState(l, t);
    return state->context;
}

static void quicFree(quic_context_t *context)
{
    assert(! context->attached && ! context->driving);
    assert(context->application_line == NULL && context->carrier_line == NULL);
    ww_quic_engine_destroy(context->engine);
    memoryFree(context);
}

bool quicEnter(quic_context_t *context)
{
    if (context->driving)
        return false;
    assert(context->attached);
    context->driving = true;
    return true;
}

void quicLeave(quic_context_t *context)
{
    assert(context->driving);
    context->driving = false;
    if (! context->attached)
        quicFree(context);
}

static void *quicCarrierAllocate(void *owner, size_t length)
{
    quic_context_t      *context = owner;
    quic_tstate_t       *state   = tunnelGetState(context->tunnel);
    buffer_budget_cost_t cost    = {.charge = length};
    if (quicInputEntries(context) >= state->max_buffers || ! bufferbudgetTryAcquire(&context->input_budget, cost))
        return NULL;
    ++context->carrier_allocations;
    return memoryAllocate(length);
}

static void quicCarrierDeallocate(void *owner, void *pointer, size_t length)
{
    quic_context_t *context = owner;
    memoryFree(pointer);
    assert(context->carrier_allocations != 0);
    --context->carrier_allocations;
    bufferbudgetRelease(&context->input_budget, (buffer_budget_cost_t) {.charge = length});
}

/* Null the association before calling out. A sibling callback can finish the
 * other line; the entered driver keeps only the independent context alive. */
static void quicDetachSide(quic_context_t *context, bool application, bool notify)
{
    line_t **slot = application ? &context->application_line : &context->carrier_line;
    line_t  *line = *slot;
    if (line == NULL)
        return;
    *slot                      = NULL;
    tunnel_t            *t     = context->tunnel;
    const quic_tstate_t *state = tunnelGetState(t);
    bool                 owned = application != state->client;
    lineRef(line);
    memoryZeroAligned32(lineGetState(line, t), tunnelGetCorrectAlignedLineStateSize(sizeof(quic_lstate_t)));
    if (notify && (! owned || context->next_init_sent))
    {
        if (owned)
            tunnelNextUpStreamFinish(t, line);
        else
            tunnelPrevDownStreamFinish(t, line);
    }
    if (owned && lineIsAlive(line))
        lineDestroy(line);
    lineUnref(line);
}

void quicRetire(quic_context_t *context)
{
    assert(context->attached && context->driving);
    context->attached = false;
    quicCancelTimer(context);
    quic_tstate_t *state = tunnelGetState(context->tunnel);
    if (context->previous != NULL)
        context->previous->next = context->next;
    else
        state->workers[context->wid] = context->next;
    if (context->next != NULL)
        context->next->previous = context->previous;
    context->previous = context->next = NULL;
    quicReleaseActive(context, true);
    quicReleaseActive(context, false);
    bufferqueueDestroy(&context->application);
    bufferqueueDestroy(&context->input);
    ww_quic_carrier_destroy(&context->carrier);
    assert(context->carrier_allocations == 0);
    bufferbudgetAssertEmpty(&context->application_budget);
    bufferbudgetAssertEmpty(&context->input_budget);
    /* Next before prev. Nested Finish of the other side is allowed, but the
     * detached context cannot admit input, timers or further protocol work. */
    quicDetachSide(context, ! state->client, true);
    quicDetachSide(context, state->client, true);
}

void quicFail(quic_context_t *context, const char *reason)
{
    assert(context->attached && context->driving);
    quic_tstate_t *state = tunnelGetState(context->tunnel);
    if (strcmp(reason, WW_QUIC_CLOSE_FINISHED) == 0)
        LOGD("%s: association finished", state->client ? "QuicClient" : "QuicServer");
    else
        LOGW("%s: closing association: %s", state->client ? "QuicClient" : "QuicServer", reason);
    quicRetire(context);
}

bool quicSurvived(const quic_context_t *context)
{
    return context->attached;
}

static void quicCopyContext(line_t *next, line_t *previous, const quic_tstate_t *state)
{
    addresscontextCopy(lineGetSourceAddressContext(next), lineGetSourceAddressContext(previous));
    addresscontextCopy(lineGetDestinationAddressContext(next), lineGetDestinationAddressContext(previous));
    lineGetRoutingContext(next)->local_listener_port = lineGetRoutingContext(previous)->local_listener_port;
    lineGetRoutingContext(next)->peer_source_port    = lineGetRoutingContext(previous)->peer_source_port;
    lineCopyUsers(next, previous);
    if (lineIsFallback(previous))
    {
        lineMarkFallback(next);
        if (lineHasCloseLingerReason(previous, kLineCloseLingerPeerWriteShutdown))
            lineRequestCloseLinger(next, kLineCloseLingerPeerWriteShutdown);
    }
    if (linePrefersOrdinaryReadUpstream(previous))
        linePreferOrdinaryReadUpstream(next);
    if (linePrefersOrdinaryReadDownstream(previous))
        linePreferOrdinaryReadDownstream(next);
    const uint8_t protocol = state->client && ! state->stream_carrier ? IP_PROTO_UDP : IP_PROTO_TCP;
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(next), protocol);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(next), protocol);
}

quic_context_t *quicBeginLineInit(tunnel_t *t, line_t *l)
{
    assert(lineIsOnCurrentWorker(l));
    quic_lstate_t *line_state = lineGetState(l, t);
    memoryZeroAligned32(line_state, tunnelGetCorrectAlignedLineStateSize(sizeof(*line_state)));
    quic_tstate_t *state = tunnelGetState(t);
    if (atomicLoadRelaxed(&state->stopping) || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return NULL;
    quic_context_t *context = memoryCalloc(1, sizeof(*context));
    context->tunnel         = t;
    context->wid            = lineGetWID(l);
    context->pool           = lineGetBufferPool(l);
    context->engine         = ww_quic_engine_create(state->config);
    context->attached       = true;
    line_t *next            = lineCreate(t->chain->line_pools, context->wid);
    quicCopyContext(next, l, state);
    context->application_line                          = state->client ? l : next;
    context->carrier_line                              = state->client ? next : l;
    ((quic_lstate_t *) lineGetState(next, t))->context = context;
    line_state->context                                = context;
    context->carrier =
        (ww_quic_carrier_t) {.context = context, .allocate = quicCarrierAllocate, .deallocate = quicCarrierDeallocate};
    buffer_budget_cost_t limits = {.bytes = state->max_bytes, .charge = (size_t) state->max_bytes * 2};
    bufferbudgetInit(&context->application_budget, limits);
    bufferbudgetInit(&context->input_budget, limits);
    bufferqueueInitEmpty(&context->application);
    bufferqueueInitEmpty(&context->input);
    bool app_attached   = bufferqueueTryAttachBudget(&context->application, &context->application_budget);
    bool input_attached = bufferqueueTryAttachBudget(&context->input, &context->input_budget);
    assert(app_attached && input_attached);
    discard app_attached;
    discard input_attached;
    context->next = state->workers[context->wid];
    if (context->next != NULL)
        context->next->previous = context;
    state->workers[context->wid] = context;
    if (state->verbose)
        LOGD("%s: initializing split association on worker %u with %s carrier",
             state->client ? "QuicClient" : "QuicServer",
             (unsigned) context->wid,
             state->stream_carrier ? "stream" : "datagram");
    bool entered = quicEnter(context);
    assert(entered);
    discard entered;
    /* The caller dispatches next Init immediately; nested callbacks may finish
     * either line before that dispatch returns. */
    context->next_init_sent = true;
    return context;
}

line_t *quicNextLine(quic_context_t *context)
{
    const quic_tstate_t *state = tunnelGetState(context->tunnel);
    return state->client ? context->carrier_line : context->application_line;
}

void quicCompleteLineInit(quic_context_t *context)
{
    assert(context->driving);
    if (quicSurvived(context))
        quicPump(context);
    quicLeave(context);
}

static void quicBeginDrain(quic_context_t *context)
{
    if (context->final_deadline_us == 0)
    {
        const quic_tstate_t *state = tunnelGetState(context->tunnel);
        context->final_deadline_us = ww_quic_now_us() + (uint64_t) state->close_drain_timeout_ms * 1000;
    }
    context->final_flush = true;
}

void quicPeerFinish(quic_context_t *context)
{
    assert(context->attached && context->driving);
    quicBeginDrain(context);
    quicDetachSide(context, true, true);
}

void quicFinishApplication(tunnel_t *t, line_t *l)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL && context->application_line == l);
    bool entered = quicEnter(context);
    quicBeginDrain(context);
    quicDetachSide(context, true, false);
    if (quicSurvived(context))
    {
        const quic_tstate_t *state = tunnelGetState(t);
        if (atomicLoadRelaxed(&state->stopping))
            quicRetire(context);
        else if (entered)
            quicPump(context);
    }
    if (entered)
        quicLeave(context);
}

void quicFinishCarrier(tunnel_t *t, line_t *l)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL && context->carrier_line == l);
    bool entered = quicEnter(context);
    quicDetachSide(context, false, false);
    if (quicSurvived(context))
        quicRetire(context);
    if (entered)
        quicLeave(context);
}

static void quicRelay(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal, bool up)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    if (! context->attached)
        return;
    const quic_tstate_t *state  = tunnelGetState(t);
    line_t              *target = up == state->client ? context->carrier_line : context->application_line;
    if (target == NULL)
        return;
    bool entered = quicEnter(context);
    lineRef(target);
    signal(t, target);
    lineUnref(target);
    if (entered)
    {
        if (quicSurvived(context))
            quicPump(context);
        quicLeave(context);
    }
}

void quicRelayUp(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal)
{
    quicRelay(t, l, signal, true);
}
void quicRelayDown(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal)
{
    quicRelay(t, l, signal, false);
}

/* The carrier's flow signals reach the application only while QUIC's own backlog does not hold it. A
 * Resume under that pressure would let the next reads pass the hard budget and close the association. */
void quicSetCarrierPaused(tunnel_t *t, line_t *l, bool paused)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    if (! context->attached || context->application_line == NULL)
    {
        return;
    }
    context->carrier_paused = paused;
    bool entered            = quicEnter(context);
    if (! context->pressure)
    {
        const quic_tstate_t *state       = tunnelGetState(t);
        line_t              *application = context->application_line;
        lineRef(application);
        if (paused)
        {
            state->output->application_pause(t, application);
        }
        else
        {
            state->output->application_resume(t, application);
        }
        lineUnref(application);
    }
    if (entered)
    {
        if (quicSurvived(context))
        {
            quicPump(context);
        }
        quicLeave(context);
    }
}

void quicCloseAdmission(tunnel_t *t)
{
    quic_tstate_t *state = tunnelGetState(t);
    atomicStoreRelaxed(&state->stopping, true);
}
void quicQuiesceWorker(tunnel_t *t, wid_t wid)
{
    assert(currentThreadOwnsWorker(wid));
    quic_tstate_t *state = tunnelGetState(t);
    for (quic_context_t *session = state->workers[wid]; session != NULL; session = session->next)
    {
        assert(! session->driving);
        quicCancelTimer(session);
    }
}
void quicStopWorker(tunnel_t *t, wid_t wid)
{
    assert(currentThreadOwnsWorker(wid));
    quic_tstate_t *state = tunnelGetState(t);
    while (state->workers[wid] != NULL)
    {
        quic_context_t *context = state->workers[wid];
        bool            entered = quicEnter(context);
        assert(entered);
        discard entered;
        quicRetire(context);
        quicLeave(context);
    }
}
void quicDestroyState(tunnel_t *t)
{
    quic_tstate_t *state = tunnelGetState(t);
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        if (state->workers[wid] != NULL)
        {
            LOGF("QUIC: destroying tunnel with sessions still attached");
            abortProgramNow(1);
        }
    }
    memoryFree(state->workers);
    ww_quic_config_destroy(state->config);
}

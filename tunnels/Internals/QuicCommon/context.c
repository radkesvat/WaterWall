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
    ww_quic_engine_destroy(context->engine);
    memoryFree(context);
}

bool quicEnter(quic_context_t *context)
{
    if (context->driving)
    {
        return false;
    }
    assert(context->attached);
    context->driving = true;
    lineRef(context->line);
    return true;
}

void quicLeave(quic_context_t *context)
{
    assert(context->driving);
    line_t *line     = context->line;
    context->driving = false;
    if (! context->attached)
    {
        quicFree(context);
    }
    lineUnref(line);
}

static void *quicCarrierAllocate(void *owner, size_t length)
{
    quic_context_t      *context = owner;
    buffer_budget_cost_t cost    = {.charge = length, .entries = 1};
    if (! bufferbudgetTryAcquire(&context->input_budget, cost))
    {
        return NULL;
    }
    return memoryAllocate(length);
}

static void quicCarrierDeallocate(void *owner, void *pointer, size_t length)
{
    quic_context_t *context = owner;
    memoryFree(pointer);
    bufferbudgetRelease(&context->input_budget, (buffer_budget_cost_t) {.charge = length, .entries = 1});
}

static void quicDetach(quic_context_t *context)
{
    assert(context->attached);
    context->attached = false;
    quicCancelTimer(context);
    quic_tstate_t *state = tunnelGetState(context->tunnel);
    const wid_t    wid   = lineGetWID(context->line);
    if (context->previous != NULL)
    {
        context->previous->next = context->next;
    }
    else
    {
        state->workers[wid] = context->next;
    }
    if (context->next != NULL)
    {
        context->next->previous = context->previous;
    }
    quic_lstate_t *line_state = lineGetState(context->line, context->tunnel);
    memoryZeroAligned32(line_state, tunnelGetCorrectAlignedLineStateSize(sizeof(*line_state)));
    quicReleaseActive(context, true);
    quicReleaseActive(context, false);
    bufferqueueDestroy(&context->application);
    bufferqueueDestroy(&context->input);
    ww_quic_carrier_destroy(&context->carrier);
    bufferbudgetAssertEmpty(&context->application_budget);
    bufferbudgetAssertEmpty(&context->input_budget);
    if (! context->driving)
    {
        quicFree(context);
    }
}

void quicFail(quic_context_t *context, const char *reason)
{
    assert(context->attached && context->driving);
    tunnel_t      *t                = context->tunnel;
    line_t        *l                = context->line;
    bool           next_initialized = context->next_init_sent;
    bool           finish_up        = context->finish_up;
    bool           finish_down      = context->finish_down;
    quic_tstate_t *state            = tunnelGetState(t);
    LOGW("%s: closing association: %s", state->client ? "QuicClient" : "QuicServer", reason);
    quicDetach(context);
    if (next_initialized && ! finish_down)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (! finish_up && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

bool quicSurvived(const quic_context_t *context)
{
    return context->attached && lineIsAlive(context->line);
}

quic_context_t *quicBeginLineInit(tunnel_t *t, line_t *l)
{
    assert(lineIsOnCurrentWorker(l));
    quic_lstate_t *line_state = lineGetState(l, t);
    memoryZeroAligned32(line_state, tunnelGetCorrectAlignedLineStateSize(sizeof(*line_state)));
    quic_tstate_t *state = tunnelGetState(t);
    if (atomicLoadRelaxed(&state->stopping))
    {
        return NULL;
    }
    quic_context_t *context = memoryCalloc(1, sizeof(*context));
    context->tunnel         = t;
    context->line           = l;
    context->pool           = lineGetBufferPool(l);
    context->engine         = ww_quic_engine_create(state->config);
    context->attached       = true;
    context->carrier =
        (ww_quic_carrier_t) {.context = context, .allocate = quicCarrierAllocate, .deallocate = quicCarrierDeallocate};
    buffer_budget_cost_t limits = {
        .bytes = state->max_bytes, .charge = (size_t) state->max_bytes * 2, .entries = state->max_buffers};
    bufferbudgetInit(&context->application_budget, limits);
    bufferbudgetInit(&context->input_budget, limits);
    bufferqueueInitEmpty(&context->application);
    bufferqueueInitEmpty(&context->input);
    bool app_attached   = bufferqueueTryAttachBudget(&context->application, &context->application_budget);
    bool input_attached = bufferqueueTryAttachBudget(&context->input, &context->input_budget);
    assert(app_attached && input_attached);
    discard app_attached;
    discard input_attached;
    wid_t   wid   = lineGetWID(l);
    context->next = state->workers[wid];
    if (context->next != NULL)
    {
        context->next->previous = context;
    }
    state->workers[wid] = context;
    line_state->context = context;
    if (state->verbose)
    {
        LOGD("%s: initializing borrowed line on worker %u with %s carrier",
             state->client ? "QuicClient" : "QuicServer",
             (unsigned) wid,
             state->stream_carrier ? "stream" : "datagram");
    }
    bool entered = quicEnter(context);
    assert(entered);
    discard entered;
    /* Publish before Init: eager Est, Payload and Finish may arrive inline. */
    context->next_init_sent = true;
    return context;
}

void quicCompleteLineInit(quic_context_t *context)
{
    assert(context->driving);
    if (quicSurvived(context))
    {
        quicPump(context);
    }
    quicLeave(context);
}

quic_finish_scope_t quicBeginFinish(tunnel_t *t, line_t *l, quic_finish_side_t sender, quic_finish_mode_t mode)
{
    assert(sender == kQuicFinishFromPrev || sender == kQuicFinishFromNext);
    assert(mode == kQuicFinishFlushApplication || mode == kQuicFinishDiscardCarrier);
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    quic_finish_scope_t scope         = {.context = context, .entered = quicEnter(context)};
    bool                was_finishing = context->finish_up || context->finish_down;
    if (sender == kQuicFinishFromPrev)
    {
        context->finish_up = true;
    }
    else
    {
        context->finish_down = true;
    }
    quicCancelTimer(context);
    if (was_finishing)
    {
        // The other still-open side finished during final wire delivery.
        quicDetach(context);
    }
    else
    {
        if (mode == kQuicFinishFlushApplication && ww_quic_engine_ready(context->engine))
        {
            quicFinalWire(context);
        }
        if (quicSurvived(context))
        {
            scope.forward = sender == kQuicFinishFromNext || context->next_init_sent;
            quicDetach(context);
        }
    }
    return scope;
}

void quicEndFinish(quic_finish_scope_t *scope)
{
    if (scope->entered)
    {
        quicLeave(scope->context);
    }
}

bool quicCanRelay(tunnel_t *t, line_t *l)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    return ! context->finish_up && ! context->finish_down;
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

void quicDestroyState(tunnel_t *t)
{
    quic_tstate_t *state = tunnelGetState(t);
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        if (state->workers[wid] != NULL)
        {
            LOGF("QUIC: destroying tunnel with borrowed sessions still attached");
            abortProgramNow(1);
        }
    }
    memoryFree(state->workers);
    ww_quic_config_destroy(state->config);
}

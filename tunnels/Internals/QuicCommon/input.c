#include "runtime.h"

#include "loggers/network_logger.h"

typedef enum quic_input_kind
{
    kQuicInputApplication,
    kQuicInputCarrier
} quic_input_kind_t;

void quicReleaseActiveApplication(quic_context_t *context)
{
    if (context->active_application != NULL)
    {
        bufferpoolReuseBuffer(context->pool, context->active_application);
        context->active_application = NULL;
        bufferbudgetReservationRelease(&context->application_reservation);
    }
}

bool quicFeedInput(quic_context_t *context)
{
    sbuf_t *buffer = bufferqueuePopFront(&context->input);
    if (buffer == NULL)
    {
        return false;
    }
    /* Each buffer contains one datagram. The engine stages output without
     * dispatching tunnel callbacks during the call. */
    const size_t length = sbufGetLength(buffer);
    if (length > 0 && length <= WW_QUIC_MAX_DATAGRAM)
    {
        ww_quic_engine_feed(context->engine, sbufGetRawPtr(buffer), length);
    }
    bufferpoolReuseBuffer(context->pool, buffer);
    return true;
}

static bool quicAdmitApplication(quic_context_t *context, sbuf_t *buffer)
{
    quic_tstate_t    *state = tunnelGetState(context->tunnel);
    ww_quic_storage_t storage;
    ww_quic_engine_storage(context->engine, &storage);
    buffer_budget_cost_t used = bufferbudgetGetUsage(&context->application_budget);
    buffer_budget_cost_t cost;
    if (! bufferbudgetTryGetCost(buffer, &cost))
    {
        return false;
    }
    size_t marker  = state->client && storage.send_bytes == 0 && ! ww_quic_engine_ready(context->engine) ? 1 : 0;
    size_t entries = quicApplicationEntries(context);
    if (cost.bytes + used.bytes + storage.send_bytes + marker > state->max_bytes ||
        1 + entries + storage.send_entries + marker > state->max_buffers ||
        cost.charge + used.charge + storage.send_allocation > (size_t) state->max_bytes * 2)
    {
        return false;
    }
    return bufferqueueTryPushBack(&context->application, &buffer);
}

static void quicSubmit(tunnel_t *t, line_t *l, sbuf_t *buffer, quic_input_kind_t kind)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    const bool application = kind == kQuicInputApplication;
    assert(l == (application ? context->application_line : context->carrier_line));
    if (! context->attached)
    {
        bufferpoolReuseBuffer(context->pool, buffer);
        return;
    }
    bool           entered = quicEnter(context);
    quic_tstate_t *state   = tunnelGetState(t);
    bool           admitted;
    if (application)
    {
        admitted = quicAdmitApplication(context, buffer);
    }
    else
    {
        admitted = bufferqueueGetEntryCount(&context->input) < state->max_buffers &&
                   bufferqueueTryPushBack(&context->input, &buffer);
    }
    if (! admitted)
    {
        char              reason[256];
        size_t            charge;
        ww_quic_storage_t storage;
        ww_quic_engine_storage(context->engine, &storage);
        const unsigned marker =
            application && state->client && storage.send_bytes == 0 && ! ww_quic_engine_ready(context->engine) ? 1U
                                                                                                               : 0U;
        if (sbufTryGetQueueCharge(buffer, &charge))
            snprintf(reason,
                     sizeof(reason),
                     "%s backlog admission refused "
                     "(incoming_bytes=%zu, incoming_charge_bytes=%zu, incoming_entries=1, "
                     "opening_marker_bytes=%u, opening_marker_entries=%u)",
                     application ? "application" : "carrier",
                     sbufGetLength(buffer),
                     charge,
                     marker,
                     marker);
        else
            snprintf(reason,
                     sizeof(reason),
                     "%s input allocation charge is unrepresentable "
                     "(incoming_bytes=%zu)",
                     application ? "application" : "carrier",
                     sbufGetLength(buffer));
        bufferpoolReuseBuffer(context->pool, buffer);
        quicFail(context, reason);
    }
    else
    {
        ++context->input_generation;
        quicPressure(context);
        if (entered && quicSurvived(context))
        {
            quicPump(context);
        }
    }
    if (entered)
    {
        quicLeave(context);
    }
}

void quicSubmitApplication(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    quicSubmit(t, l, buffer, kQuicInputApplication);
}

void quicSubmitCarrier(tunnel_t *t, line_t *l, sbuf_t *buffer)
{
    quicSubmit(t, l, buffer, kQuicInputCarrier);
}

#include "runtime.h"

#include "loggers/network_logger.h"

typedef enum quic_input_kind
{
    kQuicInputApplication,
    kQuicInputCarrier
} quic_input_kind_t;

void quicReleaseActive(quic_context_t *context, bool application)
{
    sbuf_t                     **active = application ? &context->active_application : &context->active_input;
    buffer_budget_reservation_t *reservation =
        application ? &context->application_reservation : &context->input_reservation;
    if (*active != NULL)
    {
        bufferpoolReuseBuffer(context->pool, *active);
        *active = NULL;
        bufferbudgetReservationRelease(reservation);
    }
}

bool quicFeedInput(quic_context_t *context)
{
    if (context->active_input == NULL)
    {
        context->active_input = bufferqueuePopFrontReserved(&context->input, &context->input_reservation);
    }
    sbuf_t *buffer = context->active_input;
    if (buffer == NULL)
    {
        return false;
    }
    quic_tstate_t *state  = tunnelGetState(context->tunnel);
    size_t         length = sbufGetLength(buffer);
    if (! state->stream_carrier)
    {
        if (length > 0 && length <= WW_QUIC_MAX_DATAGRAM)
        {
            ww_quic_engine_feed(context->engine, sbufGetRawPtr(buffer), length);
        }
        /* Oversized/empty carrier datagrams are dropped without engine allocation. */
        quicReleaseActive(context, false);
        return true;
    }
    size_t                   consumed;
    const uint8_t           *packet;
    size_t                   packet_length;
    ww_quic_carrier_result_t result =
        ww_quic_carrier_decode(&context->carrier, sbufGetRawPtr(buffer), length, &consumed, &packet, &packet_length);
    if (result == WW_QUIC_CARRIER_PACKET)
    {
        ww_quic_engine_feed(context->engine, packet, packet_length);
        ww_quic_carrier_release_packet(&context->carrier);
    }
    if (result == WW_QUIC_CARRIER_INVALID || result == WW_QUIC_CARRIER_REFUSED)
    {
        char reason[192];
        snprintf(reason,
                 sizeof(reason),
                 "%s (declared_packet_bytes=%u, protocol_limit_bytes=%u)",
                 result == WW_QUIC_CARRIER_INVALID ? "invalid stream carrier length"
                                                   : "carrier storage admission refused",
                 context->carrier.body_length,
                 (unsigned) WW_QUIC_MAX_DATAGRAM);
        quicFail(context, reason);
        return true;
    }
    sbufShiftRight(buffer, consumed);
    bufferbudgetReservationSetBytes(&context->input_reservation, sbufGetLength(buffer));
    if (sbufGetLength(buffer) == 0)
    {
        quicReleaseActive(context, false);
    }
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
        size_t retained = ww_quic_carrier_retained(&context->carrier);
        size_t queued   = bufferbudgetGetUsage(&context->input_budget).bytes;
        admitted        = quicInputEntries(context) < state->max_buffers &&
                   retained + queued + sbufGetLength(buffer) <= state->max_bytes &&
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

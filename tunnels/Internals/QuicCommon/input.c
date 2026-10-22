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
        quicFail(context,
                 result == WW_QUIC_CARRIER_INVALID ? "invalid stream carrier length"
                                                   : "carrier storage budget exceeded");
        return true;
    }
    sbufShiftRight(buffer, (uint32_t) consumed);
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
    size_t marker = state->client && storage.send_bytes == 0 && ! ww_quic_engine_ready(context->engine) ? 1 : 0;
    if (cost.bytes + used.bytes + storage.send_bytes + marker > state->max_bytes ||
        cost.entries + used.entries + storage.send_entries + marker > state->max_buffers ||
        cost.charge + used.charge + storage.send_allocation > (size_t) state->max_bytes * 2)
    {
        LOGD("QUIC send admission refused: bytes=%zu+%zu+%zu entries=%zu+%zu+%zu charge=%zu+%zu+%zu limits=%u/%u",
             cost.bytes,
             used.bytes,
             storage.send_bytes,
             cost.entries,
             used.entries,
             storage.send_entries,
             cost.charge,
             used.charge,
             storage.send_allocation,
             state->max_bytes,
             state->max_buffers);
        return false;
    }
    return bufferqueueTryPushBack(&context->application, &buffer);
}

static void quicSubmit(tunnel_t *t, line_t *l, sbuf_t *buffer, quic_input_kind_t kind)
{
    quic_context_t *context = quicGetContext(t, l);
    assert(context != NULL);
    if (context->finish_up || context->finish_down)
    {
        bufferpoolReuseBuffer(context->pool, buffer);
        return;
    }
    bool           entered     = quicEnter(context);
    quic_tstate_t *state       = tunnelGetState(t);
    bool           application = kind == kQuicInputApplication;
    bool           admitted;
    if (application)
    {
        admitted = quicAdmitApplication(context, buffer);
    }
    else
    {
        size_t retained = ww_quic_carrier_retained(&context->carrier);
        size_t queued   = bufferbudgetGetUsage(&context->input_budget).bytes;
        admitted        = retained + queued + sbufGetLength(buffer) <= state->max_bytes &&
                   bufferqueueTryPushBack(&context->input, &buffer);
    }
    if (! admitted)
    {
        bufferpoolReuseBuffer(context->pool, buffer);
        quicFail(context, application ? "application backlog budget exceeded" : "carrier backlog budget exceeded");
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

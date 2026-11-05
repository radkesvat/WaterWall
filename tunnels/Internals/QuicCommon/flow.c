#include "runtime.h"

#include "loggers/network_logger.h"

void quicPressure(quic_context_t *context)
{
    if (context->application_line == NULL)
    {
        return;
    }
    quic_tstate_t    *state = tunnelGetState(context->tunnel);
    ww_quic_storage_t storage;
    ww_quic_engine_storage(context->engine, &storage);
    buffer_budget_cost_t queued       = bufferbudgetGetUsage(&context->application_budget);
    size_t               bytes        = queued.bytes + storage.send_bytes;
    size_t               entries      = quicApplicationEntries(context) + storage.send_entries;
    size_t               charge       = queued.charge + storage.send_allocation;
    size_t               charge_limit = (size_t) state->max_bytes * 2;
    /* A small socket read can retain a large pool allocation. Apply pressure
     * to every hard admission dimension before the next read can exhaust it. */
    bool pause =
        ! context->pressure && (bytes > (size_t) state->max_bytes * 3 / 4 ||
                                entries > (size_t) state->max_buffers * 3 / 4 || charge > charge_limit * 3 / 4);
    bool resume = context->pressure && bytes * 2 < state->max_bytes && entries * 2 < state->max_buffers &&
                  charge * 2 < charge_limit;
    if (! pause && ! resume)
    {
        return;
    }
    context->pressure = pause;
    if (context->carrier_paused)
    {
        /* The carrier's Pause already holds the application, and its Resume releases it. */
        return;
    }
    if (pause)
    {
        line_t *line = context->application_line;
        lineRef(line);
        state->output->application_pause(context->tunnel, line);
        lineUnref(line);
    }
    else
    {
        line_t *line = context->application_line;
        lineRef(line);
        state->output->application_resume(context->tunnel, line);
        lineUnref(line);
    }
}

static bool quicDeliverEvent(quic_context_t *context)
{
    ww_quic_event_t event;
    if (! ww_quic_engine_peek(context->engine, &event))
    {
        return false;
    }
    if (event.type == WW_QUIC_EVENT_CLOSED)
    {
        quicFail(context, ww_quic_engine_error(context->engine));
        return true;
    }
    if (event.type == WW_QUIC_EVENT_PEER_FIN)
    {
        ww_quic_engine_consume(context->engine);
        quicPeerFinish(context);
        return true;
    }
    if (event.type == WW_QUIC_EVENT_READY)
    {
        ww_quic_engine_consume(context->engine);
        quic_tstate_t *state = tunnelGetState(context->tunnel);
        if (state->verbose)
        {
            LOGD("%s: authenticated QUIC connection and application stream ready",
                 state->client ? "QuicClient" : "QuicServer");
        }
        return true;
    }
    quic_tstate_t *state = tunnelGetState(context->tunnel);
    bool           wire  = event.type == WW_QUIC_EVENT_DATAGRAM;
    line_t        *line  = wire ? context->carrier_line : context->application_line;
    if (line == NULL)
    {
        /* Output toward a side that already finished has no reader. */
        ww_quic_engine_consume(context->engine);
        return true;
    }
    uint32_t prefix = wire && state->stream_carrier ? 4 : 0;
    assert(event.length <= WW_QUIC_WRITE_CHUNK);
    /* Retire staging before allocating the onward buffer, so their heap
     * allocations never overlap at the output backlog's hard boundary. */
    uint8_t staged[WW_QUIC_WRITE_CHUNK];
    memoryCopy(staged, event.data, event.length);
    ww_quic_engine_consume(context->engine);
    ww_quic_storage_t storage;
    ww_quic_engine_storage(context->engine, &storage);
    size_t retained = (wire ? storage.wire_bytes : storage.plaintext_bytes) +
                      ((size_t) state->max_buffers + (wire ? 1 : 2)) * WW_QUIC_EVENT_DESCRIPTOR_CHARGE;
    uint32_t          length  = (uint32_t) event.length + prefix;
    uint16_t          padding = bufferpoolGetLargeBufferPadding(context->pool);
    buffer_pool_fit_t fit;
    if (! bufferpoolQueryBestFit(context->pool, length, padding, &fit) ||
        fit.allocation_charge + retained > (size_t) state->max_bytes * 2)
    {
        quicFail(context, "output allocation budget exceeded");
        return true;
    }
    sbuf_t *buffer = bufferpoolGetBestFit(context->pool, length, padding);
    if (length > sbufGetMaximumWriteableSize(buffer))
    {
        bufferpoolReuseBuffer(context->pool, buffer);
        quicFail(context, "output allocation budget exceeded");
        return true;
    }
    uint8_t *data = sbufGetMutablePtr(buffer);
    if (prefix != 0)
    {
        ww_quic_carrier_header(data, (uint32_t) event.length);
    }
    memoryCopy(data + prefix, staged, event.length);
    sbufSetLength(buffer, length);
    lineRef(line);
    if (wire)
    {
        state->output->wire_payload(context->tunnel, line, buffer);
    }
    else
    {
        state->output->application_payload(context->tunnel, line, buffer);
    }
    lineUnref(line);
    return true;
}

static bool quicWriteApplication(quic_context_t *context)
{
    if (! ww_quic_engine_ready(context->engine))
    {
        return false;
    }
    if (context->active_application == NULL)
    {
        context->active_application =
            bufferqueuePopFrontReserved(&context->application, &context->application_reservation);
    }
    sbuf_t *buffer = context->active_application;
    if (buffer == NULL)
    {
        return false;
    }
    size_t length = sbufGetLength(buffer);
    if (length == 0)
    {
        quicReleaseActive(context, true);
        return true;
    }
    uint32_t          chunk = (uint32_t) min(length, (size_t) WW_QUIC_WRITE_CHUNK);
    quic_tstate_t    *state = tunnelGetState(context->tunnel);
    ww_quic_storage_t storage;
    ww_quic_engine_storage(context->engine, &storage);
    buffer_budget_cost_t pending = bufferbudgetGetUsage(&context->application_budget);
    /* The original allocation remains charged until its suffix is consumed. */
    if (storage.send_entries + quicApplicationEntries(context) + (length > chunk ? 1 : 0) > state->max_buffers ||
        storage.send_allocation + pending.charge + chunk > (size_t) state->max_bytes * 2)
    {
        if (storage.send_entries == 0)
        {
            quicFail(context, "send ledger storage budget exceeded");
            return true;
        }
        return false;
    }
    if (! ww_quic_engine_write(context->engine, sbufGetRawPtr(buffer), chunk))
    {
        return ww_quic_engine_closed(context->engine);
    }
    sbufShiftRight(buffer, chunk);
    bufferbudgetReservationSetBytes(&context->application_reservation, sbufGetLength(buffer));
    if (sbufGetLength(buffer) == 0)
    {
        quicReleaseActive(context, true);
    }
    return true;
}

static bool quicDrainExpired(quic_context_t *context)
{
    if (context->final_flush && ! ww_quic_engine_closing(context->engine) &&
        ww_quic_now_us() >= context->final_deadline_us)
    {
        quicFail(context, "data/FIN delivery unconfirmed at close-drain deadline");
        return true;
    }
    return false;
}

void quicPump(quic_context_t *context)
{
    assert(context->driving && context->attached);
    if (quicDrainExpired(context))
        return;
    if (! context->started)
    {
        context->started = true;
        ww_quic_engine_start(context->engine);
    }
    ww_quic_engine_tick(context->engine);
    unsigned work = 0;
    for (; work < kQuicPumpWork && quicSurvived(context); ++work)
    {
        if (quicDrainExpired(context))
            break;
        if (quicDeliverEvent(context))
        {
            continue;
        }
        if (ww_quic_engine_closed(context->engine))
        {
            quicFail(context, ww_quic_engine_error(context->engine));
            break;
        }
        if (quicFeedInput(context))
        {
            continue;
        }
        if (quicWriteApplication(context))
        {
            continue;
        }
        break;
    }
    uint64_t generation = context->input_generation;
    if (quicSurvived(context))
    {
        quicPressure(context);
    }
    if (quicSurvived(context))
    {
        quicReconcileFinal(context);
    }
    if (quicSurvived(context))
    {
        quicArm(context, work == kQuicPumpWork || generation != context->input_generation);
    }
}

void quicReconcileFinal(quic_context_t *context)
{
    ww_quic_event_t pending;
    if (ww_quic_engine_closing(context->engine))
    {
        /* A connection-close packet can follow plaintext staged in the same
         * engine call. A fairness yield must not retire that reader early. */
        if (context->application_line != NULL && ! ww_quic_engine_peek(context->engine, &pending))
            quicPeerFinish(context);
        /* Protocol closing/draining has its own fixed, bounded deadline. */
        context->final_flush = false;
        return;
    }
    if (! context->final_flush)
        return;
    if (quicDrainExpired(context))
        return;
    if (! context->fin_sent && context->active_application == NULL &&
        bufferqueueGetBufCount(&context->application) == 0 && ww_quic_engine_ready(context->engine))
    {
        context->fin_sent = ww_quic_engine_finish(context->engine);
        if (context->fin_sent)
            ++context->input_generation; // Deliver newly staged FIN without waiting for an unrelated alarm.
    }
    if (context->fin_sent && ww_quic_engine_finish_acked(context->engine) &&
        ww_quic_engine_peer_finished(context->engine) && ! ww_quic_engine_peek(context->engine, &pending))
    {
        context->final_flush = false;
        ww_quic_engine_begin_close(context->engine);
        ++context->input_generation;
    }
}

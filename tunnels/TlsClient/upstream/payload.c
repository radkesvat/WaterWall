#include "structure.h"

#include "loggers/network_logger.h"

static bool tlsclientPlaintextStateIsActive(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    return ls->tunnel == t && ! ls->resources_released && ! ls->upstream_finished && ls->ssl != NULL;
}

static bool tlsclientQueuePlaintext(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls    = lineGetState(l, t);
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->bq, &buf)))
    {
        const buffer_budget_cost_t used            = bufferbudgetGetUsage(&ls->pending_budget);
        const buffer_budget_cost_t limits          = bufferbudgetGetLimits(&ls->pending_budget);
        const size_t               incoming_bytes  = sbufGetLength(buf);
        const size_t               incoming_charge = sbufGetQueueCharge(buf);
        LOGW("TlsClient: closing connection: pending plaintext %s "
             "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%zu, retained_charge_bytes=%zu, "
             "incoming_charge_bytes=%zu, limit_charge_bytes=%zu)",
             incoming_bytes > limits.bytes - used.bytes      ? "byte budget exceeded"
             : incoming_charge > limits.charge - used.charge ? "storage charge budget exceeded"
                                                             : "queue admission failed",
             used.bytes,
             incoming_bytes,
             limits.bytes,
             used.charge,
             incoming_charge,
             limits.charge);
        lineReuseBuffer(l, buf);
        tlsclientCloseLineBidirectional(t, l);
        return false;
    }
    ls->plaintext_producer_paused = true;
    return tlsclientUpdateSourcePressure(t, l);
}

/* Publish consumption before TLS output can call either neighbour. */
static bool tlsclientWritePlaintextChunk(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    sbuf_t *buf    = ls->pending_plaintext;
    int     length = (int) min(sbufGetLength(buf), (uint32_t) SSL3_RT_MAX_PLAIN_LENGTH);
    int     n      = SSL_write(ls->ssl, sbufGetRawPtr(buf), length);
    if (UNLIKELY(n <= 0))
    {
        LOGW("TlsClient: failed to encrypt application payload");
        return false;
    }
    sbufShiftRight(buf, n);
    bufferbudgetReservationSetBytes(&ls->pending_reservation, sbufGetLength(buf));
    return tlsclientFlushSslOutput(t, l, ls);
}

/* Finish takes over the published head from any suspended normal pump. The
 * normal pump must check the association after each handoff before using it. */
static bool tlsclientPumpPlaintext(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls, bool final)
{
    while (final || ! ls->shaping_producer_paused || ls->pending_reservation.budget == &ls->direct_budget)
    {
        if (ls->pending_plaintext == NULL)
        {
            ls->pending_plaintext = bufferqueuePopFrontReserved(&ls->bq, &ls->pending_reservation);
            if (ls->pending_plaintext == NULL)
            {
                break;
            }
        }
        if (sbufGetLength(ls->pending_plaintext) == 0)
        {
            lineReuseBuffer(l, ls->pending_plaintext);
            ls->pending_plaintext = NULL;
            bufferbudgetReservationRelease(&ls->pending_reservation);
            continue;
        }
        if (UNLIKELY(! tlsclientWritePlaintextChunk(t, l, ls) || ! lineIsAlive(l) || ls->tunnel != t ||
                     ls->resources_released || (! final && ls->upstream_finished)))
        {
            return false;
        }
    }
    return true;
}

bool tlsclientDrainFinalPlaintext(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->upstream_finished && ls->ssl != NULL);
    if (! ls->handshake_completed)
    {
        const tlsclient_tstate_t *ts = tunnelGetState(t);
        if (ts->handshake_takeover_enabled || ! SSL_is_init_finished(ls->ssl))
            return true;
    }

    /* Finish can reenter the last handshake write. Flush any remaining flight
     * bytes before enabling application record shaping. */
    if (! tlsclientFlushSslOutput(t, l, ls))
        return false;
    ls->handshake_completed = true;
    return tlsclientPumpPlaintext(t, l, ls, true);
}

bool tlsclientDrainPendingPlaintext(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (ls->plaintext_write_in_progress || ! ls->handshake_completed || ls->upstream_finished)
        return true;

    lineRef(l);
    ls->plaintext_write_in_progress = true;
    if (! tlsclientPumpPlaintext(t, l, ls, false))
    {
        if (lineIsAlive(l) && tlsclientPlaintextStateIsActive(t, l))
            tlsclientCloseLineBidirectional(t, l);
        lineUnref(l);
        return false;
    }

    ls->plaintext_write_in_progress = false;
    if (ls->pending_plaintext == NULL && bufferqueueGetEntryCount(&ls->bq) == 0)
    {
        ls->plaintext_producer_paused = false;
    }
    bool active = tlsclientUpdateSourcePressure(t, l);
    lineUnref(l);
    return active;
}

void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->upstream_finished))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->takeover_phase == kTlsClientTakeoverDrain || ls->takeover_phase == kTlsClientTakeoverPassthrough)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (! ls->handshake_completed || ls->plaintext_write_in_progress || ls->pending_plaintext != NULL ||
        bufferqueueGetEntryCount(&ls->bq) != 0)
    {
        if (LIKELY(tlsclientQueuePlaintext(t, l, buf)))
        {
            discard tlsclientDrainPendingPlaintext(t, l);
        }
        return;
    }

    /* Retain one direct input under its own accounting. Reentrant input still
     * enters the bounded FIFO and cannot overtake this head. */
    if (UNLIKELY(! bufferbudgetTryReserve(&ls->direct_budget, buf, &ls->pending_reservation)))
    {
        lineReuseBuffer(l, buf);
        tlsclientCloseLineBidirectional(t, l);
        return;
    }
    ls->pending_plaintext = buf;
    discard tlsclientDrainPendingPlaintext(t, l);
}

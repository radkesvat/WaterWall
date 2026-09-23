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
        lineReuseBuffer(l, buf);
        LOGW("TlsClient: pending plaintext limit or queue admission failure");
        tlsclientCloseLineBidirectional(t, l);
        return false;
    }
    ls->plaintext_producer_paused = true;
    return tlsclientUpdateSourcePressure(t, l);
}

/* Publish consumption before the wire callback. The caller either owns buf
 * locally or leaves it in pending_plaintext for close to reclaim. */
static bool tlsclientWritePlaintextChunk(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls     = lineGetState(l, t);
    int                 length = (int) min(sbufGetLength(buf), (uint32_t) SSL3_RT_MAX_PLAIN_LENGTH);
    int                 n      = SSL_write(ls->ssl, sbufGetRawPtr(buf), length);
    if (UNLIKELY(n <= 0 || getSslStatus(ls->ssl, n) == kSslstatusFail))
    {
        return false;
    }
    sbufShiftRight(buf, (uint32_t) n);
    if (buf == ls->pending_plaintext)
        bufferbudgetReservationSetBytes(&ls->pending_reservation, sbufGetLength(buf));
    return tlsclientFlushSslOutput(t, l, ls);
}

bool tlsclientDrainPendingPlaintext(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (ls->plaintext_write_in_progress || ! ls->handshake_completed)
    {
        return true;
    }

    lineRef(l);
    ls->plaintext_write_in_progress = true;
    while (! ls->shaping_wire_paused && ! ls->shaping_producer_paused)
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
        if (UNLIKELY(! tlsclientWritePlaintextChunk(t, l, ls->pending_plaintext)))
        {
            if (lineIsAlive(l) && tlsclientPlaintextStateIsActive(t, l))
            {
                tlsclientCloseLineBidirectional(t, l);
            }
            lineUnref(l);
            return false;
        }
        if (UNLIKELY(! lineIsAlive(l) || ! tlsclientPlaintextStateIsActive(t, l)))
        {
            lineUnref(l);
            return false;
        }
        ls = lineGetState(l, t);
    }
    ls->plaintext_write_in_progress = false;
    if (ls->pending_plaintext == NULL && bufferqueueGetBufCount(&ls->bq) == 0)
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
        bufferqueueGetBufCount(&ls->bq) != 0)
    {
        if (LIKELY(tlsclientQueuePlaintext(t, l, buf)))
        {
            discard tlsclientDrainPendingPlaintext(t, l);
        }
        return;
    }

    /* A direct admitted input may finish after Pause. Reentrant input joins
     * the FIFO so it cannot overtake the remaining bytes of this input. */
    lineRef(l);
    ls->plaintext_write_in_progress = true;
    while (sbufGetLength(buf) > 0)
    {
        if (UNLIKELY(! tlsclientWritePlaintextChunk(t, l, buf)))
        {
            lineReuseBuffer(l, buf);
            if (lineIsAlive(l) && tlsclientPlaintextStateIsActive(t, l))
            {
                LOGW("TlsClient: failed to encrypt application payload");
                tlsclientCloseLineBidirectional(t, l);
            }
            lineUnref(l);
            return;
        }
        if (UNLIKELY(! lineIsAlive(l) || ! tlsclientPlaintextStateIsActive(t, l)))
        {
            lineReuseBuffer(l, buf);
            lineUnref(l);
            return;
        }
        ls = lineGetState(l, t);
    }
    lineReuseBuffer(l, buf);
    ls->plaintext_write_in_progress = false;
    discard tlsclientDrainPendingPlaintext(t, l);
    lineUnref(l);
}

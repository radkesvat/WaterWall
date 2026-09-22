#include "structure.h"

/* Prev -> next: writable established TCP transfers buf directly. Otherwise
 * pending_up owns it on the direct/application line. In common/flow.c,
 * forwardQueuedUpstream() drains that FIFO after establishment, wrapping UDP
 * once before sending it on the carrier. Reentrant input joins the same FIFO. */
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpCarrier))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (UNLIKELY(ls->kind == kTrojanClientLineKindUdpApp && sbufGetLength(buf) > kTrojanClientUdpMaxPacket))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    line_t *next_line = ls->kind == kTrojanClientLineKindUdpApp ? ls->carrier_line : l;
    assert(next_line != NULL);
    buffer_queue_t *queue = &ls->pending_up;
    /* Established TCP is opaque, including allocation identity. The same pump
     * barrier orders any nested input behind this transferred buffer. */
    if (ls->kind == kTrojanClientLineKindDirect && ls->phase == kTrojanClientPhaseEstablished && ! ls->pumping &&
        ! ls->next_paused && bufferqueueGetBufCount(queue) == 0)
    {
        lineRef(l);
        ls->pumping = true;
        tunnelNextUpStreamPayload(t, l, buf);
        if (LIKELY(lineIsAlive(l) && ls->phase != kTrojanClientPhaseClosed))
        {
            ls->pumping = false;
            trojanclientPump(t, l);
        }
        lineUnref(l);
        return;
    }
    size_t   retained = bufferqueueGetBufLen(queue);
    size_t   limit    = kTrojanClientMaxPendingBytes;
    uint32_t length   = sbufGetLength(buf);
    if (UNLIKELY(length > limit - retained || bufferqueueGetBufCount(queue) >= kTrojanClientMaxQueuedBuffers ||
                 ! bufferqueueTryPushBack(queue, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return;
    }
    trojanclientPump(t, next_line);
}

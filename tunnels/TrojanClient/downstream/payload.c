#include "structure.h"

/* Next -> prev: writable established TCP transfers buf directly. Otherwise
 * pending_down owns opaque TCP bytes on this line or framed UDP bytes on the carrier.
 * In common/flow.c, forwardQueuedDownstream() drains TCP or uses common/input.c
 * to extract one UDP datagram at a time and deliver it on the application line. */
void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpApp))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    buffer_queue_t *queue       = &ls->pending_down;
    bool            udp_receive = ls->kind == kTrojanClientLineKindUdpCarrier;
    if (udp_receive && sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    /* Established TCP is opaque, including allocation identity. The same pump
     * barrier orders any nested input behind this transferred buffer. */
    if (ls->kind == kTrojanClientLineKindDirect && ls->phase == kTrojanClientPhaseEstablished && ! ls->pumping &&
        ! ls->prev_paused && bufferqueueGetBufCount(queue) == 0)
    {
        lineRef(l);
        ls->pumping = true;
        tunnelPrevDownStreamPayload(t, l, buf);
        if (LIKELY(lineIsAlive(l) && ls->phase != kTrojanClientPhaseClosed))
        {
            ls->pumping = false;
            trojanclientPump(t, l);
        }
        lineUnref(l);
        return;
    }
    size_t   retained = udp_receive ? ls->receive_bytes : bufferqueueGetBufLen(queue);
    size_t   limit    = udp_receive ? kTrojanClientMaxUdpBufferedBytes : kTrojanClientMaxBufferedBytes;
    uint32_t length   = sbufGetLength(buf);
    if (UNLIKELY(length > limit - retained ||
                 (! udp_receive && bufferqueueGetBufCount(queue) >= kTrojanClientMaxQueuedBuffers) ||
                 ! bufferqueueTryPushBack(queue, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return;
    }
    if (udp_receive)
        ls->receive_bytes += length;
    trojanclientPump(t, l);
}

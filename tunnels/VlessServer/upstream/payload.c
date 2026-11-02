#include "internal.h"

void vlessserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessServerPhaseClosing || ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->phase == kVlessServerPhaseFallback)
    {
        discard vlessserverSendFallbackPayload(t, l, ls, buf);
        return;
    }
    bool tcp = ls->phase == kVlessServerPhaseTcpConnecting || ls->phase == kVlessServerPhaseTcpEstablished;
    if (tcp && ! ls->input_dispatching)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
    bool first             = ! ls->first_payload_seen;
    bool short_uuid        = first && sbufGetLength(buf) < 17;
    ls->first_payload_seen = true;
    /* Empty parser input owns no bytes, but an empty first callback still
     * selects fallback. Output/reentry queues account even empty entries. */
    if (! tcp && sbufGetLength(buf) == 0)
        lineReuseBuffer(l, buf);
    else
    {
        bool admitted = tcp ? bufferqueueTryPushBack(&ls->pending_up, &buf)
                            : bufferreaderTryPush(&ls->reader, &buf, kVlessServerMaxBufferedBytes);
        if (! admitted)
            goto refused;
    }
    if (ls->input_dispatching)
    {
        if ((ls->phase == kVlessServerPhaseUdpConnecting || ls->phase == kVlessServerPhaseUdpEstablished) &&
            ! bufferreaderSettle(&ls->reader, kVlessServerMaxInputCharge, kVlessServerMaxInputBuffers))
            vlessserverCloseLineBidirectional(t, l);
        return;
    }
    lineRef(l);
    ls->input_dispatching = true;
    bool ok               = vlessserverDrainInput(t, l, ls, short_uuid);
    if (ok && lineIsAlive(l))
    {
        ls = lineGetState(l, t);
        if (ls->tunnel == t && ls->phase != kVlessServerPhaseClosing)
        {
            ls->input_dispatching = false;
            vlessserverTryBypassTcp(t, l);
        }
    }
    lineUnref(l);
    return;
refused:
    lineReuseBuffer(l, buf);
    vlessserverCloseLineBidirectional(t, l);
}

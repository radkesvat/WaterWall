#include "structure.h"

#include "loggers/network_logger.h"

void vlessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;

        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            lineReuseBuffer(l, buf);
            vlessserverCloseLineBidirectional(t, l);
            return;
        }

        if (UNLIKELY(! vlessserverWrapUdpPayload(l, &buf)))
        {
            lineReuseBuffer(l, buf);
            return;
        }

        lineRef(l);
        discard vlessserverForwardResponse(t, client_l, buf);
        lineUnref(l);
        return;
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kVlessServerPhaseFallback)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    discard vlessserverForwardResponse(t, l, buf);
}

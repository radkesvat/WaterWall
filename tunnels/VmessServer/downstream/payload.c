#include "internal.h"

#include "loggers/network_logger.h"

void vmessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;

        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            lineReuseBuffer(l, buf);
            vmessserverCloseLineBidirectional(t, l);
            return;
        }

        lineRef(l);
        discard vmessserverForwardResponse(t, client_l, buf);
        lineUnref(l);
        return;
    }

    if (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kVmessServerPhaseFallback)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    discard vmessserverForwardResponse(t, l, buf);
}

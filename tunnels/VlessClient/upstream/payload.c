#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpApp)
    {
        discard vlessclientForwardUdpAppPayload(t, l, ls, buf);
        return;
    }

    if (UNLIKELY(ls->kind == kVlessClientLineKindUdpCarrier))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kVlessClientPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferqueuePushBack(&ls->pending_up, buf);

    if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_up) > kVlessClientMaxPendingBytes))
    {
        LOGE("VlessClient: upstream queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(&ls->pending_up),
             (unsigned int) kVlessClientMaxPendingBytes);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
    }
}

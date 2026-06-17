#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpApp)
    {
        discard trojanclientForwardUdpAppPayload(t, l, ls, buf);
        return;
    }

    if (UNLIKELY(ls->kind == kTrojanClientLineKindUdpCarrier))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kTrojanClientPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferqueuePushBack(&ls->pending_up, buf);

    if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_up) > kTrojanClientMaxPendingBytes))
    {
        LOGE("TrojanClient: upstream queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(&ls->pending_up),
             (unsigned int) kTrojanClientMaxPendingBytes);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
    }
}

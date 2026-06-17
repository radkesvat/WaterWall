#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpCarrier)
    {
        discard trojanclientHandleUdpCarrierPayload(t, l, ls, buf);
        return;
    }

    if (UNLIKELY(ls->kind == kTrojanClientLineKindUdpApp))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kTrojanClientPhaseEstablished)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) > kTrojanClientMaxBufferedBytes))
    {
        LOGE("TrojanClient: downstream buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kTrojanClientMaxBufferedBytes);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
    }
}

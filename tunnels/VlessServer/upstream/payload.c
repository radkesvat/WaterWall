#include "structure.h"

#include "loggers/network_logger.h"

void vlessserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(ls->phase == kVlessServerPhaseFallback))
    {
        tunnel_t *fallback = ((vlessserver_tstate_t *) tunnelGetState(t))->fallback_tunnel;
        if (UNLIKELY(fallback == NULL))
        {
            lineReuseBuffer(l, buf);
            vlessserverCloseLineBidirectional(t, l);
            return;
        }
        tunnelUpStreamPayload(fallback, l, buf);
        return;
    }

    if (ls->phase == kVlessServerPhaseTcpConnecting || ls->phase == kVlessServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bool reject_short_password =
        ls->phase == kVlessServerPhaseWaitInitial && bufferstreamIsEmpty(&ls->in_stream);

    bufferstreamPush(&ls->in_stream, buf);

    if (UNLIKELY((ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
                  ls->phase == kVlessServerPhaseUdpEstablished) &&
                 bufferstreamGetBufLen(&ls->in_stream) > kVlessServerMaxBufferedBytes))
    {
        LOGE("VlessServer: UDP input buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kVlessServerMaxBufferedBytes);
        vlessserverCloseLineBidirectional(t, l);
        return;
    }

    discard vlessserverDrainInput(t, l, ls, reject_short_password);
}

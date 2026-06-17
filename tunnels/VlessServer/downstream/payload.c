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

        if (ls->phase == kVlessServerPhaseUdpConnecting)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_down) > kVlessServerMaxPendingBytes))
            {
                LOGE("VlessServer: UDP downstream queue overflow, size=%zu limit=%u",
                     bufferqueueGetBufLen(&ls->pending_down),
                     (unsigned int) kVlessServerMaxPendingBytes);
                vlessserverCloseLineBidirectional(t, l);
            }
            return;
        }

        if (UNLIKELY(! withLineLockedWithBuf(client_l, tunnelPrevDownStreamPayload, t, buf)))
        {
            return;
        }
        return;
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kVlessServerPhaseTcpConnecting)
    {
        bufferqueuePushBack(&ls->pending_down, buf);
        if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_down) > kVlessServerMaxPendingBytes))
        {
            LOGE("VlessServer: TCP downstream queue overflow, size=%zu limit=%u",
                 bufferqueueGetBufLen(&ls->pending_down),
                 (unsigned int) kVlessServerMaxPendingBytes);
            vlessserverCloseLineBidirectional(t, l);
        }
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

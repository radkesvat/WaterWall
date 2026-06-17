#include "structure.h"

void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;

        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }

        if (UNLIKELY(! trojanserverWrapUdpPayload(l, &buf)))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }

        if (ls->phase == kTrojanServerPhaseUdpConnecting)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_down) > kTrojanServerMaxPendingBytes))
            {
                trojanserverCloseLineBidirectional(t, l);
            }
            return;
        }

        if (UNLIKELY(! withLineLockedWithBuf(client_l, tunnelPrevDownStreamPayload, t, buf)))
        {
            return;
        }
        return;
    }

    if (ls->branch == kTrojanServerBranchTrojan &&
        (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpConnecting ||
         ls->phase == kTrojanServerPhaseUdpEstablished))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kTrojanServerPhaseTcpConnecting || ls->phase == kTrojanServerPhaseUdpConnecting)
    {
        bufferqueuePushBack(&ls->pending_down, buf);
        if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_down) > kTrojanServerMaxPendingBytes))
        {
            trojanserverCloseLineBidirectional(t, l);
        }
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

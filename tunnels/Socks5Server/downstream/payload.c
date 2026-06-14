#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        if (ls->phase == kSocks5ServerPhaseTcpEstablished)
        {
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }

        if (ls->phase == kSocks5ServerPhaseConnectWaitEst)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            if (bufferqueueGetBufLen(&ls->pending_down) > kSocks5ServerMaxPendingBytes)
            {
                socks5serverCloseControlLineBidirectional(t, l);
            }
            return;
        }

        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;

        if (client_l == NULL || ! lineIsAlive(client_l))
        {
            lineReuseBuffer(l, buf);
            socks5serverCloseUdpRemoteLine(t, l);
            return;
        }

        if (! socks5serverLookupUdpAssociation(client_l, &ls->user_handle, &ls->association_key))
        {
            lineReuseBuffer(l, buf);
            socks5serverCloseUdpRemoteLine(t, l);
            return;
        }

        if (! socks5serverWrapUdpPayloadForClient(l, &buf, lineGetDestinationAddressContext(l)))
        {
            lineReuseBuffer(l, buf);
            socks5serverCloseUdpRemoteLine(t, l);
            return;
        }

        if (! withLineLockedWithBuf(client_l, tunnelPrevDownStreamPayload, t, buf))
        {
            socks5serverCloseUdpRemoteLine(t, l);
        }
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

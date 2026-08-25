#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Payload");
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
        bool    client_alive;

        if (client_l == NULL || ! ls->client_line_ref_held || ! lineIsAlive(client_l))
        {
            lineReuseBuffer(l, buf);
            socks5serverCloseUdpRemoteLine(t, l);
            return;
        }

        socks5server_lstate_t *client_ls = lineGetState(client_l, t);
        if (client_ls->kind != kSocks5ServerLineKindUdpClient ||
            ! udplistenerDynamicEndpointHandleEquals(client_ls->dynamic_handle, ls->dynamic_handle) ||
            ! socks5serverAssociationIsActive(t,
                                              lineGetWID(client_l),
                                              client_ls->dynamic_handle,
                                              lineGetRoutingContext(client_l)->local_listener_port,
                                              NULL))
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

        /* The client callback can synchronously finish client_l. Its nested
         * Socks5Server close drains every registered UDP remote, including
         * this exact line. Keep the remote allocation present until the
         * outer frame can observe whether that owner path already closed it. */
        lineRef(l);
        client_alive = lineCallWithRefWithBuf(client_l, tunnelPrevDownStreamPayload, t, buf);

        if (! lineIsAlive(l))
        {
            lineUnref(l);
            return;
        }

        if (! client_alive)
        {
            socks5serverCloseUdpRemoteLine(t, l);
        }
        lineUnref(l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindUdpClient)
    {
        /* A dynamic client line never initializes its next side; fail closed. */
        lineReuseBuffer(l, buf);
        socks5serverRejectUdpClientLine(t, l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindRejected)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

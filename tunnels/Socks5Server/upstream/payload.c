#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5server_lstate_t *ls = lineGetState(l, t);

    switch (ls->kind)
    {
    case kSocks5ServerLineKindControlTcp:
        if (ls->phase == kSocks5ServerPhaseTcpEstablished)
        {
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        if (ls->phase == kSocks5ServerPhaseConnectWaitEst)
        {
            bufferqueuePushBack(&ls->pending_up, buf);
            if (bufferqueueGetBufLen(&ls->pending_up) > kSocks5ServerMaxPendingBytes)
            {
                socks5serverCloseControlLineBidirectional(t, l);
            }
            return;
        }

        if (ls->phase == kSocks5ServerPhaseUdpControl)
        {
            lineReuseBuffer(l, buf);
            return;
        }

        bufferstreamPush(&ls->in_stream, buf);
        if (bufferstreamGetBufLen(&ls->in_stream) > kSocks5ServerMaxHandshakeBytes)
        {
            socks5serverCloseControlLineBidirectional(t, l);
            return;
        }

        socks5serverControlDrainInput(t, l, ls);
        return;

    case kSocks5ServerLineKindUdpClient:
        socks5serverHandleUdpClientPayload(t, l, ls, buf);
        return;

    case kSocks5ServerLineKindUdpRemote:
        //In the current intended flow, that branch should not normally be hit.
        LOGE("Socks5Server: kSocks5ServerLineKindUdpRemote is not expected to receive upstream payload; dropping");
        lineReuseBuffer(l, buf);
        return;

    case kSocks5ServerLineKindNone:
    default:
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
}

#include "internal.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Payload");
    socks5server_lstate_t *ls = lineGetState(l, t);

    switch (ls->kind)
    {
    case kSocks5ServerLineKindControlTcp:
        if (sbufGetLength(buf) == 0 || ls->phase == kSocks5ServerPhaseClosing ||
            ls->phase == kSocks5ServerPhaseUdpControl)
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (ls->input_draining)
        {
            discard socks5serverQueueControl(t, l, buf, true);
            return;
        }
        if ((ls->phase == kSocks5ServerPhaseTcpEstablished || ls->phase == kSocks5ServerPhaseConnectWaitEst) &&
            ! ls->next_initializing && ! ls->control_draining && bufferqueueGetBufCount(&ls->pending_up) == 0 &&
            bufferstreamIsEmpty(&ls->in_stream))
        {
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }
        if (ls->phase == kSocks5ServerPhaseConnectWaitEst || ls->phase == kSocks5ServerPhaseTcpEstablished)
        {
            if (socks5serverQueueControl(t, l, buf, true))
                discard socks5serverDrainControl(t, l);
            return;
        }
        bufferstreamPush(&ls->in_stream, buf);
        discard socks5serverControlDrainInput(t, l, ls);
        return;

    case kSocks5ServerLineKindUdpClient:
        socks5serverHandleUdpClientPayload(t, l, ls, buf);
        return;

    case kSocks5ServerLineKindUdpRemote:
        LOGE("Socks5Server: kSocks5ServerLineKindUdpRemote is not expected to receive upstream payload; dropping");
        lineReuseBuffer(l, buf);
        return;

    case kSocks5ServerLineKindRejected:
        lineReuseBuffer(l, buf);
        return;

    case kSocks5ServerLineKindNone:
    default:
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
}

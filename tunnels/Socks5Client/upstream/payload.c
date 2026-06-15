#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        discard socks5clientForwardUdpAppPayload(t, l, ls, buf);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kSocks5ClientPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferqueuePushBack(&ls->pending_up, buf);

    if (bufferqueueGetBufLen(&ls->pending_up) > kSocks5ClientMaxPendingUpBytes)
    {
        LOGE("Socks5Client: upstream handshake queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(&ls->pending_up),
             (unsigned int) kSocks5ClientMaxPendingUpBytes);
        socks5clientCloseLineBidirectional(t, l);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApplication)
    {
        discard socks5clientForwardUdpApplicationPayload(t, l, ls, buf);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kSocks5ClientPhaseEstablished && ! ls->draining_up && bufferqueueGetBufCount(&ls->pending_up) == 0)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (UNLIKELY(sbufGetLength(buf) == 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (LIKELY(socks5clientQueuePayload(t, l, buf)))
        discard socks5clientDrainPending(t, l);
}

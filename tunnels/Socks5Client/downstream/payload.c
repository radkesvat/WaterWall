#include "internal.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        discard socks5clientHandleUdpRelayPayload(t, l, ls, buf);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpApplication)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (sbufGetLength(buf) == 0 ||
        (ls->kind == kSocks5ClientLineKindUdpControl && ls->phase == kSocks5ClientPhaseEstablished))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->input_draining || bufferqueueGetBufCount(&ls->pending_down) != 0)
    {
        if (socks5clientQueueReplyInput(t, l, buf) && ! ls->input_draining)
            discard socks5clientDrainHandshakeInput(t, l, ls);
        return;
    }
    if (ls->phase == kSocks5ClientPhaseEstablished)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);
    discard socks5clientDrainHandshakeInput(t, l, ls);
}

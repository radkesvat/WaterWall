#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kSocks5ClientPhaseEstablished)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (bufferstreamGetBufLen(&ls->in_stream) > kSocks5ClientMaxHandshakeBytes)
    {
        LOGE("Socks5Client: proxy handshake buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kSocks5ClientMaxHandshakeBytes);
        socks5clientCloseLineBidirectional(t, l);
        return;
    }

    if (! socks5clientDrainHandshakeInput(t, l, ls))
    {
        return;
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientOnUdpRelayEstablished(t, l, ls);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        return;
    }

    if (ls->phase != kSocks5ClientPhaseIdle)
    {
        LOGW("Socks5Client: duplicate downstream establish while phase=%d", ls->phase);
        return;
    }

    if (! socks5clientSendGreeting(t, l, ls))
    {
        return;
    }
}

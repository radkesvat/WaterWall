#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApp || ls->kind == kSocks5ClientLineKindUdpControl ||
        ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}

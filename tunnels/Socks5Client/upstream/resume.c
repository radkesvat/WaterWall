#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        line_t *udp_l = ls->udp_line;
        if (udp_l != NULL && lineIsAlive(udp_l))
        {
            discard withLineLocked(udp_l, tunnelNextUpStreamResume, t);
        }
        return;
    }

    tunnelNextUpStreamResume(t, l);
}

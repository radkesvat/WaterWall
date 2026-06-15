#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        line_t *app_l = ls->app_line;
        if (app_l != NULL && lineIsAlive(app_l))
        {
            discard withLineLocked(app_l, tunnelPrevDownStreamPause, t);
        }
        return;
    }

    tunnelPrevDownStreamPause(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        line_t *app_l = ls->app_line;
        socks5clientLinestateDestroy(ls);
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }

        if (app_l != NULL && lineIsAlive(app_l))
        {
            socks5client_lstate_t *app_ls = lineGetState(app_l, t);
            socks5clientLinestateDestroy(app_ls);
            tunnelPrevDownStreamFinish(t, app_l);
        }
        return;
    }

    socks5clientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        line_t *control_l = ls->control_line;
        line_t *udp_l     = ls->udp_line;

        ls->control_line = NULL;
        ls->udp_line     = NULL;

        socks5clientCloseOwnedLine(t, udp_l);
        socks5clientCloseOwnedLine(t, control_l);
        socks5clientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        line_t *app_l     = ls->app_line;
        line_t *control_l = NULL;
        line_t *udp_l     = NULL;

        if (app_l != NULL && lineIsAlive(app_l))
        {
            socks5client_lstate_t *app_ls = lineGetState(app_l, t);

            control_l = app_ls->control_line;
            udp_l     = app_ls->udp_line;
            if (control_l == l)
            {
                control_l = NULL;
            }
            if (udp_l == l)
            {
                udp_l = NULL;
            }

            app_ls->control_line = NULL;
            app_ls->udp_line     = NULL;
        }

        socks5clientLinestateDestroy(ls);
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }

        socks5clientCloseOwnedLine(t, udp_l);
        socks5clientCloseOwnedLine(t, control_l);

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

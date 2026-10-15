#include "internal.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApplication)
    {
        line_t *control_l = ls->control_line;
        line_t *udp_l     = ls->udp_line;

        ls->control_line = NULL;
        ls->udp_line     = NULL;

        socks5clientCloseOwnedLine(t, udp_l);
        socks5clientCloseOwnedLine(t, control_l);
        socks5clientLinestateDestroy(ls);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientCloseOwnedLine(t, l);
        return;
    }

    socks5clientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

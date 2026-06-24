#include "structure.h"

#include "loggers/network_logger.h"

static void finishOwnedLine(tunnel_t *t, line_t *l)
{
    if (l == NULL || ! lineIsAlive(l))
    {
        return;
    }

    socks5clientLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
}

void socks5clientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        line_t *control_l = ls->control_line;
        line_t *udp_l     = ls->udp_line;

        ls->control_line = NULL;
        ls->udp_line     = NULL;

        finishOwnedLine(t, udp_l);
        finishOwnedLine(t, control_l);
        socks5clientLinestateDestroy(ls);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        finishOwnedLine(t, l);
        return;
    }

    socks5clientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

void socks5clientDomainSetupTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_domain_setup_lstate_t *ls = lineGetState(l, t);

    socks5clientDomainSetupLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

void socks5clientDomainSetupTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    socks5client_domain_setup_lstate_t *ls = lineGetState(l, t);

    socks5clientDomainSetupLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

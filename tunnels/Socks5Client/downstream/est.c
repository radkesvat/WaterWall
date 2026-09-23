#include "structure.h"

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientOnUdpRelayEstablished(t, l, ls);
        return;
    }
    if (ls->kind == kSocks5ClientLineKindUdpApp || ls->transport_est_forwarded)
        return;

    line_t *app                 = ls->kind == kSocks5ClientLineKindUdpControl ? ls->app_line : l;
    ls->transport_est_forwarded = true;
    ls->greeting_due            = true;
    lineRef(l);
    if (app != l)
        lineRef(app);
    socks5client_lstate_t *app_ls   = lineGetState(app, t);
    app_ls->transport_est_forwarded = true;
    tunnelPrevDownStreamEst(t, app);
    if (lineIsAlive(l) && lineIsAlive(app))
        discard socks5clientMaybeSendGreeting(t, l);
    if (app != l)
        lineUnref(app);
    lineUnref(l);
}

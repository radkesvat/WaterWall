#include "structure.h"

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientOnUdpRelayEstablished(t, l, ls);
        return;
    }
    if (ls->kind == kSocks5ClientLineKindUdpApplication || ls->transport_est_forwarded)
        return;

    line_t *application         = ls->kind == kSocks5ClientLineKindUdpControl ? ls->application_line : l;
    ls->transport_est_forwarded = true;
    ls->greeting_due            = true;
    lineRef(l);
    if (application != l)
        lineRef(application);
    socks5client_lstate_t *application_ls   = lineGetState(application, t);
    application_ls->transport_est_forwarded = true;
    tunnelPrevDownStreamEst(t, application);
    if (lineIsAlive(l) && lineIsAlive(application))
        discard socks5clientMaybeSendGreeting(t, l);
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}

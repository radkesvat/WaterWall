#include "internal.h"

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientOnUdpRelayEstablished(t, l, ls);
        return;
    }
    if (ls->kind == kSocks5ClientLineKindUdpApplication)
        return;
    if (ls->transport_est_forwarded)
    {
        if (ls->kind == kSocks5ClientLineKindDirect)
            tunnelPrevDownStreamEst(t, l);
        return;
    }

    line_t *application         = ls->kind == kSocks5ClientLineKindUdpControl ? ls->application_line : l;
    ls->transport_est_forwarded = true;
    ls->greeting_due            = true;
    lineRef(l);
    if (application != l)
        lineRef(application);
    tunnelPrevDownStreamEst(t, application);
    if (lineIsAlive(l) && lineIsAlive(application) && tunnelIsActiveForLine(t, l) && socks5clientHasLineState(t, l) &&
        socks5clientHasLineState(t, application))
        discard socks5clientMaybeSendGreeting(t, l);
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}

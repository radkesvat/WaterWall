#include "internal.h"

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ClientLineKindDirect)
    {
        tunnelPrevDownStreamEst(t, l);
    }
    else if (ls->kind == kSocks5ClientLineKindUdpControl && ! ls->control_est_forwarded)
    {
        ls->control_est_forwarded = true;
        tunnelPrevDownStreamEst(t, ls->application_line);
    }
    else if (ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        socks5clientOnUdpRelayEstablished(t, l, ls);
    }
}

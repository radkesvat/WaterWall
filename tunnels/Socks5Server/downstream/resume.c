#include "internal.h"

void socks5serverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Resume");
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        if (ls->phase != kSocks5ServerPhaseConnectWaitEst && ls->phase != kSocks5ServerPhaseTcpEstablished)
            return;
        tunnelPrevDownStreamResume(t, l);
        return;
    }
    if (ls->kind == kSocks5ServerLineKindNone)
        tunnelPrevDownStreamResume(t, l);
}

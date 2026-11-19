#include "internal.h"

void socks5serverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Est");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindNone ||
        (ls->kind == kSocks5ServerLineKindControlTcp &&
         (ls->phase == kSocks5ServerPhaseConnectStarting || ls->phase == kSocks5ServerPhaseTcpEstablished)))
    {
        tunnelPrevDownStreamEst(t, l);
    }
}

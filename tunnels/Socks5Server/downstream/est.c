#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Est");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindControlTcp && ls->phase == kSocks5ServerPhaseConnectWaitEst)
    {
        socks5serverOnControlEstablished(t, l, ls);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindNone)
    {
        tunnelPrevDownStreamEst(t, l);
    }
}

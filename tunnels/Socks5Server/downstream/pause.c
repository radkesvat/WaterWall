#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Pause");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindControlTcp && ls->phase == kSocks5ServerPhaseTcpEstablished)
    {
        tunnelPrevDownStreamPause(t, l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindNone)
    {
        tunnelPrevDownStreamPause(t, l);
    }
}

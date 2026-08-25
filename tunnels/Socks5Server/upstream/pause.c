#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Pause");
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindControlTcp && ls->phase == kSocks5ServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindNone)
    {
        tunnelNextUpStreamPause(t, l);
    }
}

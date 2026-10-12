#include "internal.h"

void socks5serverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Pause");
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        if (! ls->next_initialized)
        {
            ls->pending_read_pause = true;
            return;
        }
        if (ls->phase != kSocks5ServerPhaseConnectWaitEst && ls->phase != kSocks5ServerPhaseTcpEstablished)
            return;
        ls->pending_read_pause = false;
        tunnelNextUpStreamPause(t, l);
        return;
    }
    if (ls->kind == kSocks5ServerLineKindNone)
        tunnelNextUpStreamPause(t, l);
}

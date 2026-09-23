#include "structure.h"

void socks5serverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Pause");
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        ls->prev_paused = true;
        if (ls->phase != kSocks5ServerPhaseConnectWaitEst && ls->phase != kSocks5ServerPhaseTcpEstablished)
            return;
        if (ls->next_read_paused != true)
        {
            ls->next_read_paused = true;
            tunnelNextUpStreamPause(t, l);
        }
        return;
    }
    if (ls->kind == kSocks5ServerLineKindNone)
        if (ls->next_read_paused != true)
        {
            ls->next_read_paused = true;
            tunnelNextUpStreamPause(t, l);
        }
}

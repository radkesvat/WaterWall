#include "structure.h"

void socks5serverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Resume");
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        ls->prev_paused = false;
        if (ls->phase != kSocks5ServerPhaseConnectWaitEst && ls->phase != kSocks5ServerPhaseTcpEstablished)
            return;
        if (UNLIKELY(! socks5serverDrainControl(t, l)))
            return;
        if (ls->prev_paused)
            return;
        if (ls->next_read_paused != false)
        {
            ls->next_read_paused = false;
            tunnelNextUpStreamResume(t, l);
        }
        return;
    }
    if (ls->kind == kSocks5ServerLineKindNone)
        if (ls->next_read_paused != false)
        {
            ls->next_read_paused = false;
            tunnelNextUpStreamResume(t, l);
        }
}

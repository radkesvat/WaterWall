#include "internal.h"

void socks5serverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Resume");
    socks5server_lstate_t *ls = lineGetState(l, t);
    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        ls->pending_read_pause = false;
        if (ls->phase != kSocks5ServerPhaseConnectWaitEst && ls->phase != kSocks5ServerPhaseTcpEstablished)
            return;
        tunnelNextUpStreamResume(t, l);
        return;
    }
    if (ls->kind == kSocks5ServerLineKindNone)
        tunnelNextUpStreamResume(t, l);
}

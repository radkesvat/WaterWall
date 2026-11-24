#include "WireGuardServer/structure.h"

void wireguardserverTunnelUpStreamPause(tunnel_t *t, line_t *line)
{
    server_line_t *ls = lineGetState(line, t);
    if (ls->ingress != NULL)
    {
        mutexLock(&ls->ingress->lock);
        ls->ingress->paused = true;
        mutexUnlock(&ls->ingress->lock);
    }
}

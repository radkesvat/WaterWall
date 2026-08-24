#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}

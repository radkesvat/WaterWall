#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining)
    {
        return;
    }

    if (ls->fallback_mode)
    {
        ls->fallback_payload_paused = true;
    }

    tunnelPrevDownStreamPause(t, l);
}

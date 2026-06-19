#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        if (fallback != NULL && ! ls->fallback_up_finished)
        {
            tunnelUpStreamEst(fallback, l);
        }
        return;
    }

    if (ls->protected_init_sent && ! ls->upstream_finished)
    {
        tunnelNextUpStreamEst(t, l);
    }
}

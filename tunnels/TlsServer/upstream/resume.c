#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        if (fallback != NULL && ! ls->fallback_up_finished)
        {
            tunnelUpStreamResume(fallback, l);
        }
        return;
    }

    if (! ls->protected_init_sent)
    {
        return;
    }

    if (ls->upstream_finished)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Resume because upstream side is already finished");
        }
        return;
    }

    tunnelNextUpStreamResume(t, l);
}

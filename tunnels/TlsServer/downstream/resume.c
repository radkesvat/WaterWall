#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining)
    {
        return;
    }

    if (ls->fallback_mode)
    {
        ls->fallback_payload_paused = false;
        if (UNLIKELY(! tlsserverScheduleFallbackPayloadDrain(t, l, ls)))
        {
            tlsserverCloseLineFatal(t, l);
            return;
        }
        if (! lineIsAlive(l))
        {
            return;
        }
    }

    tunnelPrevDownStreamResume(t, l);
}

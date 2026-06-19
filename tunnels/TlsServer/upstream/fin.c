#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received upstream Finish (upstream_finished=%d, downstream_finishing=%d)",
             (unsigned int) lineGetWID(l), (int) ls->upstream_finished, (int) ls->downstream_finishing);
    }

    if (ls->downstream_finishing)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Finish because downstream side is already closing");
        }
        return;
    }

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        bool      forward  = fallback != NULL && ls->fallback_init_sent && ! ls->fallback_up_finished;

        if (forward && ls->fallback_pending_up != NULL && bufferqueueGetBufCount(ls->fallback_pending_up) > 0)
        {
            ls->fallback_up_finish_pending = true;
            return;
        }

        tlsserverLinestateDestroy(ls);

        if (forward)
        {
            tunnelUpStreamFin(fallback, l);
        }
        return;
    }

    bool forward_upstream = ls->protected_init_sent && ! ls->upstream_finished;

    if (ls->verbose)
    {
        LOGD("TlsServer: destroying TLS state%s", forward_upstream ? " and forwarding upstream Finish" : "");
    }

    tlsserverLinestateDestroy(ls);

    if (forward_upstream)
    {
        tunnelNextUpStreamFinish(t, l);
    }
}

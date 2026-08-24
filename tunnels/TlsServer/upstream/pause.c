#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        if (fallback != NULL && ! ls->fallback_close_draining)
        {
            tunnelUpStreamPause(fallback, l);
        }
        return;
    }

    if (! ls->protected_init_sent)
    {
        return;
    }

    if (ts->record_shaping.enabled)
    {
        ls->shaping_wire_paused = true;
        if (! ls->shaping_retired)
        {
            tlsserverCancelShapedOutputTimer(ls);
        }
        if (! ls->shaping_retired && ls->handshake_completed && SSL_version(ls->ssl) == TLS1_3_VERSION &&
            (ls->shaping_producer_paused || ls->downstream_finishing))
        {
            return;
        }
    }

    if (ls->upstream_finished || ls->downstream_finishing)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Pause because upstream side is already finished");
        }
        return;
    }

    tunnelNextUpStreamPause(t, l);
}

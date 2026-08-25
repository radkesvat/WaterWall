#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        if (fallback != NULL && ! ls->fallback_close_draining)
        {
            tunnelUpStreamResume(fallback, l);
        }
        return;
    }

    if (! ls->protected_init_sent)
    {
        return;
    }

    if (ts->record_shaping.enabled)
    {
        ls->shaping_wire_paused = false;
    }

    if (ts->record_shaping.enabled && ls->handshake_completed && SSL_version(ls->ssl) == TLS1_3_VERSION)
    {
        lineRef(l);
        bool shaping_pause_was_active = ls->shaping_producer_paused;
        bool output_ok = ls->shaping_retired ? tlsserverFlushSslOutput(t, l, ls)
                                             : tlsserverDrainShapedOutput(t, l, ls, false);
        if (! output_ok)
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsserver_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnref(l);
                if (state_is_active)
                {
                    tlsserverCloseLineFatal(t, l);
                }
                return;
            }
            lineUnref(l);
            return;
        }

        ls = lineGetState(l, t);
        if (! tlsserverTryCompleteDeferredFinish(t, l, ls))
        {
            lineUnref(l);
            return;
        }

        if (! ls->shaping_retired && ! tlsserverScheduleShapedOutput(t, l, ls))
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsserver_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnref(l);
                if (state_is_active)
                {
                    tlsserverCloseLineFatal(t, l);
                }
                return;
            }
            lineUnref(l);
            return;
        }

        ls = lineGetState(l, t);
        if (shaping_pause_was_active || ls->shaping_producer_paused || ls->shaping_wire_paused ||
            ls->upstream_finished || ls->downstream_finishing)
        {
            lineUnref(l);
            return;
        }

        tunnelNextUpStreamResume(t, l);
        lineUnref(l);
        return;
    }

    if (ls->upstream_finished || ls->downstream_finishing)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Resume because upstream side is already finished");
        }
        return;
    }

    tunnelNextUpStreamResume(t, l);
}

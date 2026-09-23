#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    ls->shaping_wire_paused = false;

    if (ls->upstream_finished)
    {
        return;
    }

    if (ts->record_shaping.enabled && ls->handshake_completed && ls->ssl != NULL &&
        SSL_version(ls->ssl) == TLS1_3_VERSION)
    {
        lineRef(l);
        bool output_ok =
            ls->shaping_retired ? tlsclientFlushSslOutput(t, l, ls) : tlsclientDrainShapedOutput(t, l, ls, false);
        if (! output_ok)
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnref(l);
                if (state_is_active)
                {
                    tlsclientCloseLineBidirectional(t, l);
                }
                return;
            }
            lineUnref(l);
            return;
        }

        ls = lineGetState(l, t);
        if (! ls->shaping_retired && ! tlsclientScheduleShapedOutput(t, l, ls))
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnref(l);
                if (state_is_active)
                {
                    tlsclientCloseLineBidirectional(t, l);
                }
                return;
            }
            lineUnref(l);
            return;
        }

        if (UNLIKELY(! tlsclientDrainPendingPlaintext(t, l)))
        {
            lineUnref(l);
            return;
        }
        discard tlsclientUpdateSourcePressure(t, l);
        lineUnref(l);
        return;
    }
    if (UNLIKELY(! tlsclientDrainPendingPlaintext(t, l)))
    {
        return;
    }
    discard tlsclientUpdateSourcePressure(t, l);
}

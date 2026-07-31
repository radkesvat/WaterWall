#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (ts->record_shaping.enabled)
    {
        ls->shaping_wire_paused = false;
    }

    if (ls->upstream_finished)
    {
        return;
    }

    if (ts->record_shaping.enabled && ls->handshake_completed && ls->ssl != NULL &&
        SSL_version(ls->ssl) == TLS1_3_VERSION)
    {
        lineLock(l);
        bool shaping_pause_was_active = ls->shaping_producer_paused;
        if (! tlsclientDrainShapedOutput(t, l, ls, false))
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnlock(l);
                if (state_is_active)
                {
                    tlsclientCloseLineBidirectional(t, l);
                }
                return;
            }
            lineUnlock(l);
            return;
        }

        ls = lineGetState(l, t);
        if (! tlsclientScheduleShapedOutput(t, l, ls))
        {
            if (lineIsAlive(l))
            {
                bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
                lineUnlock(l);
                if (state_is_active)
                {
                    tlsclientCloseLineBidirectional(t, l);
                }
                return;
            }
            lineUnlock(l);
            return;
        }

        ls = lineGetState(l, t);
        if (shaping_pause_was_active || ls->shaping_producer_paused || ls->shaping_wire_paused || ls->upstream_finished)
        {
            lineUnlock(l);
            return;
        }

        tunnelPrevDownStreamResume(t, l);
        lineUnlock(l);
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (ts->record_shaping.enabled)
    {
        ls->shaping_wire_paused = true;
        if (! ls->shaping_retired)
        {
            tlsclientCancelShapedOutputTimer(ls);
        }
    }

    if (ls->upstream_finished)
    {
        return;
    }

    if (ts->record_shaping.enabled && ! ls->shaping_retired && ls->handshake_completed && ls->ssl != NULL &&
        SSL_version(ls->ssl) == TLS1_3_VERSION && ls->shaping_producer_paused)
    {
        return;
    }
    tunnelPrevDownStreamPause(t, l);
}

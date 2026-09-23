#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    ls->shaping_wire_paused = true;
    if (ts->record_shaping.enabled)
    {
        if (! ls->shaping_retired)
        {
            tlsclientCancelShapedOutputTimer(ls);
        }
    }

    discard tlsclientUpdateSourcePressure(t, l);
}

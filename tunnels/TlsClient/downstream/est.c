#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (ls->upstream_finished)
    {
        return;
    }

    if (ts->handshake_takeover_enabled)
    {
        discard l;
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}

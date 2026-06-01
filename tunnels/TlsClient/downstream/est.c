#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);

    if (ts->handshake_takeover_enabled)
    {
        discard l;
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    lineMarkEstablished(l);
    const testerclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->packet_mode)
    {
        return;
    }

    testerclient_lstate_t *ls = lineGetState(l, t);
    if (ls->request_ready)
    {
        return;
    }

    ls->request_ready = true;
    discard testerclientScheduleRequestSend(t, l, ls);
}

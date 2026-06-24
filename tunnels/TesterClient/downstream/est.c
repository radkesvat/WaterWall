#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    lineMarkEstablished(l);

    ls->est_received = true;
    testerclientScheduleRequestSend(t, l, ls);
}

#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    ls->request_paused = false;
    discard testerclientScheduleRequestSend(t, l, ls);
}

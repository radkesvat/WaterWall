#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
    ls->pending_next_pause = false;
    if (ls->phase == kConnectionFisherServerPhaseEstablished)
        tunnelNextUpStreamResume(t, l);
}

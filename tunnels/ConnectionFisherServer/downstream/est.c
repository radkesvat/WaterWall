#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kConnectionFisherServerPhaseEstablished)
    {
        return;
    }

    if (! lineIsEstablished(l))
    {
        lineMarkEstablished(l);
    }

    tunnelPrevDownStreamEst(t, l);
}

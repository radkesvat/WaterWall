#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kConnectionFisherServerPhaseClosing)
        return;
    if (! ls->next_init_sent)
    {
        ls->pending_next_pause = true;
        return;
    }

    ls->pending_next_pause = false;
    tunnelNextUpStreamPause(t, l);
}

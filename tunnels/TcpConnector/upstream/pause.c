#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tcpconnector_lstate_t *lstate = lineGetState(l, t);

    if (! lstate->read_paused)
    {
        lstate->read_paused = true;
        wioReadStop(lstate->io);
    }
}

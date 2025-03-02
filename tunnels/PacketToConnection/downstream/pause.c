#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate = lineGetState(l, t);
    assert(lineIsAlive(l));

    if (! lstate->read_paused)
    {
        lstate->read_paused = true;
    }


}

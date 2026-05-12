#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *ls = lineGetState(l, t);
    assert(lineIsAlive(l));

    ls->read_paused = true;
}

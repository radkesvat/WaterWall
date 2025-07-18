#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l)
{

    udplistener_lstate_t *ls = lineGetState(l, t);

    if (! ls->read_paused)
    {
        ls->read_paused = true;
    }
}

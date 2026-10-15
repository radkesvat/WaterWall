#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);

    ls->read_paused = true;
}

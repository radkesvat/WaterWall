#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);

    ls->read_paused = false;
}

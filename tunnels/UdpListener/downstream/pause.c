#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    udplistenerRequireCurrentLineWorker(l, "downstream Pause");
    udplistener_lstate_t *ls = lineGetState(l, t);

    ls->read_paused = true;
}

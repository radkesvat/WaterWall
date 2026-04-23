#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDestroy(tunnel_t *t)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}

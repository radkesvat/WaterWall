#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDestroy(tunnel_t *t)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    mutexDestroy(&state->aggregate_mutex);
    tunnelDestroy(t);
}


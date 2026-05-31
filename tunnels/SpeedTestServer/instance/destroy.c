#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDestroy(tunnel_t *t)
{
    speedtestserver_tstate_t *state = tunnelGetState(t);
    mutexDestroy(&state->aggregate_mutex);
    tunnelDestroy(t);
}


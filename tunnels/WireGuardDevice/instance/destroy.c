#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelDestroy(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);
    mutexDestroy(&state->mutex);
    tunnelDestroy(t);
}


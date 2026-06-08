#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelDestroy(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);
    if (state->device_configuration.private_key != NULL)
    {
        memoryFree((void *) state->device_configuration.private_key);
        state->device_configuration.private_key = NULL;
    }
    mutexDestroy(&state->mutex);
    tunnelDestroy(t);
}

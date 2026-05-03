#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelDestroy(tunnel_t *t)
{
    loggertunnel_tstate_t *state = tunnelGetState(t);

    if (state->file_prefix != NULL)
    {
        memoryFree(state->file_prefix);
    }

    if (state->up_path != NULL)
    {
        memoryFree(state->up_path);
    }

    if (state->down_path != NULL)
    {
        memoryFree(state->down_path);
    }

    if (state->all_path != NULL)
    {
        memoryFree(state->all_path);
    }

    mutexDestroy(&state->file_mutex);
    tunnelDestroy(t);
}

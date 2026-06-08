#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelDestroy(tunnel_t *t)
{
    packetsender_tstate_t *state = tunnelGetState(t);

    if (state->source_ranges != NULL)
    {
        memoryFree(state->source_ranges);
        state->source_ranges = NULL;
    }

    if (state->workers != NULL)
    {
        memoryFree(state->workers);
        state->workers = NULL;
    }

    if (state->packet_bytes != NULL)
    {
        memoryFree(state->packet_bytes);
        state->packet_bytes = NULL;
    }

    tunnelDestroy(t);
}

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
        for (wid_t wi = 0; wi < state->workers_count; ++wi)
        {
            if (state->workers[wi].timer != NULL)
            {
                weventSetUserData(state->workers[wi].timer, NULL);
                wtimerDelete(state->workers[wi].timer);
                state->workers[wi].timer = NULL;
            }
        }

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

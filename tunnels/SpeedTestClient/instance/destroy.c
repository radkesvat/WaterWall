#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                   context;
    speedtestclient_tstate_t *state = tunnelGetState(t);
    if (state->owned_lines != NULL)
    {
        for (uint32_t stream_id = 0; stream_id < state->connection_count; ++stream_id)
        {
            if (UNLIKELY(state->owned_lines[stream_id] != NULL))
            {
                LOGF("SpeedTestClient: destroying tunnel with a live owned stream slot");
                abortProgramNow(1);
            }
        }
        memoryFree(state->owned_lines);
    }
    mutexDestroy(&state->aggregate_mutex);
    tunnelDestroy(t);
}

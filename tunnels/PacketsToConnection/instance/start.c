#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnStart(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    state->route_worker_count = getWorkersCount();
    state->routes_v4          = memoryAllocateZero(sizeof(*state->routes_v4) * (size_t) state->route_worker_count);
    state->owned_worker_count = state->route_worker_count;
    state->owned_lines        = memoryAllocateZero(sizeof(*state->owned_lines) * (size_t) state->owned_worker_count);
    if (UNLIKELY(! quiescenceGateOpen(&state->output_gate)))
    {
        memoryFree(state->owned_lines);
        memoryFree(state->routes_v4);
        state->owned_lines = NULL;
        state->routes_v4   = NULL;
        LOGF("PacketsToConnection: failed to open the output admission gate");
        startupFailureRecord(1);
        return;
    }
    if (UNLIKELY(! quiescenceGateOpen(&state->next_gate)))
    {
        quiescenceGateCloseAndQuiesce(&state->output_gate, quiescenceGateYieldThread, NULL);
        memoryFree(state->owned_lines);
        memoryFree(state->routes_v4);
        state->owned_lines = NULL;
        state->routes_v4   = NULL;
        LOGF("PacketsToConnection: failed to open the next-side admission gate");
        startupFailureRecord(1);
        return;
    }
}

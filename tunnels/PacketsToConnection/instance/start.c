#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnStart(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    state->route_worker_count = getWorkersCount();
    state->routes_v4          = memoryAllocateZero(sizeof(*state->routes_v4) * (size_t) state->route_worker_count);
    if (UNLIKELY(state->routes_v4 == NULL))
    {
        LOGF("PacketsToConnection: failed to allocate the worker route table");
        abortProgramNow(1);
    }

    state->owned_worker_count = state->route_worker_count;
    state->owned_lines        = memoryAllocateZero(sizeof(*state->owned_lines) * (size_t) state->owned_worker_count);
    if (UNLIKELY(state->owned_lines == NULL))
    {
        memoryFree(state->routes_v4);
        state->routes_v4 = NULL;
        LOGF("PacketsToConnection: failed to allocate the owned-line registry");
        abortProgramNow(1);
    }

    if (UNLIKELY(! deviceLifetimeGateOpen(&state->output_gate)))
    {
        memoryFree(state->owned_lines);
        memoryFree(state->routes_v4);
        state->owned_lines = NULL;
        state->routes_v4   = NULL;
        LOGF("PacketsToConnection: failed to open the output admission gate");
        abortProgramNow(1);
    }
    if (UNLIKELY(! deviceLifetimeGateOpen(&state->next_gate)))
    {
        deviceLifetimeGateCloseAndQuiesce(&state->output_gate, deviceLifetimeYieldThread, NULL);
        memoryFree(state->owned_lines);
        memoryFree(state->routes_v4);
        state->owned_lines = NULL;
        state->routes_v4   = NULL;
        LOGF("PacketsToConnection: failed to open the next-side admission gate");
        abortProgramNow(1);
    }
    if (UNLIKELY(state->async_session == NULL || ! tunnelasyncsessionOpen(state->async_session)))
    {
        deviceLifetimeGateCloseAndQuiesce(&state->next_gate, deviceLifetimeYieldThread, NULL);
        deviceLifetimeGateCloseAndQuiesce(&state->output_gate, deviceLifetimeYieldThread, NULL);
        memoryFree(state->owned_lines);
        memoryFree(state->routes_v4);
        state->owned_lines = NULL;
        state->routes_v4   = NULL;
        LOGF("PacketsToConnection: failed to open the asynchronous callback gate");
        abortProgramNow(1);
    }
}

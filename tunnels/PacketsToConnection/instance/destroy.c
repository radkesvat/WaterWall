#include "structure.h"

#include "loggers/network_logger.h"

void ptcDestroyLwipResources(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    if (state->lwip_resources_destroyed)
    {
        return;
    }

    LOCK_TCPIP_CORE();
    ptcDetachOwnedLinePcbsLocked(t);
    ptcTcpDrainDestroyAllLocked(t);
    ptcDestroyRouteContexts(t);
    ptcFakeDnsDestroy(state);
    state->lwip_resources_destroyed = true;
    UNLOCK_TCPIP_CORE();
}

void ptcTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    ptcTunnelOnStop(t, context);

    ptc_tstate_t *state = tunnelGetState(t);
    if (state->owned_lines != NULL)
    {
        for (uint32_t wid = 0; wid < state->owned_worker_count; ++wid)
        {
            assert(state->owned_lines[wid] == NULL);
        }
        memoryFree(state->owned_lines);
        state->owned_lines = NULL;
    }
    if (state->owned_lines_lock_initialized)
    {
        mutexDestroy(&state->owned_lines_lock);
        state->owned_lines_lock_initialized = false;
    }

    tunnelDestroy(t);
}

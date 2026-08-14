#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnPreStop(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    atomicStoreExplicit(&state->stopping, true, memory_order_release);
    deviceLifetimeGateCloseAndQuiesce(&state->output_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateCloseAndQuiesce(&state->next_gate, deviceLifetimeYieldThread, NULL);
    if (state->async_session != NULL)
    {
        tunnelasyncsessionCloseAndQuiesce(state->async_session);
    }
}

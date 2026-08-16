#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ptc_tstate_t *state = tunnelGetState(t);

    atomicStoreRelaxed(&state->stopping, true);
    deviceLifetimeGateClose(&state->output_gate);
    deviceLifetimeGateClose(&state->next_gate);
    if (state->async_session != NULL)
    {
        tunnelasyncsessionClose(state->async_session);
    }
}

void ptcTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ptc_tstate_t *state = tunnelGetState(t);
    deviceLifetimeGateWaitQuiesced(&state->output_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateWaitQuiesced(&state->next_gate, deviceLifetimeYieldThread, NULL);
    if (state->async_session != NULL)
    {
        tunnelasyncsessionWaitQuiesced(state->async_session);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ptc_tstate_t *state = tunnelGetState(t);

    atomicStoreRelaxed(&state->stopping, true);
    quiescenceGateClose(&state->output_gate);
    quiescenceGateClose(&state->next_gate);
}

void ptcTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ptc_tstate_t *state = tunnelGetState(t);
    quiescenceGateWaitQuiesced(&state->output_gate, quiescenceGateYieldThread, NULL);
    quiescenceGateWaitQuiesced(&state->next_gate, quiescenceGateYieldThread, NULL);
}

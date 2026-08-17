#include "structure.h"

void ctpTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ctp_tstate_t *ts = tunnelGetState(t);

    atomicStoreRelaxed(&ts->stopping, true);
    quiescenceGateClose(&ts->prev_gate);
    quiescenceGateClose(&ts->next_gate);
    quiescenceGateClose(&ts->packet_ingress_gate);
}

void ctpTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ctp_tstate_t *ts = tunnelGetState(t);
    quiescenceGateWaitQuiesced(&ts->prev_gate, quiescenceGateYieldThread, NULL);
    quiescenceGateWaitQuiesced(&ts->next_gate, quiescenceGateYieldThread, NULL);
    quiescenceGateWaitQuiesced(&ts->packet_ingress_gate, quiescenceGateYieldThread, NULL);
}

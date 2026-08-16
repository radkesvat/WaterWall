#include "structure.h"

void ctpTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ctp_tstate_t *ts = tunnelGetState(t);

    atomicStoreRelaxed(&ts->stopping, true);
    deviceLifetimeGateClose(&ts->prev_gate);
    deviceLifetimeGateClose(&ts->next_gate);
    deviceLifetimeGateClose(&ts->packet_ingress_gate);
    if (ts->async_session != NULL)
    {
        tunnelasyncsessionClose(ts->async_session);
    }
}

void ctpTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ctp_tstate_t *ts = tunnelGetState(t);
    deviceLifetimeGateWaitQuiesced(&ts->prev_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateWaitQuiesced(&ts->next_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateWaitQuiesced(&ts->packet_ingress_gate, deviceLifetimeYieldThread, NULL);
    if (ts->async_session != NULL)
    {
        tunnelasyncsessionWaitQuiesced(ts->async_session);
    }
}

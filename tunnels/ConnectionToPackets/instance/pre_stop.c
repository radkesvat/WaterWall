#include "structure.h"

void ctpTunnelOnPreStop(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    atomicStoreExplicit(&ts->stopping, true, memory_order_release);
    deviceLifetimeGateCloseAndQuiesce(&ts->prev_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateCloseAndQuiesce(&ts->next_gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateCloseAndQuiesce(&ts->packet_ingress_gate, deviceLifetimeYieldThread, NULL);
    if (ts->async_session != NULL)
    {
        tunnelasyncsessionCloseAndQuiesce(ts->async_session);
    }
}

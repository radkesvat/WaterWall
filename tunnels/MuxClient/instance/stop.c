#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void muxclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    muxclient_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(wid >= ts->workers_count))
    {
        LOGF("MuxClient: invalid worker %d during quiescence", (int) wid);
        abortProgramNow(1);
    }
    ts->worker_states[wid].quiescing = true;
}

void muxclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    muxclientTunnelOnWorkerQuiesce(t, wid, context);
    muxclient_tstate_t *ts = tunnelGetState(t);
    while (ts->worker_states[wid].owned_parents != NULL)
    {
        muxclientHandleParentLoss(t, ts->worker_states[wid].owned_parents->l, true);
    }
}

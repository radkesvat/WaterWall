#include "structure.h"

#include "loggers/network_logger.h"

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
    wtimer_t *timer                  = ts->worker_states[wid].keepalive_timer;
    if (timer != NULL)
    {
        ts->worker_states[wid].keepalive_timer = NULL;
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
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

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
    local_idle_table_t *table        = ts->worker_states[wid].keepalive_table;
    if (table != NULL)
    {
        localidletableQuiesce(table);
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
    local_idle_table_t *table = ts->worker_states[wid].keepalive_table;
    if (table != NULL)
    {
        if (UNLIKELY(localidletableGetItemCount(table) != 0))
        {
            LOGF("MuxClient: worker %u stopped with keepalive items", (unsigned int) wid);
            abortProgramNow(1);
        }
        localidletableDestroy(table);
        ts->worker_states[wid].keepalive_table = NULL;
    }
}

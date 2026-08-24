#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseclient_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void reverseclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    reverseclient_tstate_t *ts = tunnelGetState(t);
    if (ts->starved_connections != NULL)
    {
        idletableDrainWorkerItems(ts->starved_connections, wid);
    }

    reverseclient_thread_box_t *box = &ts->threadlocal_pool[wid];
    while (box->owned_pairs != NULL)
    {
        reverseclientClosePair(box->owned_pairs, kReverseClientCloseInternal);
    }
    if (UNLIKELY(box->connecting_cons_count != 0 || box->unused_cons_count != 0))
    {
        LOGF("ReverseClient: worker %d stopped with %u connecting and %u unused pair reservation(s)",
             (int) wid,
             (unsigned int) box->connecting_cons_count,
             (unsigned int) box->unused_cons_count);
        abortProgramNow(1);
    }
}

void reverseclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseclient_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < getWorkersCount(); wid++)
    {
        if (UNLIKELY(ts->threadlocal_pool[wid].owned_pairs != NULL))
        {
            LOGF("ReverseClient: stop observed an undrained owned pair on worker %d", (int) wid);
            abortProgramNow(1);
        }
    }
    if (UNLIKELY(atomicLoadRelaxed(&ts->reverse_cons) != 0))
    {
        LOGF("ReverseClient: stop observed %u active reverse pair reservation(s)",
             (unsigned int) atomicLoadRelaxed(&ts->reverse_cons));
        abortProgramNow(1);
    }
    if (ts->starved_connections != NULL)
    {
        idletableDestroy(ts->starved_connections);
        ts->starved_connections = NULL;
    }
}

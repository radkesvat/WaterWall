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
    assert(box->connecting_cons_count == 0);
    assert(box->unused_cons_count == 0);
}

void reverseclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseclient_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < getWorkersCount(); wid++)
    {
        assert(ts->threadlocal_pool[wid].owned_pairs == NULL);
    }
    assert(atomicLoadRelaxed(&ts->reverse_cons) == 0);
    if (ts->starved_connections != NULL)
    {
        idletableDestroy(ts->starved_connections);
        ts->starved_connections = NULL;
    }
}

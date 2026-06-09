#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelOnStop(tunnel_t *t)
{
    tcplistener_tstate_t *ts = tunnelGetState(t);
    atomicStoreExplicit(&ts->stopping, true, memory_order_release);
}

void tcplistenerTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    tcplistener_tstate_t *ts = tunnelGetState(t);
    atomicStoreExplicit(&ts->stopping, true, memory_order_release);

    if (ts->idle_tables == NULL)
    {
        return;
    }

    local_idle_table_t *table = ts->idle_tables[wid];
    if (table == NULL)
    {
        return;
    }

    localidletableDrainItems(table);
    localidletableDestroy(table);
    ts->idle_tables[wid] = NULL;
}

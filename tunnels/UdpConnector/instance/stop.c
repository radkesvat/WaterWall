#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void udpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    // onWorkerStop runs on the worker being stopped, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

    udpconnector_tstate_t *ts = tunnelGetState(t);
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

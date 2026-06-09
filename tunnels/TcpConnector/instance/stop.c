#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void tcpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    tcpconnector_tstate_t *ts = tunnelGetState(t);
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

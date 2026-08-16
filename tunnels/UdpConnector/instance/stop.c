#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void udpconnectorTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    udpconnector_tstate_t *ts = tunnelGetState(t);
    if (ts->idle_tables != NULL && ts->idle_tables[wid] != NULL)
    {
        localidletableQuiesce(ts->idle_tables[wid]);
    }
}

void udpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
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

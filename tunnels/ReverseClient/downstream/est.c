#include <stddef.h>

#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    reverseclient_tstate_t *ts = tunnelGetState(t);

    wid_t wid = lineGetWID(l);

    if (! lineIsEstablished(l))
    {
        lineMarkEstablished(l);

        ts->threadlocal_pool[wid].connecting_cons_count -= 1;
        ts->threadlocal_pool[wid].unused_cons_count += 1;

        LOGI("ReverseClient: connected,    tid: %d unused: %u active: %d", wid,
             ts->threadlocal_pool[wid].unused_cons_count,
             atomicLoadExplicit(&(ts->reverse_cons), memory_order_relaxed));

        reverseclientInitiateConnectOnWorker(t, wid, false);
    }
}

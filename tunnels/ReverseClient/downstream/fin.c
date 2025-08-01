#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    reverseclient_tstate_t *ts  = tunnelGetState(t);
    reverseclient_lstate_t *uls = lineGetState(l, t);

    line_t *ul = uls->u;
    line_t *dl = uls->d;

    wid_t wid = lineGetWID(l);

    if (uls->pair_connected)
    {
        atomicDecRelaxed((&(ts->reverse_cons)));
        LOGD("ReverseClient: disconnected, wid: %d unused: %u active: %d", wid,
             ts->threadlocal_pool[wid].unused_cons_count, atomicLoadRelaxed(&(ts->reverse_cons)));

        reverseclientLinestateDestroy(uls);
        lineDestroy(ul);

        reverseclientLinestateDestroy(lineGetState(dl, t));
        tunnelPrevDownStreamFinish(t, dl);
        lineDestroy(dl);

        reverseclientInitiateConnectOnWorker(t, wid, false);
    }
    else
    {
        if (lineIsEstablished(l))
        {
            ts->threadlocal_pool[wid].unused_cons_count -= 1;
            LOGD("ReverseClient: disconnected, wid: %d unused: %u active: %d", wid,
                 ts->threadlocal_pool[wid].unused_cons_count, atomicLoadRelaxed(&(ts->reverse_cons)));
        }
        else
        {
            ts->threadlocal_pool[wid].connecting_cons_count -= 1;
        }
        assert(uls->idle_handle != NULL);
        idletableRemoveIdleItemByHash(uls->u->wid, ts->starved_connections, (hash_t) (uintptr_t) (uls));
        uls->idle_handle = NULL;

        reverseclientInitiateConnectOnWorker(t, wid, false);

        reverseclientLinestateDestroy(uls);
        reverseclientLinestateDestroy(lineGetState(dl, t));

        lineDestroy(ul);
        lineDestroy(dl);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    reverseclient_tstate_t *ts  = tunnelGetState(t);
    reverseclient_lstate_t *uls = lineGetState(l, t);

    wid_t wid = lineGetWID(l);

    if (uls->pair_connected)
    {
        tunnelPrevDownStreamPayload(t, uls->d, buf);
    }
    else
    {
        ts->threadlocal_pool[wid].unused_cons_count -= 1;
        reverseclientInitiateConnectOnWorker(t, wid, false);

        atomicIncRelaxed(&(ts->reverse_cons));

        assert(uls->idle_handle);
        uls->idle_handle = NULL;
        idleTableRemoveIdleItemByHash(uls->u->wid, ts->starved_connections, (hash_t) (uls));

        uls->pair_connected = true;

        line_t *dl = uls->d;

        lineLock(dl);
        tunnelPrevDownStreamInit(t, dl);

        if (! lineIsAlive(dl))
        {
            bufferpoolReuseBuffer(lineGetBufferPool(dl), buf);
            lineUnlock(dl);
            return;
        }
        lineUnlock(dl);
        tunnelPrevDownStreamPayload(t, dl, buf);
    }
}

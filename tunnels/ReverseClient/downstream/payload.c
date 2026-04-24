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
        line_t *dl = uls->d;

        ts->threadlocal_pool[wid].unused_cons_count -= 1;
        reverseclientInitiateConnectOnWorker(t, wid, false);

        assert(uls->idle_handle);
        bool removed =
            idletableRemoveIdleItemByHash(uls->u->wid, ts->starved_connections, (hash_t) (uintptr_t) (uls));
        if (! removed)
        {
            LOGF("ReverseClient: failed to remove idle item while pairing connection");
            terminateProgram(1);
            return;
        }
        uls->idle_handle = NULL;

        atomicIncRelaxed(&(ts->reverse_cons));

        if (! withLineLocked(dl, tunnelPrevDownStreamInit, t))
        {
            reuseBuffer(buf);
            return;
        }

        uls->pair_connected = true;

        tunnelPrevDownStreamPayload(t, dl, buf);
    }
}

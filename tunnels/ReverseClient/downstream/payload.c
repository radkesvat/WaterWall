#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    reverseclient_tstate_t *ts   = tunnelGetState(t);
    reverseclient_pair_t   *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;

    if (pair->phase == kReverseClientPairActive)
    {
        tunnelPrevDownStreamPayload(t, pair->d, buf);
        return;
    }

    assert(pair->phase == kReverseClientPairUnused);
    assert(pair->idle_handle != NULL);

    const wid_t wid = lineGetWID(pair->u);
    if (! idletableRemoveIdleItemByHash(wid, ts->starved_connections, (hash_t) (uintptr_t) pair))
    {
        LOGF("ReverseClient: failed to remove an idle pair while activating it");
        abortProgramNow(1);
    }
    pair->idle_handle = NULL;

    reverseclient_thread_box_t *box = &ts->threadlocal_pool[wid];
    assert(box->unused_cons_count > 0);
    box->unused_cons_count--;
    pair->phase = kReverseClientPairActive;
    atomicIncRelaxed(&ts->reverse_cons);
    reverseclientInitiateConnectOnWorker(t, wid, false);

    pair->downstream_init_sent = true;
    if (! withLineLocked(pair->d, tunnelPrevDownStreamInit, t))
    {
        reuseBuffer(buf);
        return;
    }
    tunnelPrevDownStreamPayload(t, pair->d, buf);
}

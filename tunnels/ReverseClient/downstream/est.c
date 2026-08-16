#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    reverseclient_tstate_t     *ts   = tunnelGetState(t);
    reverseclient_pair_t       *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;
    reverseclient_thread_box_t *box  = &ts->threadlocal_pool[lineGetWID(l)];

    if (pair->phase != kReverseClientPairConnecting)
    {
        return;
    }

    lineMarkEstablished(l);
    assert(box->connecting_cons_count > 0);
    box->connecting_cons_count--;
    box->unused_cons_count++;
    pair->phase = kReverseClientPairUnused;

    LOGI("ReverseClient: connected, wid: %d unused: %u active: %d",
         lineGetWID(l),
         box->unused_cons_count,
         atomicLoadRelaxed(&ts->reverse_cons));
    reverseclientInitiateConnectOnWorker(t, lineGetWID(l), false);
}

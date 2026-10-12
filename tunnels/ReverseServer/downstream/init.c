#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamInit(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    reverseserverLinestateInitialize(uls, u, NULL);
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    uls->handshaked                 = true;
    reverseserverAddConnectionU(box, uls);
    if (! lineCallWithRef(u, tunnelNextUpStreamEst, t))
        return;
    /* Est can admit payload and complete pairing reentrantly. */
    if (uls->paired)
        return;
    if (! reverseserverReconcileSource(t, u))
        return;
    /* The waiting Pause can itself admit a peer or close this line. */
    if (uls->paired)
        return;
    if (atomicLoad(&box->d_count) != 0)
        reverseserverPair(t, u, box->d_root->d);
    else
        reverseserverNotifyWaitingPeers(t, lineGetWID(u));
}

#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamInit(tunnel_t *t, line_t *u)
{
    address_context_t *destination = lineGetDestinationAddressContext(u);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelNextUpStreamFinish(t, u);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    reverseserver_lstate_t *uls = lineGetState(u, t);
    reverseserverLinestateInitialize(uls, u, NULL);
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    reverseserverEnterWaiting(&box->users, uls);
    if (! lineCallWithRef(u, tunnelNextUpStreamEst, t))
        return;
    /* Est can admit payload and complete pairing reentrantly. */
    if (uls->phase != kReverseHalfWaiting)
        return;
    if (! reverseserverReconcileSource(t, u))
        return;
    /* The waiting Pause can itself admit a peer or close this line. */
    if (uls->phase != kReverseHalfWaiting)
        return;
    if (box->reverse_links.head != NULL)
        reverseserverPair(t, u, box->reverse_links.head->d);
    else
        reverseserverNotifyWaitingPeers(t, lineGetWID(u));
}

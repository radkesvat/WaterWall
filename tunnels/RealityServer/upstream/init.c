#include "structure.h"

void realityserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    realityserverLinestateInitialize(ls, lineGetBufferPool(l));
    ls->destination_init_sent = true;
    lineMarkFallback(l);

    lineCallWithRef(l, tunnelUpStreamInit, ts->destination_tunnel);
}

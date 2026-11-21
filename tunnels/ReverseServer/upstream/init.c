#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamInit(tunnel_t *t, line_t *d)
{
    address_context_t *destination = lineGetDestinationAddressContext(d);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, d);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    reverseserver_lstate_t *dls = lineGetState(d, t);

    reverseserverLinestateInitialize(dls, NULL, d);

    tunnelPrevDownStreamEst(t, d);
}

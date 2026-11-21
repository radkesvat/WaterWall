#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    keepaliveserver_lstate_t *ls = lineGetState(l, t);
    keepaliveserverLinestateInitialize(ls, l, tunnelGetChain(t)->supports_splice);

    tunnelNextUpStreamInit(t, l);
}

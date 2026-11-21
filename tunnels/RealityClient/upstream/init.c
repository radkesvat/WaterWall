#include "structure.h"

void realityclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    realityclient_lstate_t *ls = lineGetState(l, t);
    realityclientLinestateInitialize(ls, lineGetBufferPool(l));

    tunnelNextUpStreamInit(t, l);
}

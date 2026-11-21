#include "structure.h"

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    bgp4server_lstate_t *ls = lineGetState(l, t);
    bgp4serverLinestateInitialize(ls, l, tunnelGetChain(t)->supports_splice);
    tunnelNextUpStreamInit(t, l);
}

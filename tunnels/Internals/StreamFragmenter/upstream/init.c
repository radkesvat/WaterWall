#include "structure.h"

void streamfragmenterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    streamfragmenterLinestateInitialize(lineGetState(l, t), t, l);
    streamfragmenterTryBypass(t, l);
    tunnelNextUpStreamInit(t, l);
}

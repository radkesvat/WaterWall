#include "structure.h"

void obfuscatorclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        address_context_t *destination = lineGetDestinationAddressContext(l);
        if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
        {
            tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);
        obfuscatorclientLinestateInitialize(lineGetState(l, t), l, false);
    }
    tunnelNextUpStreamInit(t, l);
}

#include "structure.h"

void obfuscatorserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        address_context_t *destination = lineGetDestinationAddressContext(l);
        if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
        {
            tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
            tunnelNextUpStreamFinish(t, l);
            return;
        }
        addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);
        obfuscatorserverLinestateInitialize(lineGetState(l, t), l, true);
    }
    tunnelPrevDownStreamInit(t, l);
}

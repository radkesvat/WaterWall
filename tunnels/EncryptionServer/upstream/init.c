#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    const uint8_t      transport   = addresscontextSelectTransport(destination, kAddressContextTransportBoth);
    if (transport == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportBoth);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    addresscontextSetTransportOffer(destination, transport);
    encryptionserver_lstate_t *ls = lineGetState(l, t);
    encryptionserverLinestateInitialize(ls, lineGetBufferPool(l), transport == kAddressContextTransportUdp);
    tunnelNextUpStreamInit(t, l);
}

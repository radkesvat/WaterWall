#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    connectionfisherserverLinestateInitialize(lineGetState(l, t), l);
}

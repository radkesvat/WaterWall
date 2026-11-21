#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    udpovertcpserverLinestateInitialize(ls, lineGetBufferPool(l), tunnelGetChain(t)->supports_splice);

    addresscontextSetOnlyProtocol(destination, IP_PROTO_UDP);
    tunnelNextUpStreamInit(t, l);
}

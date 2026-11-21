#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportUdp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportUdp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    udpovertcpclient_lstate_t *ls = lineGetState(l, t);

    udpovertcpclientLinestateInitialize(ls, lineGetBufferPool(l), tunnelGetChain(t)->supports_splice);

    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    tunnelNextUpStreamInit(t, l);
}

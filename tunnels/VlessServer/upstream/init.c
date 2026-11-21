#include "internal.h"

#include "loggers/network_logger.h"

void vlessserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        LOGW("VlessServer: refusing a line without a TCP destination offer");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    vlessserverLinestateInitialize(lineGetState(l, t), t, l, kVlessServerLineKindClient);
}

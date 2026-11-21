#include "structure.h"

#include "loggers/network_logger.h"

void softiplimiterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        LOGW("SoftIpLimiter: identity parsing requires a TCP offer");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);
    softiplimiterLinestateInitialize(lineGetState(l, t), l);
}

#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    authenticationserverLinestateInitialize(ls, lineGetBufferPool(l));
    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream Init; line state initialized and downstream Est will be sent");
    }
    tunnelPrevDownStreamEst(t, l);
}

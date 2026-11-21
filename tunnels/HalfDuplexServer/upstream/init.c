#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    halfduplexserverLinestateInitialize(ls);
    ls->ingress_tunnel = t;

    tunnelPrevDownStreamEst(t, l);

}

void halfduplexserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    // This borrowed transport ends here; the reconstructed application has
    // its own lifecycle. Repeated transport readiness does not start it.
    discard t;
    discard l;
}

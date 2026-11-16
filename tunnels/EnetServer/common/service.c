#include "EnetServer/structure.h"

/* Called only after ENet admits the peer. Common code attaches and initializes the prepared line. */
line_t *enetserverCreateApplication(tunnel_t *t, line_t *carrier)
{
    line_t *service = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(carrier));
    addresscontextCopy(lineGetSourceAddressContext(service), lineGetSourceAddressContext(carrier));
    addresscontextCopy(lineGetDestinationAddressContext(service), lineGetDestinationAddressContext(carrier));
    lineGetRoutingContext(service)->local_listener_port = lineGetRoutingContext(carrier)->local_listener_port;
    lineGetRoutingContext(service)->peer_source_port    = lineGetRoutingContext(carrier)->peer_source_port;
    lineCopyUsers(service, carrier);
    if (lineIsFallback(carrier))
    {
        lineMarkFallback(service);
        if (lineHasCloseLingerReason(carrier, kLineCloseLingerPeerWriteShutdown))
        {
            lineRequestCloseLinger(service, kLineCloseLingerPeerWriteShutdown);
        }
    }
    /* The service carries a reliable stream; the carrier stays UDP. */
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(service), IP_PROTO_TCP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(service), IP_PROTO_TCP);
    if (linePrefersOrdinaryReadUpstream(carrier))
    {
        linePreferOrdinaryReadUpstream(service);
    }
    if (linePrefersOrdinaryReadDownstream(carrier))
    {
        linePreferOrdinaryReadDownstream(service);
    }
    return service;
}

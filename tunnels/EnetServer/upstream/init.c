#include "EnetServer/structure.h"

void enetserverTunnelUpStreamInit(tunnel_t *t, line_t *carrier)
{
    /* The UDP source owns this carrier. Its service line is created only after the ENet handshake. */
    if (! enetEndpointPrepareInit(t, carrier) || ! enetEndpointAttachServer(t, carrier))
    {
        tunnelPrevDownStreamFinish(t, carrier);
        return;
    }
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(carrier), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(carrier), IP_PROTO_UDP);
    enetEndpointStartServer(t, carrier);
}

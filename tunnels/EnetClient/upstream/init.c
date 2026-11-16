#include "EnetClient/structure.h"

void enetclientTunnelUpStreamInit(tunnel_t *t, line_t *application)
{
    if (! enetEndpointPrepareInit(t, application))
    {
        tunnelPrevDownStreamFinish(t, application);
        return;
    }

    /* Borrow the application line and create the UDP carrier on the same worker. */
    line_t *carrier = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(application));
    lineCopyContext(carrier, application);
    carrier->prefer_ordinary_read_u = application->prefer_ordinary_read_u;
    carrier->prefer_ordinary_read_d = application->prefer_ordinary_read_d;
    carrier->fallback_mode          = application->fallback_mode;
    if (lineHasCloseLingerReason(application, kLineCloseLingerPeerWriteShutdown))
    {
        lineRequestCloseLinger(carrier, kLineCloseLingerPeerWriteShutdown);
    }
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(carrier), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(carrier), IP_PROTO_UDP);

    if (! enetEndpointStartClient(t, application, carrier))
    {
        /* No association was published and no outward callback ran. */
        lineDestroy(carrier);
        tunnelPrevDownStreamFinish(t, application);
    }
    /* Successful attachment may already have closed either line through reentrant Init. */
}

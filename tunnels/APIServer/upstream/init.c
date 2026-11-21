#include "APIServer/structure.h"

void apiserverUpStreamInit(tunnel_t *t, line_t *line)
{
    address_context_t *destination = lineGetDestinationAddressContext(line);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    if (! apiserverLinestateInitialize(t, line))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    apiserver_lstate_t *ls = lineGetState(line, t);
    if (! apiserverArmTimer(ls))
    {
        apiserverCloseSession(t, line);
        return;
    }
    tunnelPrevDownStreamEst(t, line);
}

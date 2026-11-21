#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelUpStreamInit(tunnel_t *t, line_t *parent_l)
{
    address_context_t *destination = lineGetDestinationAddressContext(parent_l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, parent_l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportTcp);

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, t);
    muxserverLinestateInitialize(t, parent_ls, parent_l, false, 0);
    muxserverScheduleParentStatsLog(t, parent_l);
    tunnelPrevDownStreamEst(t, parent_l);
}

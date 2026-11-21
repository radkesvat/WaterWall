#include "internal.h"

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel == t && ls->phase == kTrojanServerPhaseClosing)
        return;
    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    trojanserverLinestateInitialize(ls, t, l, kTrojanServerLineKindClient);
}

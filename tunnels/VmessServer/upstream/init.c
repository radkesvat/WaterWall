#include "auth.h"
#include "internal.h"

void vmessserverTunnelUpStreamInit(tunnel_t *t, line_t *line)
{
    address_context_t *destination = lineGetDestinationAddressContext(line);
    if (addresscontextSelectTransport(destination, kAddressContextTransportTcp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportTcp);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_TCP);
    vmessserver_lstate_t *ls = lineGetState(line, t);
    vmessserverLinestateInitialize(ls, t, line, kVmessServerLineKindClient);
    if (! vmessserverAuthLineInit(ls))
    {
        vmessserverReason(ls, kVmessServerReasonAdmission);
        vmessserverCloseLineBidirectional(t, line);
    }
}

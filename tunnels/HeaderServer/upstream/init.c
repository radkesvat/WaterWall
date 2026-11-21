#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    headerserver_tstate_t *ts = tunnelGetState(t);
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ts->override_mode != kHeaderServerOverrideModeConstant)
    {
        address_context_t *dest      = lineGetDestinationAddressContext(l);
        const uint8_t      transport = addresscontextSelectTransport(dest, kAddressContextTransportTcp);
        if (transport == 0)
        {
            tunnelLogTransportRefusal(t, dest, kAddressContextTransportTcp);
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        addresscontextSetTransportOffer(dest, transport);
    }

    headerserverLinestateInitialize(ls, l, ts);

    if (ts->override_mode == kHeaderServerOverrideModeConstant)
    {
        addresscontextSetPort(lineGetDestinationAddressContext(l), ts->constant_port);
        headerserverLinestateDestroy(ls);
        tunnelBypassLine(t, l);
        tunnelNextUpStreamInit(t, l);
    }
}

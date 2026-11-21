#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    const speedlimit_tstate_t *ts = tunnelGetState(t);
    if (ts->work_mode == kSpeedLimitWorkModePause && ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        address_context_t *dest      = lineGetDestinationAddressContext(l);
        const uint8_t      transport = addresscontextSelectTransport(dest, kAddressContextTransportTcp);
        if (transport == 0)
        {
            tunnelLogTransportRequirement(t, dest, "TCP for settings.work-mode=pause");
            tunnelPrevDownStreamFinish(t, l);
            return;
        }
        addresscontextSetTransportOffer(dest, transport);
    }
    speedlimit_lstate_t *ls = lineGetState(l, t);
    speedlimitLinestateInitialize(ls, t, l);

    tunnelNextUpStreamInit(t, l);
}

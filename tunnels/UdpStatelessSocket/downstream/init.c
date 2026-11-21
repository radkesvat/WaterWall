#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    if (tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || udpstatelesssocketLinestateOwnsLine(lineGetState(l, t)))
        return;

    address_context_t *destination = lineGetDestinationAddressContext(l);
    if (addresscontextSelectTransport(destination, kAddressContextTransportUdp) == 0)
    {
        LOGW("UdpStatelessSocket: borrowed line does not offer UDP");
        tunnelNextUpStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(destination, kAddressContextTransportUdp);
}

#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpudpconnectorSelectUpStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudpconnector_tstate_t *ts          = tunnelGetState(t);
    address_context_t        *destination = lineGetDestinationAddressContext(l);
    const uint8_t             transport   = addresscontextSelectTransport(destination, kAddressContextTransportBoth);
    if (transport == 0)
        return NULL;

    addresscontextSetTransportOffer(destination, transport);
    return transport == kAddressContextTransportTcp ? tcpconnectorTunnelGetEntryTunnel(ts->tcp_connector)
                                                    : udpconnectorTunnelGetEntryTunnel(ts->udp_connector);
}

tunnel_t *tcpudpconnectorGetSelectedUpStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudpconnector_lstate_t *ls = lineGetState(l, t);

    if (ls->selected_connector == NULL)
    {
        LOGF("TcpUdpConnector: upstream callback received before init selected a connector");
        abortProgramNow(1);
    }

    return ls->selected_connector;
}

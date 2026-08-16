#include "structure.h"

#include "loggers/network_logger.h"

void tcpudpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);

    if (ts->tcp_connector == NULL || ts->udp_connector == NULL)
    {
        LOGF("TcpUdpConnector: internal connector tunnels are not available");
        startupFailureRecord(1);
        return;
    }

    if (t->next != NULL)
    {
        LOGF("TcpUdpConnector: this wrapper is a chain end and must not be bound to a next tunnel");
        startupFailureRecord(1);
        return;
    }

    if ((ts->tcp_connector->prev != NULL && ts->tcp_connector->prev != t) ||
        (ts->udp_connector->prev != NULL && ts->udp_connector->prev != t))
    {
        LOGF("TcpUdpConnector: internal connector tunnels are already bound");
        startupFailureRecord(1);
        return;
    }

    if (ts->tcp_connector->chain != NULL || ts->udp_connector->chain != NULL)
    {
        LOGF("TcpUdpConnector: internal connector tunnels are already in a chain");
        startupFailureRecord(1);
        return;
    }

    tunnelBindDown(t, ts->tcp_connector);
    tunnelBindDown(t, ts->udp_connector);

    tunnelchainInsert(chain, t);
    ts->tcp_connector->onChain(ts->tcp_connector, chain);
    ts->udp_connector->onChain(ts->udp_connector, chain);
}

#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpudplistenerSelectDownStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudplistener_tstate_t *ts      = tunnelGetState(t);
    const address_context_t *src_ctx = lineGetSourceAddressContext(l);
    const address_context_transport_t transport = addresscontextClassifyTransport(src_ctx);

    if (transport == kAddressContextTransportTcp)
    {
        return ts->tcp_listener;
    }

    if (transport == kAddressContextTransportUdp)
    {
        return ts->udp_listener;
    }

    LOGF("TcpUdpListener: expected an exact TCP or UDP source protocol on the accepted line");
    abortProgramNow(1);
}

udplistener_dynamic_provider_t tcpudplistenerGetDynamicProvider(tunnel_t *t)
{
    if (t == NULL)
    {
        return (udplistener_dynamic_provider_t) {0};
    }
    tcpudplistener_tstate_t *ts = tunnelGetState(t);
    if (ts == NULL || ts->udp_listener == NULL)
    {
        return (udplistener_dynamic_provider_t) {0};
    }
    return udplistenerGetDynamicProvider(ts->udp_listener);
}

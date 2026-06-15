#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpudplistenerSelectDownStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudplistener_tstate_t *ts      = tunnelGetState(t);
    const address_context_t *src_ctx = lineGetSourceAddressContext(l);

    if (src_ctx->proto_tcp && ! src_ctx->proto_udp)
    {
        return ts->tcp_listener;
    }

    if (src_ctx->proto_udp && ! src_ctx->proto_tcp)
    {
        return ts->udp_listener;
    }

    LOGF("TcpUdpListener: line has ambiguous or missing source protocol flags (tcp=%u, udp=%u)",
         (unsigned int) src_ctx->proto_tcp,
         (unsigned int) src_ctx->proto_udp);
    terminateProgram(1);
    return NULL;
}

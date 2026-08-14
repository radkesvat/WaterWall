#include "structure.h"

#include "loggers/network_logger.h"

static tunnel_t *tcpudpconnectorSelectFromContext(tcpudpconnector_tstate_t *ts, const address_context_t *ctx)
{
    switch (addresscontextClassifyTransport(ctx))
    {
    case kAddressContextTransportTcp:
        return tcpconnectorTunnelGetEntryTunnel(ts->tcp_connector);
    case kAddressContextTransportUdp:
        return udpconnectorTunnelGetEntryTunnel(ts->udp_connector);
    default:
        return NULL;
    }
}

static void tcpudpconnectorLogUnsupportedContext(const char *label, const address_context_t *ctx)
{
    LOGE("TcpUdpConnector: line has unsupported or ambiguous %s protocol flags "
         "(tcp=%u, udp=%u, icmp=%u, packet=%u)",
         label,
         (unsigned int) ctx->proto_tcp,
         (unsigned int) ctx->proto_udp,
         (unsigned int) ctx->proto_icmp,
         (unsigned int) ctx->proto_packet);
}

tunnel_t *tcpudpconnectorSelectUpStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudpconnector_tstate_t *ts        = tunnelGetState(t);
    const address_context_t  *dest_ctx  = lineGetDestinationAddressContext(l);
    const address_context_t  *src_ctx   = lineGetSourceAddressContext(l);
    tunnel_t                 *connector = NULL;

    if (addresscontextClassifyTransport(dest_ctx) != kAddressContextTransportNone)
    {
        connector = tcpudpconnectorSelectFromContext(ts, dest_ctx);
        if (connector != NULL)
        {
            return connector;
        }

        // metadata of a single line, the caller rejects only that line
        tcpudpconnectorLogUnsupportedContext("destination", dest_ctx);
        return NULL;
    }

    connector = tcpudpconnectorSelectFromContext(ts, src_ctx);
    if (connector != NULL)
    {
        return connector;
    }

    if (addresscontextClassifyTransport(src_ctx) != kAddressContextTransportNone)
    {
        tcpudpconnectorLogUnsupportedContext("source", src_ctx);
    }
    else
    {
        LOGE("TcpUdpConnector: line has no TCP/UDP protocol flags in destination or source context");
    }

    return NULL;
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

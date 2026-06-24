#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpudpconnectorContextHasAnyProtocol(const address_context_t *ctx)
{
    return ctx->proto_tcp || ctx->proto_udp || ctx->proto_icmp || ctx->proto_packet;
}

static tunnel_t *tcpudpconnectorSelectFromContext(tcpudpconnector_tstate_t *ts, const address_context_t *ctx)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        return tcpconnectorTunnelGetEntryTunnel(ts->tcp_connector);
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        return udpconnectorTunnelGetEntryTunnel(ts->udp_connector);
    }

    return NULL;
}

static void tcpudpconnectorLogUnsupportedContext(const char *label, const address_context_t *ctx)
{
    LOGF("TcpUdpConnector: line has unsupported or ambiguous %s protocol flags "
         "(tcp=%u, udp=%u, icmp=%u, packet=%u)",
         label,
         (unsigned int) ctx->proto_tcp,
         (unsigned int) ctx->proto_udp,
         (unsigned int) ctx->proto_icmp,
         (unsigned int) ctx->proto_packet);
}

tunnel_t *tcpudpconnectorSelectUpStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudpconnector_tstate_t *ts       = tunnelGetState(t);
    const address_context_t *dest_ctx  = lineGetDestinationAddressContext(l);
    const address_context_t *src_ctx   = lineGetSourceAddressContext(l);
    tunnel_t                *connector = NULL;

    if (tcpudpconnectorContextHasAnyProtocol(dest_ctx))
    {
        connector = tcpudpconnectorSelectFromContext(ts, dest_ctx);
        if (connector != NULL)
        {
            return connector;
        }

        tcpudpconnectorLogUnsupportedContext("destination", dest_ctx);
        terminateProgram(1);
        return NULL;
    }

    connector = tcpudpconnectorSelectFromContext(ts, src_ctx);
    if (connector != NULL)
    {
        return connector;
    }

    if (tcpudpconnectorContextHasAnyProtocol(src_ctx))
    {
        tcpudpconnectorLogUnsupportedContext("source", src_ctx);
    }
    else
    {
        LOGF("TcpUdpConnector: line has no TCP/UDP protocol flags in destination or source context");
    }
    terminateProgram(1);
    return NULL;
}

tunnel_t *tcpudpconnectorGetSelectedUpStreamTunnel(tunnel_t *t, line_t *l)
{
    tcpudpconnector_lstate_t *ls = lineGetState(l, t);

    if (ls->selected_connector == NULL)
    {
        LOGF("TcpUdpConnector: upstream callback received before init selected a connector");
        terminateProgram(1);
    }

    return ls->selected_connector;
}

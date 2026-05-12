#include "structure.h"

#include "loggers/network_logger.h"

LWIP_MEMPOOL_DECLARE(RX_POOL, 10, sizeof(my_custom_pbuf_t), "Zero-copy RX PBUF pool")

static void my_pbuf_free_custom(struct pbuf *p)
{
    my_custom_pbuf_t *custombuf = (my_custom_pbuf_t *) p;

    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), custombuf->sbuf);
    LWIP_MEMPOOL_FREE(RX_POOL, custombuf);
}

static void passToTcpIp(sbuf_t *buf, struct netif *inp)
{
    my_custom_pbuf_t *custombuf = (my_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);
    if (custombuf == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        return;
    }

    custombuf->p.custom_free_function = my_pbuf_free_custom;
    custombuf->sbuf                   = buf;

    struct pbuf *p = pbuf_alloced_custom(
        PBUF_RAW, sbufGetLength(buf), PBUF_REF, &custombuf->p, sbufGetMutablePtr(buf), sbufGetLength(buf));
    if (p == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
        LWIP_MEMPOOL_FREE(RX_POOL, custombuf);
        return;
    }

    if (inp->input(p, inp) != ERR_OK)
    {
        pbuf_free(p);
    }
}

static bool ptcValidateIpv4Packet(const sbuf_t *buf, const struct ip_hdr *iphdr)
{
    const uint32_t packet_len = sbufGetLength(buf);

    if (UNLIKELY(packet_len < sizeof(struct ip_hdr) || IPH_V(iphdr) != 4))
    {
        return false;
    }

    const uint32_t header_len = IPH_HL_BYTES(iphdr);
    if (UNLIKELY(header_len < sizeof(struct ip_hdr) || header_len > packet_len))
    {
        return false;
    }

    const uint32_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (UNLIKELY(total_len < header_len || total_len > packet_len))
    {
        return false;
    }

    return true;
}

static bool ptcPacketHasTransportHeader(const sbuf_t *buf, const struct ip_hdr *iphdr, uint32_t min_transport_len)
{
    const uint32_t header_len = IPH_HL_BYTES(iphdr);
    return sbufGetLength(buf) >= header_len + min_transport_len;
}

static void processV4(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(buf);
    ip_addr_t      dest_ip;

    if (! ptcValidateIpv4Packet(buf, iphdr))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const uint16_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (UNLIKELY(sbufGetLength(buf) != total_len))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP && IPH_PROTO(iphdr) != IP_PROTO_UDP)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    ipAddrCopyFromIp4(dest_ip, iphdr->dest);

    if (IPH_PROTO(iphdr) == IP_PROTO_UDP && ptcPacketHasTransportHeader(buf, iphdr, sizeof(struct udp_hdr)))
    {
        struct udp_hdr *udphdr = (struct udp_hdr *) ((uint8_t *) iphdr + IPH_HL_BYTES(iphdr));

        if (ptcFakeDnsHandleIpv4UdpPacket(t, l, buf, iphdr, udphdr))
        {
            return;
        }
    }

    interface_route_context_t *route_ctx = ptcFindOrCreateRouteContextV4(t, lineGetWID(l), &dest_ip.u_addr.ip4);
    if (route_ctx == NULL)
    {
        LOGW("PacketsToConnection: failed to create virtual netif for destination");
        lineReuseBuffer(l, buf);
        return;
    }

    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP:
        if (ptcEnsureTcpListener(route_ctx, t, &dest_ip, 0) != ERR_OK)
        {
            LOGW("PacketsToConnection: failed to create pretend TCP gateway");
            lineReuseBuffer(l, buf);
            return;
        }
        break;

    case IP_PROTO_UDP:
        if (ptcEnsureUdpListener(route_ctx, t, &dest_ip, 0) != ERR_OK)
        {
            LOGW("PacketsToConnection: failed to create pretend UDP gateway");
            lineReuseBuffer(l, buf);
            return;
        }
        break;

    default:
        lineReuseBuffer(l, buf);
        return;
    }

    passToTcpIp(buf, &route_ctx->netif);
}

void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (UNLIKELY(sbufGetLength(buf) < 1))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(iphdr) == 4)
    {
        LOCK_TCPIP_CORE();
        processV4(t, l, buf);
        UNLOCK_TCPIP_CORE();
        return;
    }

    lineReuseBuffer(l, buf);
}

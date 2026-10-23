#include "fake_dns_internal.h"

#include "loggers/dns_logger.h"

bool ptcFakeDnsOwnsDestination(tunnel_t *t, const ip4_addr_p_t *dest)
{
    const ptc_fake_dns_t *dns = &((ptc_tstate_t *) tunnelGetState(t))->fake_dns;

    return dns->enabled && dest->addr == dns->listen_addr.addr;
}

ptc_fake_dns_result_t ptcFakeDnsHandleIpv4UdpPacket(tunnel_t *t, line_t *packet_line, sbuf_t *buf,
                                                    const struct ip_hdr *iphdr, const struct udp_hdr *udphdr)
{
    ptc_tstate_t   *ts  = tunnelGetState(t);
    ptc_fake_dns_t *dns = &ts->fake_dns;

    if (! dns->enabled || iphdr->dest.addr != dns->listen_addr.addr || lwip_ntohs(udphdr->dest) != dns->listen_port)
    {
        return (ptc_fake_dns_result_t) {0};
    }

    uint32_t ip_header_len = IPH_HL_BYTES(iphdr);
    uint32_t ip_total_len  = lwip_ntohs(IPH_LEN(iphdr));
    uint32_t udp_len       = lwip_ntohs(udphdr->len);

    const bool trusted = packettunnelTrustedReceiveChecksumsActive(t);

    if (udp_len < UDP_HLEN || ip_header_len + udp_len != ip_total_len ||
        (! trusted && inet_chksum(iphdr, (u16_t) ip_header_len) != 0))
    {
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    if (! trusted && udphdr->chksum != 0)
    {
        struct pbuf udp_packet = {
            .next    = NULL,
            .payload = (void *) udphdr,
            .tot_len = (u16_t) udp_len,
            .len     = (u16_t) udp_len,
            .ref     = 1,
        };
        const ip4_addr_t source      = {.addr = iphdr->src.addr};
        const ip4_addr_t destination = {.addr = iphdr->dest.addr};

        if (inet_chksum_pseudo(&udp_packet, IP_PROTO_UDP, (u16_t) udp_len, &source, &destination) != 0)
        {
            lineReuseBuffer(packet_line, buf);
            return (ptc_fake_dns_result_t) {.handled = true};
        }
    }

    const uint8_t *dns_query     = ((const uint8_t *) udphdr) + UDP_HLEN;
    uint32_t       dns_query_len = udp_len - UDP_HLEN;
    uint32_t       max_dns_len   = dns_query_len + ((uint32_t) kPtcDnsMaxQuestions * kPtcDnsAnswerALen);

    if (max_dns_len > UINT16_MAX - UDP_HLEN)
    {
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    buffer_pool_t  *pool       = lineGetBufferPool(packet_line);
    uint32_t        packet_cap = UDP_HLEN + max_dns_len;
    sbuf_t         *response   = bufferpoolGetBestFit(pool, packet_cap, bufferpoolGetLargeBufferPadding(pool));
    uint8_t        *packet     = sbufGetMutablePtr(response);
    struct udp_hdr *rudp       = (struct udp_hdr *) packet;
    uint8_t        *rdns       = packet + UDP_HLEN;

    int dns_response_len = ptcFakeDnsBuildResponse(ts, dns_query, dns_query_len, rdns, max_dns_len);
    if (dns_response_len < 0)
    {
        bufferpoolReuseBuffer(pool, response);
        lineReuseBuffer(packet_line, buf);
        return (ptc_fake_dns_result_t) {.handled = true};
    }

    uint32_t response_len = UDP_HLEN + (uint32_t) dns_response_len;
    sbufSetLength(response, response_len);
    memoryZero(packet, UDP_HLEN);

    rudp->src  = udphdr->dest;
    rudp->dest = udphdr->src;
    rudp->len  = lwip_htons((uint16_t) (UDP_HLEN + (uint32_t) dns_response_len));

    const ip4_addr_t source      = {.addr = iphdr->dest.addr};
    const ip4_addr_t destination = {.addr = iphdr->src.addr};
    struct pbuf      udp_packet  = {
              .next    = NULL,
              .payload = packet,
              .tot_len = (u16_t) response_len,
              .len     = (u16_t) response_len,
              .ref     = 1,
    };
    /* PublishResponse uses ip4_output_if without options and the route's
     * immutable instance MTU. Complete oversized replies before fragmentation. */
    if (! packettunnelTrustedChecksumsActive(t) || response_len + IP_HLEN > ts->mtu)
    {
        rudp->chksum = inet_chksum_pseudo(&udp_packet, IP_PROTO_UDP, (u16_t) response_len, &source, &destination);
        if (rudp->chksum == 0)
        {
            rudp->chksum = 0xFFFF;
        }
    }

    lineReuseBuffer(packet_line, buf);
    return (ptc_fake_dns_result_t) {
        .response    = response,
        .source      = source,
        .destination = destination,
        .handled     = true,
    };
}

/*
 * Publishes one fake-DNS reply through the worker netif's MTU-aware IPv4 path.
 *
 * The reply is one variable-length UDP datagram. Its echoed question names and
 * answer records can exceed the configured IPv4 MTU, so publication uses the
 * netif's fragmentation path rather than emitting an oversized raw packet.
 *
 * Going through ip4_output_if() makes lwIP construct the IPv4 header, allocate
 * the identification value, and apply MTU fragmentation. It is safe
 * inside the owner engine because netif output detaches packet bytes and only invokes a
 * certified enqueue-only packet sink inline; arbitrary neighbours stay queued.
 *
 * Consumes `response` on every path. A copied PBUF_RAM owns the datagram through
 * the complete IPv4 output loop. Once it returns, each queued output owns its
 * detached bytes, and the pbuf and original response are released here.
 */
bool ptcFakeDnsPublishResponseLocked(tunnel_t *t, line_t *packet_line, sbuf_t *response, const ip4_addr_t *source,
                                     const ip4_addr_t *destination)
{
    buffer_pool_t             *pool      = lineGetBufferPool(packet_line);
    interface_route_context_t *route_ctx = ptcFindOrCreateRouteContextV4(t, lineGetWID(packet_line));

    if (UNLIKELY(route_ctx == NULL))
    {
        bufferpoolReuseBuffer(pool, response);
        return false;
    }

    const uint32_t response_len = sbufGetLength(response);
    struct pbuf   *p            = pbuf_alloc(PBUF_IP, (u16_t) response_len, PBUF_RAM);

    if (UNLIKELY(p == NULL || pbuf_take(p, sbufGetRawPtr(response), (u16_t) response_len) != ERR_OK))
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        bufferpoolReuseBuffer(pool, response);
        return false;
    }

    struct netif *netif  = &route_ctx->netif;
    const err_t   result = ip4_output_if(p, source, destination, UDP_TTL, 0, IP_PROTO_UDP, netif);

    pbuf_free(p);
    bufferpoolReuseBuffer(pool, response);
    return result == ERR_OK;
}

#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kVlessVersion    = 0x00,
    kVlessCmdTcp     = 0x01,
    kVlessCmdUdp     = 0x02,
    kVlessAtypIpv4   = 0x01,
    kVlessAtypDomain = 0x02,
    kVlessAtypIpv6   = 0x03
};

static bool vlessclientAddressLength(const address_context_t *ctx, uint32_t *len_out)
{
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            *len_out = 2 + 1 + 4;
            return true;
        }

        if (addresscontextIsIpv6(ctx))
        {
            *len_out = 2 + 1 + 16;
            return true;
        }

        return false;
    }

    if (addresscontextIsDomain(ctx) && ctx->domain_len > 0)
    {
        *len_out = 2U + 1U + 1U + (uint32_t) ctx->domain_len;
        return true;
    }

    return false;
}

static bool vlessclientWriteDestination(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    if (UNLIKELY(! addresscontextHasPort(ctx)))
    {
        return false;
    }

    uint16_t port_be = htobe16(ctx->port);
    memoryCopy(ptr + *offset, &port_be, sizeof(port_be));
    *offset += sizeof(port_be);

    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            ptr[(*offset)++] = kVlessAtypIpv4;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
            *offset += 4;
            return true;
        }

        if (addresscontextIsIpv6(ctx))
        {
            ptr[(*offset)++] = kVlessAtypIpv6;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip6, 16);
            *offset += 16;
            return true;
        }

        return false;
    }

    if (addresscontextIsDomain(ctx) && ctx->domain_len > 0)
    {
        ptr[(*offset)++] = kVlessAtypDomain;
        ptr[(*offset)++] = ctx->domain_len;
        memoryCopy(ptr + *offset, ctx->domain, ctx->domain_len);
        *offset += ctx->domain_len;
        return true;
    }

    return false;
}

static uint8_t protocolToCommand(vlessclient_protocol_t protocol)
{
    assert(protocol == kVlessClientProtocolTcp || protocol == kVlessClientProtocolUdp);
    return protocol == kVlessClientProtocolUdp ? kVlessCmdUdp : kVlessCmdTcp;
}

static bool getProtocolFromContext(const address_context_t *ctx, vlessclient_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolUdp;
        return true;
    }

    return false;
}

static vlessclient_protocol_t resolveConfiguredProtocol(const vlessclient_tstate_t *ts,
                                                        const address_context_t    *current_dest_ctx)
{
    if (ts->protocol != kVlessClientProtocolDestContext)
    {
        return ts->protocol;
    }

    vlessclient_protocol_t protocol = kVlessClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("VlessClient: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kVlessClientProtocolTcp;
}

bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    vlessclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t     current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kVlessClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextCopy(&current, dest_ctx);
    }

    vlessclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("VlessClient: configured to use dest_context->address, but line destination address is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextCopy(dest_ctx, &current);
    }

    if (ts->target_port_source == kDvsConstant)
    {
        addresscontextSetPort(dest_ctx, ts->target_addr.port);
    }
    else
    {
        if (UNLIKELY(current.port == 0))
        {
            LOGE("VlessClient: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kVlessClientProtocolTcp)
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_TCP);
    }
    else
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    }

    if (uses_current_dest)
    {
        addresscontextReset(&current);
    }

    if (ts->resolve_domains)
    {
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
    }
    return true;
}

/* Takes ownership of body on every result; first output is always ordinary. */
bool vlessclientSendInitialRequest(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *body)
{
    vlessclient_tstate_t    *ts       = tunnelGetState(t);
    const address_context_t *target   = &ls->target_addr;
    uint32_t                 addr_len = 0;
    if (UNLIKELY(! vlessclientAddressLength(target, &addr_len) || ! addresscontextHasPort(target)))
    {
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    uint32_t       body_len       = body == NULL ? 0 : sbufGetLength(body);
    uint32_t       header_len     = 1U + kVlessClientUuidLen + 2U + addr_len;
    uint32_t       udp_header_len = body != NULL && ls->protocol == kVlessClientProtocolUdp ? 2U : 0U;
    uint64_t       total          = (uint64_t) header_len + udp_header_len + body_len;
    buffer_pool_t *pool           = lineGetBufferPool(l);
    uint16_t       padding        = bufferpoolGetLargeBufferPadding(pool);
    sbuf_t        *buf            = bufferpoolTryGetBestFit(pool, total, padding);
    if (UNLIKELY(buf == NULL))
    {
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;
    ptr[off++]   = kVlessVersion;
    memoryCopy(ptr + off, ts->uuid, kVlessClientUuidLen);
    off += kVlessClientUuidLen;
    ptr[off++]   = 0;
    ptr[off++]   = protocolToCommand(ls->protocol);
    bool written = vlessclientWriteDestination(ptr, target, &off);
    assert(written);
    discard written;
    if (udp_header_len != 0)
    {
        uint16_t length = htobe16((uint16_t) body_len);
        memoryCopy(ptr + off, &length, sizeof(length));
        off += sizeof(length);
    }
    sbufSetLength(buf, (uint32_t) off);
    if (body != NULL)
    {
        buf = sbufMoveRangeTo(pool, body, buf, body_len, (uint32_t) total, padding);
        lineReuseBuffer(l, body);
    }
    vlessclientCancelFirstPayloadTimer(ls);
    ls->request_sent = true;
    tunnelNextUpStreamPayload(t, l, buf);
    return true;
}

void vlessclientWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    assert(payload > 0 && payload <= kVlessClientUdpMaxPacket);
    if (UNLIKELY(sbufGetLeftCapacity(buf) < kVlessClientUdpHeaderLen))
    {
        buffer_pool_t *pool    = lineGetBufferPool(l);
        uint16_t       padding = max(bufferpoolGetLargeBufferPadding(pool), kVlessClientUdpHeaderLen);
        sbuf_t        *wrapped = sbufIsSplice(buf) ? bufferpoolGetSpliceBuffer(pool) : NULL;
        if (wrapped != NULL && sbufGetLeftCapacity(wrapped) < padding)
        {
            bufferpoolReuseBuffer(pool, wrapped);
            wrapped = NULL;
        }
        wrapped = sbufMoveRangeTo(pool, buf, wrapped, payload, payload, padding);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    sbufShiftLeft(buf, kVlessClientUdpHeaderLen);
    uint16_t length = htobe16((uint16_t) payload);
    memoryCopy(sbufGetMutablePtr(buf), &length, sizeof(length));
    *buf_io = buf;
}

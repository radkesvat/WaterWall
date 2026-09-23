#include "structure.h"

#include "loggers/network_logger.h"

static bool trojanclientWriteAddress(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            ptr[(*offset)++] = kTrojanAtypIpv4;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
            *offset += 4;
        }
        else if (addresscontextIsIpv6(ctx))
        {
            ptr[(*offset)++] = kTrojanAtypIpv6;
            memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip6, 16);
            *offset += 16;
        }
        else
        {
            return false;
        }
    }
    else if (addresscontextIsDomain(ctx))
    {
        ptr[(*offset)++] = kTrojanAtypDomain;
        ptr[(*offset)++] = ctx->domain_len;
        memoryCopy(ptr + *offset, ctx->domain, ctx->domain_len);
        *offset += ctx->domain_len;
    }
    else
    {
        return false;
    }

    uint16_t port_be = htobe16(ctx->port);
    memoryCopy(ptr + *offset, &port_be, sizeof(port_be));
    *offset += sizeof(port_be);
    return true;
}

static bool trojanclientAddressLength(const address_context_t *ctx, uint32_t *len_out)
{
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            *len_out = 1 + 4 + 2;
            return true;
        }

        if (addresscontextIsIpv6(ctx))
        {
            *len_out = 1 + 16 + 2;
            return true;
        }

        return false;
    }

    if (addresscontextIsDomain(ctx))
    {
        *len_out = 1U + 1U + (uint32_t) ctx->domain_len + 2U;
        return true;
    }

    return false;
}

static uint8_t protocolToCommand(trojanclient_protocol_t protocol)
{
    assert(protocol == kTrojanClientProtocolTcp || protocol == kTrojanClientProtocolUdp);
    return protocol == kTrojanClientProtocolUdp ? kTrojanCommandUdpAssociate : kTrojanCommandConnect;
}

static bool getProtocolFromContext(const address_context_t *ctx, trojanclient_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kTrojanClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kTrojanClientProtocolUdp;
        return true;
    }

    return false;
}

static trojanclient_protocol_t resolveConfiguredProtocol(const trojanclient_tstate_t *ts,
                                                         const address_context_t     *current_dest_ctx)
{
    if (ts->protocol != kTrojanClientProtocolDestContext)
    {
        return ts->protocol;
    }

    trojanclient_protocol_t protocol = kTrojanClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("TrojanClient: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kTrojanClientProtocolTcp;
}

static void fillUdpAssociateRequestTarget(address_context_t *target)
{
    discard addresscontextSetIpAddressPort(target, "0.0.0.0", 0);
    addresscontextSetOnlyProtocol(target, IP_PROTO_UDP);
}

bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t      current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kTrojanClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextCopy(&current, dest_ctx);
    }

    trojanclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("TrojanClient: configured to use dest_context->address, but line destination address is not set");
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
            LOGE("TrojanClient: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kTrojanClientProtocolTcp)
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

/* Takes ownership of body on every result. No callback occurs until the whole
 * request and eligible first payload occupy one ordinary, onward-padded buffer. */
bool trojanclientSendInitialRequest(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *body)
{
    trojanclient_tstate_t   *ts           = tunnelGetState(t);
    address_context_t        assoc_target = {0};
    const address_context_t *target       = &ls->target_addr;
    uint32_t                 addr_len = 0, udp_addr_len = 0;
    if (ls->protocol == kTrojanClientProtocolUdp)
    {
        fillUdpAssociateRequestTarget(&assoc_target);
        target = &assoc_target;
    }
    if (UNLIKELY(! trojanclientAddressLength(target, &addr_len) ||
                 (body != NULL && ls->protocol == kTrojanClientProtocolUdp &&
                  ! trojanclientAddressLength(&ls->target_addr, &udp_addr_len))))
    {
        addresscontextReset(&assoc_target);
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    uint32_t       body_len       = body == NULL ? 0 : sbufGetLength(body);
    uint32_t       header_len     = kTrojanClientPasswordHexLen + 5U + addr_len;
    uint32_t       udp_header_len = udp_addr_len == 0 ? 0 : udp_addr_len + 4U;
    uint64_t       total          = (uint64_t) header_len + udp_header_len + body_len;
    buffer_pool_t *pool           = lineGetBufferPool(l);
    uint16_t       padding        = bufferpoolGetLargeBufferPadding(pool);
    sbuf_t        *buf            = bufferpoolTryGetBestFit(pool, total, padding);
    if (UNLIKELY(buf == NULL))
    {
        addresscontextReset(&assoc_target);
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;
    memoryCopy(ptr, ts->password_hex, kTrojanClientPasswordHexLen);
    off += kTrojanClientPasswordHexLen;
    ptr[off++]   = '\r';
    ptr[off++]   = '\n';
    ptr[off++]   = protocolToCommand(ls->protocol);
    bool written = trojanclientWriteAddress(ptr, target, &off);
    assert(written);
    discard written;
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    if (udp_header_len != 0)
    {
        written = trojanclientWriteAddress(ptr, &ls->target_addr, &off);
        assert(written);
        uint16_t length = htobe16((uint16_t) body_len);
        memoryCopy(ptr + off, &length, sizeof(length));
        off += sizeof(length);
        ptr[off++] = '\r';
        ptr[off++] = '\n';
    }
    addresscontextReset(&assoc_target);
    sbufSetLength(buf, (uint32_t) off);
    if (body != NULL)
    {
        buf = sbufMoveRangeTo(pool, body, buf, body_len, (uint32_t) total, padding);
        lineReuseBuffer(l, body);
    }
    trojanclientCancelFirstPayloadTimer(ls);
    ls->request_sent = true;
    tunnelNextUpStreamPayload(t, l, buf);
    return true;
}

bool trojanclientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    uint32_t addr_len;

    if (UNLIKELY(payload > kTrojanClientUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(! trojanclientAddressLength(target, &addr_len)))
    {
        return false;
    }

    uint32_t header_len = addr_len + 2U + kTrojanClientCrlfLen;

    if (sbufGetLeftCapacity(buf) < header_len)
    {
        buffer_pool_t *pool    = lineGetBufferPool(l);
        uint16_t       padding = max(bufferpoolGetLargeBufferPadding(pool), kTrojanClientUdpHeaderMaxLen);
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
    sbufShiftLeft(buf, header_len);

    *buf_io = buf;

    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;

    if (UNLIKELY(! trojanclientWriteAddress(ptr, target, &off)))
    {
        return false;
    }

    uint16_t payload_be = htobe16((uint16_t) payload);
    memoryCopy(ptr + off, &payload_be, sizeof(payload_be));
    off += sizeof(payload_be);
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    return true;
}

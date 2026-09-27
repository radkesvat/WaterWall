#include "internal.h"

static bool trojanclientAddressFromContext(const address_context_t *ctx, trojanclient_address_t *out)
{
    trojanclient_address_t value = {.port = ctx->port};
    if (addresscontextIsIpType(ctx))
    {
        if (! addresscontextIsIpv4(ctx) && ! addresscontextIsIpv6(ctx))
            return false;
        value.kind   = addresscontextIsIpv4(ctx) ? kTrojanClientAddressIpv4 : kTrojanClientAddressIpv6;
        value.length = addresscontextIsIpv4(ctx) ? 4 : 16;
        memoryCopy(value.bytes,
                   addresscontextIsIpv4(ctx) ? (const void *) &ctx->ip_address.u_addr.ip4.addr
                                             : (const void *) &ctx->ip_address.u_addr.ip6,
                   value.length);
    }
    else if (addresscontextIsDomain(ctx))
    {
        value.kind   = kTrojanClientAddressDomain;
        value.length = ctx->domain_len;
        memoryCopy(value.bytes, ctx->domain, value.length);
    }
    else
        return false;
    *out = value;
    return true;
}

static bool trojanclientWriteAddress(uint8_t *ptr, size_t capacity, const address_context_t *ctx, size_t *offset)
{
    trojanclient_address_t value;
    size_t                 written;
    if (! trojanclientAddressFromContext(ctx, &value) || *offset > capacity ||
        ! trojanclientAddressEncode(&value, ptr + *offset, capacity - *offset, &written))
        return false;
    *offset += written;
    return true;
}

static bool trojanclientAddressLength(const address_context_t *ctx, uint32_t *len_out)
{
    trojanclient_address_t value;
    if (! trojanclientAddressFromContext(ctx, &value))
        return false;
    *len_out = (uint32_t) trojanclientAddressEncodedLength(&value);
    return true;
}

static uint8_t protocolToCommand(trojanclient_protocol_t protocol)
{
    assert(protocol == kTrojanClientProtocolTcp || protocol == kTrojanClientProtocolUdp);
    return protocol == kTrojanClientProtocolUdp ? kTrojanCommandUdpAssociate : kTrojanCommandConnect;
}

static void fillUdpAssociateRequestTarget(address_context_t *target)
{
    discard addresscontextSetIpAddressPort(target, "0.0.0.0", 0);
    addresscontextSetOnlyProtocol(target, IP_PROTO_UDP);
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
    bool reuse_body = body != NULL && ! sbufIsSplice(body) && sbufGetLeftCapacity(body) >= header_len + udp_header_len;
    sbuf_t *buf     = reuse_body ? body : bufferpoolTryGetBestFit(pool, total, padding);
    if (UNLIKELY(buf == NULL))
    {
        addresscontextReset(&assoc_target);
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    if (reuse_body)
        sbufShiftLeft(buf, header_len + udp_header_len);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;
    memoryCopy(ptr, ts->password_hex, kTrojanClientPasswordHexLen);
    off += kTrojanClientPasswordHexLen;
    ptr[off++]   = '\r';
    ptr[off++]   = '\n';
    ptr[off++]   = protocolToCommand(ls->protocol);
    bool written = trojanclientWriteAddress(ptr, header_len, target, &off);
    assert(written);
    discard written;
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    if (udp_header_len != 0)
    {
        written = trojanclientWriteAddress(ptr, header_len + udp_header_len, &ls->target_addr, &off);
        assert(written);
        uint16_t length = htobe16((uint16_t) body_len);
        memoryCopy(ptr + off, &length, sizeof(length));
        off += sizeof(length);
        ptr[off++] = '\r';
        ptr[off++] = '\n';
    }
    addresscontextReset(&assoc_target);
    if (! reuse_body)
    {
        sbufSetLength(buf, (uint32_t) off);
        if (body != NULL)
        {
            buf = sbufMoveRangeTo(pool, body, buf, body_len, (uint32_t) total, padding);
            lineReuseBuffer(l, body);
        }
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

    if (UNLIKELY(! trojanclientWriteAddress(ptr, header_len, target, &off)))
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

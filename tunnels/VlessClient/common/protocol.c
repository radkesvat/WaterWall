#include "internal.h"

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
    bool reuse_body = body != NULL && ! sbufIsSplice(body) && sbufGetLeftCapacity(body) >= header_len + udp_header_len;
    sbuf_t *buf     = reuse_body ? body : bufferpoolTryGetBestFit(pool, total, padding);
    if (UNLIKELY(buf == NULL))
    {
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    if (reuse_body)
        sbufShiftLeft(buf, header_len + udp_header_len);
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
    if (! reuse_body)
    {
        sbufSetLength(buf, (uint32_t) off);
        if (body != NULL)
        {
            buf = sbufMoveRangeTo(pool, body, buf, body_len, (uint32_t) total, padding);
            lineReuseBuffer(l, body);
        }
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

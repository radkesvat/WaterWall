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

/* Target preparation validates the address before Init snapshots it for this line. */
static uint32_t vlessclientAddressLength(const address_context_t *ctx)
{
    if (addresscontextIsIpv4(ctx))
    {
        return 2 + 1 + 4;
    }
    if (addresscontextIsIpv6(ctx))
    {
        return 2 + 1 + 16;
    }
    assert(addresscontextIsDomain(ctx));
    return 2U + 1U + 1U + (uint32_t) ctx->domain_len;
}

/* The request uses the destination validated and saved during target preparation. */
static void vlessclientWriteDestination(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    assert(addresscontextHasPort(ctx));

    uint16_t port_be = htobe16(ctx->port);
    memoryCopy(ptr + *offset, &port_be, sizeof(port_be));
    *offset += sizeof(port_be);

    if (addresscontextIsIpv4(ctx))
    {
        ptr[(*offset)++] = kVlessAtypIpv4;
        memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
        *offset += 4;
        return;
    }
    if (addresscontextIsIpv6(ctx))
    {
        ptr[(*offset)++] = kVlessAtypIpv6;
        memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip6, 16);
        *offset += 16;
        return;
    }
    assert(addresscontextIsDomain(ctx));
    ptr[(*offset)++] = kVlessAtypDomain;
    ptr[(*offset)++] = ctx->domain_len;
    memoryCopy(ptr + *offset, ctx->domain, ctx->domain_len);
    *offset += ctx->domain_len;
}

/* Takes ownership of body on every result; first output is always ordinary. */
bool vlessclientSendInitialRequest(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *body)
{
    vlessclient_tstate_t    *ts       = tunnelGetState(t);
    const address_context_t *target   = &ls->target_addr;
    assert(ls->kind == kVlessClientLineKindDirect || ls->kind == kVlessClientLineKindUdpCarrier);
    uint32_t       addr_len       = vlessclientAddressLength(target);
    uint32_t       body_len       = body == NULL ? 0 : sbufGetLength(body);
    uint32_t       header_len     = 1U + kVlessClientUuidLen + 2U + addr_len;
    uint32_t       udp_header_len =
        body != NULL && ls->kind == kVlessClientLineKindUdpCarrier ? kVlessClientUdpHeaderLen : 0U;
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
    ptr[off++]   = ls->kind == kVlessClientLineKindUdpCarrier ? kVlessCmdUdp : kVlessCmdTcp;
    vlessclientWriteDestination(ptr, target, &off);
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
    /* A peer response may already be complete. Retire before handoff only if
     * no outer receive batch still owns parser/order state. */
    vlessclientTryBypass(t, l, ls);
    tunnelNextUpStreamPayload(t, l, buf);
    return true;
}

void vlessclientWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    assert(payload <= kVlessClientUdpMaxPacket);
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

#include "internal.h"

static bool trojanclientAddressFromContext(const address_context_t *ctx, trojanclient_address_t *out)
{
    trojanclient_address_t value = {.port = ctx->port};
    if (addresscontextIsIpv4(ctx))
    {
        value.kind   = kTrojanClientAddressIpv4;
        value.length = 4;
        memoryCopy(value.bytes, &ctx->ip_address.u_addr.ip4.addr, value.length);
    }
    else if (addresscontextIsIpv6(ctx))
    {
        value.kind   = kTrojanClientAddressIpv6;
        value.length = 16;
        memoryCopy(value.bytes, &ctx->ip_address.u_addr.ip6, value.length);
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

/* The caller has validated the address and reserved its complete encoded length. */
static void trojanclientWriteAddress(uint8_t *ptr, size_t capacity, const trojanclient_address_t *address,
                                     size_t *offset)
{
    assert(*offset <= capacity);
    size_t written = 0;
    bool   encoded = trojanclientAddressEncode(address, ptr + *offset, capacity - *offset, &written);
    assert(encoded);
    discard encoded;
    *offset += written;
}

static uint8_t protocolToCommand(trojanclient_protocol_t protocol)
{
    assert(protocol == kTrojanClientProtocolTcp || protocol == kTrojanClientProtocolUdp);
    return protocol == kTrojanClientProtocolUdp ? kTrojanCommandUdpAssociate : kTrojanCommandConnect;
}

/* Takes ownership of body on every result. No callback occurs until the whole
 * request and eligible first payload occupy one ordinary, onward-padded buffer. */
bool trojanclientSendInitialRequest(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *body)
{
    trojanclient_tstate_t *ts  = tunnelGetState(t);
    bool                   udp = ls->protocol == kTrojanClientProtocolUdp;
    /* UDP association requests use 0.0.0.0:0; datagrams carry the real target. */
    trojanclient_address_t request_target = {.kind = kTrojanClientAddressIpv4, .length = 4};
    trojanclient_address_t udp_target     = {0};
    if (UNLIKELY((! udp && ! trojanclientAddressFromContext(&ls->target_addr, &request_target)) ||
                 (udp && body != NULL && ! trojanclientAddressFromContext(&ls->target_addr, &udp_target))))
    {
        if (body != NULL)
            lineReuseBuffer(l, body);
        return false;
    }
    uint32_t       addr_len       = (uint32_t) trojanclientAddressEncodedLength(&request_target);
    uint32_t       udp_addr_len   = udp && body != NULL ? (uint32_t) trojanclientAddressEncodedLength(&udp_target) : 0;
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
    trojanclientWriteAddress(ptr, header_len, &request_target, &off);
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    if (udp_header_len != 0)
    {
        trojanclientWriteAddress(ptr, header_len + udp_header_len, &udp_target, &off);
        uint16_t length = htobe16((uint16_t) body_len);
        memoryCopy(ptr + off, &length, sizeof(length));
        off += sizeof(length);
        ptr[off++] = '\r';
        ptr[off++] = '\n';
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
    if (ls->kind == kTrojanClientLineKindDirect)
    {
        /* The complete TCP request is ready. Release setup state before the
         * handoff so nested callbacks use the transparent path immediately. */
        trojanclientLinestateDestroy(ls);
        tunnelBypassLine(t, l);
    }
    else
    {
        firstPayloadWindowCancel(&ls->first_payload);
        ls->request_sent = true;
    }
    tunnelNextUpStreamPayload(t, l, buf);
    return true;
}

bool trojanclientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    assert(payload <= kTrojanClientUdpMaxPacket);

    trojanclient_address_t address;
    if (UNLIKELY(! trojanclientAddressFromContext(target, &address)))
    {
        return false;
    }

    uint32_t header_len = (uint32_t) trojanclientAddressEncodedLength(&address) + 2U + kTrojanClientCrlfLen;

    if (sbufGetLeftCapacity(buf) < header_len)
    {
        buf = sbufEnsureLeftCapacity(lineGetBufferPool(l), buf, kTrojanClientUdpHeaderMaxLen);
    }
    sbufShiftLeft(buf, header_len);

    *buf_io = buf;

    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;

    trojanclientWriteAddress(ptr, header_len, &address, &off);

    uint16_t payload_be = htobe16((uint16_t) payload);
    memoryCopy(ptr + off, &payload_be, sizeof(payload_be));
    off += sizeof(payload_be);
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    return true;
}

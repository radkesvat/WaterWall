#include "internal.h"

#include "loggers/network_logger.h"

sbuf_t *socks5serverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);
    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static bool socks5serverAddressFromContext(const address_context_t *ctx, socks5_address_t *out)
{
    socks5_address_t value = {.port = ctx->port};
    if (addresscontextIsIpType(ctx))
    {
        if (addresscontextIsIpv4(ctx))
        {
            value.kind   = kSocks5AddressIpv4;
            value.length = 4;
            memoryCopy(value.bytes, &ctx->ip_address.u_addr.ip4.addr, value.length);
        }
        else if (addresscontextIsIpv6(ctx))
        {
            value.kind   = kSocks5AddressIpv6;
            value.length = 16;
            memoryCopy(value.bytes, &ctx->ip_address.u_addr.ip6, value.length);
        }
        else
            return false;
    }
    else if (addresscontextIsDomain(ctx) && ctx->domain_len != 0)
    {
        value.kind   = kSocks5AddressDomain;
        value.length = ctx->domain_len;
        memoryCopy(value.bytes, ctx->domain, value.length);
    }
    else
        return false;
    *out = value;
    return true;
}

sbuf_t *socks5serverCreateMethodReply(line_t *l, uint8_t method)
{
    sbuf_t  *buf = socks5serverAllocBuffer(l, 2);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    ptr[0]       = kSocks5Version;
    ptr[1]       = method;
    return buf;
}

sbuf_t *socks5serverCreateAuthReply(line_t *l, uint8_t status)
{
    sbuf_t  *buf = socks5serverAllocBuffer(l, 2);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    ptr[0]       = kSocks5AuthVersion;
    ptr[1]       = status;
    return buf;
}

sbuf_t *socks5serverCreateCommandReply(line_t *l, uint8_t rep, const address_context_t *ctx)
{
    address_context_t        zero_addr  = {0};
    const address_context_t *reply_addr = ctx;

    if (reply_addr == NULL)
    {
        addresscontextSetIpAddressPort(&zero_addr, "0.0.0.0", 0);
        reply_addr = &zero_addr;
    }

    socks5_address_t address;
    if (! socks5serverAddressFromContext(reply_addr, &address))
        return NULL;
    const size_t addr_len = socks5AddressEncodedLength(&address);
    sbuf_t      *buf      = socks5serverAllocBuffer(l, (uint32_t) (3 + addr_len));
    uint8_t     *ptr      = sbufGetMutablePtr(buf);
    size_t       written;
    if (! socks5AddressEncode(&address, ptr + 3, addr_len, &written))
    {
        lineReuseBuffer(l, buf);
        return NULL;
    }
    ptr[0] = kSocks5Version;
    ptr[1] = rep;
    ptr[2] = 0;
    return buf;
}

void socks5serverAddressToContext(const socks5_address_t *value, address_context_t *out)
{
    assert(socks5AddressEncodedLength(value) != 0);
    if (value->kind == kSocks5AddressDomain)
    {
        addresscontextDomainSet(out, (const char *) value->bytes, (uint8_t) value->length);
        out->port = value->port;
    }
    else
    {
        ip_addr_t ip = {0};
        ip.type      = value->kind == kSocks5AddressIpv4 ? IPADDR_TYPE_V4 : IPADDR_TYPE_V6;
        if (value->kind == kSocks5AddressIpv4)
            memoryCopy(&ip.u_addr.ip4.addr, value->bytes, 4);
        else
            memoryCopy(&ip.u_addr.ip6, value->bytes, 16);
        addresscontextSetIpPort(out, &ip, value->port);
    }
}

socks5_address_result_t socks5serverParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out,
                                                      size_t *consumed)
{
    socks5_address_t              value;
    const socks5_address_result_t result = socks5AddressDecode(buf, len, &value);
    if (result != kSocks5AddressComplete)
        return result;
    socks5serverAddressToContext(&value, out);
    *consumed = value.consumed;
    return kSocks5AddressComplete;
}

void socks5serverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);

    addresscontextCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
}

bool socks5serverWrapUdpPayloadForClient(line_t *l, sbuf_t **buf_io, const address_context_t *addr_ctx)
{
    sbuf_t          *buf     = *buf_io;
    uint32_t         payload = sbufGetLength(buf);
    socks5_address_t address;
    if (! socks5serverAddressFromContext(addr_ctx, &address))
        return false;
    const size_t addr_len   = socks5AddressEncodedLength(&address);
    const size_t header_len = 3 + addr_len;
    if (payload > UINT32_MAX - header_len)
        return false;

    if (sbufGetLeftCapacity(buf) < header_len)
    {
        sbuf_t  *wrapped = socks5serverAllocBuffer(l, (uint32_t) (payload + header_len));
        uint8_t *dst     = sbufGetMutablePtr(wrapped);
        memoryCopy(dst + header_len, sbufGetRawPtr(buf), payload);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    else
    {
        sbufShiftLeft(buf, (uint32_t) header_len);
    }

    *buf_io = buf;

    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   written;
    if (! socks5AddressEncode(&address, ptr + 3, addr_len, &written))
        return false;
    ptr[0] = ptr[1] = ptr[2] = 0;
    return true;
}

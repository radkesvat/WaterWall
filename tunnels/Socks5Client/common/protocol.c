#include "internal.h"

#include "loggers/network_logger.h"

sbuf_t *socks5clientAllocHandshakeBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);

    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static bool sendBufferUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf) && socks5clientHasLineState(t, l);
}

static size_t addressEncodedLength(const address_context_t *ctx)
{
    if (addresscontextIsIpv4(ctx))
        return 7;
    if (addresscontextIsIpv6(ctx))
        return 19;
    return addresscontextIsDomain(ctx) ? (size_t) ctx->domain_len + 4 : 0;
}

/* Both callers validate the address and reserve its complete encoded length. */
static void writeAddress(uint8_t *ptr, size_t capacity, const address_context_t *ctx, size_t *offset)
{
    assert(addressEncodedLength(ctx) != 0);
    assert(*offset <= capacity && addressEncodedLength(ctx) <= capacity - *offset);
    discard capacity;
    if (addresscontextIsIpv4(ctx))
    {
        ptr[(*offset)++] = kSocks5AddrTypeIpv4;
        memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip4.addr, 4);
        *offset += 4;
    }
    else if (addresscontextIsIpv6(ctx))
    {
        ptr[(*offset)++] = kSocks5AddrTypeIpv6;
        memoryCopy(ptr + *offset, &ctx->ip_address.u_addr.ip6, 16);
        *offset += 16;
    }
    else
    {
        assert(addresscontextIsDomain(ctx));
        ptr[(*offset)++] = kSocks5AddrTypeDomain;
        ptr[(*offset)++] = ctx->domain_len;
        memoryCopy(ptr + *offset, ctx->domain, ctx->domain_len);
        *offset += ctx->domain_len;
    }
    uint16_t port_be = htobe16(ctx->port);
    memoryCopy(ptr + *offset, &port_be, sizeof(port_be));
    *offset += sizeof(port_be);
}

int socks5clientParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (len < 1)
    {
        return 0;
    }

    uint8_t atyp = buf[0];
    size_t  need = 0;

    switch (atyp)
    {
    case kSocks5AddrTypeIpv4:
        need = 1 + 4 + 2;
        if (len < need)
        {
            return 0;
        }

        {
            ip_addr_t ip = {0};
            ip.type      = IPADDR_TYPE_V4;
            memoryCopy(&ip.u_addr.ip4.addr, buf + 1, 4);
            uint16_t port_be;
            memoryCopy(&port_be, buf + 1 + 4, sizeof(port_be));
            addresscontextSetIpPort(out, &ip, be16toh(port_be));
        }
        *consumed = need;
        return 1;

    case kSocks5AddrTypeIpv6:
        need = 1 + 16 + 2;
        if (len < need)
        {
            return 0;
        }

        {
            ip_addr_t ip = {0};
            ip.type      = IPADDR_TYPE_V6;
            memoryCopy(&ip.u_addr.ip6, buf + 1, 16);
            uint16_t port_be;
            memoryCopy(&port_be, buf + 1 + 16, sizeof(port_be));
            addresscontextSetIpPort(out, &ip, be16toh(port_be));
        }
        *consumed = need;
        return 1;

    case kSocks5AddrTypeDomain:
        if (len < 2)
        {
            return 0;
        }

        need = 1 + 1 + buf[1] + 2;
        if (len < need)
        {
            return 0;
        }

        {
            uint16_t port_be;
            memoryCopy(&port_be, buf + 2 + buf[1], sizeof(port_be));
            addresscontextDomainSet(out, (const char *) (buf + 2), buf[1]);
            addresscontextSetPort(out, be16toh(port_be));
        }
        *consumed = need;
        return 1;

    default:
        return -1;
    }
}

static uint8_t protocolToCommand(socks5client_protocol_t protocol)
{
    assert(protocol == kSocks5ClientProtocolTcp || protocol == kSocks5ClientProtocolUdp);
    return protocol == kSocks5ClientProtocolUdp ? kSocks5CommandUdpAssoc : kSocks5CommandConnect;
}

static void fillUdpAssociateRequestTarget(address_context_t *target)
{
    discard addresscontextSetIpAddressPort(target, "0.0.0.0", 0);
    addresscontextSetOnlyProtocol(target, IP_PROTO_UDP);
}

bool socks5clientSendGreeting(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts        = tunnelGetState(t);
    uint8_t                packet[4] = {kSocks5Version, 1, kSocks5NoAuthMethod, 0};
    uint32_t               len       = 3;

    if (ts->username_len > 0 || ts->password_len > 0)
    {
        packet[1] = 2;
        packet[2] = kSocks5NoAuthMethod;
        packet[3] = kSocks5UserPassMethod;
        len       = 4;
    }

    ls->phase = kSocks5ClientPhaseWaitMethod;

    if (ts->verbose)
    {
        LOGD("Socks5Client: sending method selection with %u method(s)", (unsigned int) packet[1]);
    }

    sbuf_t *buf = socks5clientAllocHandshakeBuffer(l, len);
    sbufWriteLarge(buf, packet, len);
    return sendBufferUpstream(t, l, buf);
}

bool socks5clientSendAuthRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts  = tunnelGetState(t);
    uint32_t               len = 3U + (uint32_t) ts->username_len + (uint32_t) ts->password_len;
    sbuf_t                *buf = socks5clientAllocHandshakeBuffer(l, len);
    uint8_t               *ptr = sbufGetMutablePtr(buf);

    ptr[0] = kSocks5AuthVersion;
    ptr[1] = ts->username_len;
    memoryCopy(ptr + 2, ts->username, ts->username_len);
    ptr[2 + ts->username_len] = ts->password_len;
    memoryCopy(ptr + 3 + ts->username_len, ts->password, ts->password_len);

    ls->phase = kSocks5ClientPhaseWaitAuth;

    if (ts->verbose)
    {
        LOGD("Socks5Client: sending username/password authentication request");
    }

    return sendBufferUpstream(t, l, buf);
}

bool socks5clientSendConnectRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts           = tunnelGetState(t);
    address_context_t      assoc_target = {0};
    address_context_t     *target       = &ls->target_addr;
    uint8_t                cmd          = protocolToCommand(ls->protocol);

    if (ls->protocol == kSocks5ClientProtocolUdp)
    {
        fillUdpAssociateRequestTarget(&assoc_target);
        target = &assoc_target;
    }

    const size_t addr_len = addressEncodedLength(target);
    if (addr_len == 0)
    {
        LOGE("Socks5Client: unsupported or missing destination address");
        addresscontextReset(&assoc_target);
        return false;
    }

    uint32_t len = 3U + (uint32_t) addr_len;
    sbuf_t  *buf = socks5clientAllocHandshakeBuffer(l, len);
    uint8_t *ptr = sbufGetMutablePtr(buf);

    ptr[0] = kSocks5Version;
    ptr[1] = cmd;
    ptr[2] = 0;

    size_t offset = 3;
    writeAddress(ptr, len, target, &offset);

    ls->phase = kSocks5ClientPhaseWaitCommand;

    if (ts->verbose)
    {
        LOGD("Socks5Client: sending proxy command %u for target port %u",
             (unsigned int) cmd,
             (unsigned int) target->port);
    }

    addresscontextReset(&assoc_target);
    return sendBufferUpstream(t, l, buf);
}

bool socks5clientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target)
{
    sbuf_t      *buf         = *buf_io;
    uint32_t     payload     = sbufGetLength(buf);
    const size_t address_len = addressEncodedLength(target);
    if (address_len == 0)
        return false;
    const size_t header_len = 3 + address_len;
    if (payload > UINT32_MAX - header_len)
        return false;

    buf     = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    *buf_io = buf;
    if (sbufGetLeftCapacity(buf) < header_len)
    {
        sbuf_t  *wrapped = socks5clientAllocHandshakeBuffer(l, (uint32_t) (payload + header_len));
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
    size_t   off = 0;

    ptr[off++] = 0;
    ptr[off++] = 0;
    ptr[off++] = 0;
    writeAddress(ptr, header_len, target, &off);

    return true;
}

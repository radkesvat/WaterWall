#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kHeaderClientProxyProtocolV2Signature[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
};

enum
{
    kHeaderClientProxyProtocolV2VersionCommandLocal = 0x20,
    kHeaderClientProxyProtocolV2VersionCommandProxy = 0x21,
    kHeaderClientProxyProtocolV2FamilyUnspec        = 0x00,
    kHeaderClientProxyProtocolV2FamilyTcp4          = 0x11,
};

static uint16_t headerclientGetHeaderPort(headerclient_tstate_t *ts, line_t *l)
{
    switch (ts->data_mode)
    {
    case kHeaderClientDataModeSourcePort:
        return lineGetSourceAddressContext(l)->port;

    case kHeaderClientDataModeConstant:
        return ts->constant_port;

    default:
        return 0;
    }
}

static bool headerclientGetProxySocketAddresses(headerclient_tstate_t *ts, line_t *l, sockaddr_u *src_addr,
                                                sockaddr_u *dest_addr)
{
    const address_context_t *src_ctx = lineGetSourceAddressContext(l);

    if (! addresscontextCanConvertToSockAddr(src_ctx))
    {
        return false;
    }

    *src_addr  = addresscontextToSockAddr(src_ctx);
    *dest_addr = addresscontextToSockAddr(&ts->proxy_frontend_ipv4);

    if (src_addr->sa.sa_family != AF_INET)
    {
        return false;
    }

    const routing_context_t *route = lineGetRoutingContext(l);
    sockaddrSetPort(src_addr, route->peer_source_port != 0 ? route->peer_source_port : src_ctx->port);
    sockaddrSetPort(dest_addr, route->local_listener_port != 0 ? route->local_listener_port : src_ctx->port);

    return true;
}

static uint32_t headerclientBuildProxyProtocolV1(headerclient_tstate_t *ts, line_t *l,
                                                 uint8_t out[kHeaderClientMaxHeaderSize])
{
    sockaddr_u src_addr;
    sockaddr_u dest_addr;
    int        written;

    if (! headerclientGetProxySocketAddresses(ts, l, &src_addr, &dest_addr))
    {
        written = stringNPrintf((char *) out, kHeaderClientProxyProtocolV1MaxHeaderSize, "PROXY UNKNOWN\r\n");
        return stringFormatFits(written, kHeaderClientProxyProtocolV1MaxHeaderSize) ? (uint32_t) written : 0;
    }

    char        src_ip[SOCKADDR_STRLEN]  = {0};
    char        dest_ip[SOCKADDR_STRLEN] = {0};

    written = stringNPrintf((char *) out,
                            kHeaderClientProxyProtocolV1MaxHeaderSize,
                            "PROXY %s %s %s %u %u\r\n",
                            "TCP4",
                            sockaddrIp(&src_addr, src_ip, (int) sizeof(src_ip)),
                            sockaddrIp(&dest_addr, dest_ip, (int) sizeof(dest_ip)),
                            (unsigned int) sockaddrPort(&src_addr),
                            (unsigned int) sockaddrPort(&dest_addr));

    return stringFormatFits(written, kHeaderClientProxyProtocolV1MaxHeaderSize) ? (uint32_t) written : 0;
}

static uint32_t headerclientBuildProxyProtocolV2(headerclient_tstate_t *ts, line_t *l,
                                                 uint8_t out[kHeaderClientMaxHeaderSize])
{
    sockaddr_u src_addr;
    sockaddr_u dest_addr;
    uint8_t    version_command = kHeaderClientProxyProtocolV2VersionCommandLocal;
    uint8_t    family          = kHeaderClientProxyProtocolV2FamilyUnspec;
    uint16_t   address_len     = 0;

    if (headerclientGetProxySocketAddresses(ts, l, &src_addr, &dest_addr))
    {
        version_command = kHeaderClientProxyProtocolV2VersionCommandProxy;
        family          = kHeaderClientProxyProtocolV2FamilyTcp4;
        address_len     = kHeaderClientProxyProtocolV2Ipv4AddressSize;
    }

    memoryCopy(out, kHeaderClientProxyProtocolV2Signature, sizeof(kHeaderClientProxyProtocolV2Signature));
    out[12] = version_command;
    out[13] = family;

    uint16_t address_len_network = htons(address_len);
    memoryCopy(out + 14, &address_len_network, sizeof(address_len_network));

    size_t offset = kHeaderClientProxyProtocolV2BaseHeaderSize;

    if (family == kHeaderClientProxyProtocolV2FamilyTcp4)
    {
        memoryCopy(out + offset, &src_addr.sin.sin_addr, sizeof(src_addr.sin.sin_addr));
        offset += sizeof(src_addr.sin.sin_addr);
        memoryCopy(out + offset, &dest_addr.sin.sin_addr, sizeof(dest_addr.sin.sin_addr));
        offset += sizeof(dest_addr.sin.sin_addr);
        memoryCopy(out + offset, &src_addr.sin.sin_port, sizeof(src_addr.sin.sin_port));
        offset += sizeof(src_addr.sin.sin_port);
        memoryCopy(out + offset, &dest_addr.sin.sin_port, sizeof(dest_addr.sin.sin_port));
        offset += sizeof(dest_addr.sin.sin_port);
    }

    assert(offset <= UINT32_MAX);
    return (uint32_t) offset;
}

static uint32_t headerclientBuildHeader(headerclient_tstate_t *ts, line_t *l, uint8_t out[kHeaderClientMaxHeaderSize])
{
    switch (ts->data_mode)
    {
    case kHeaderClientDataModeSourcePort:
    case kHeaderClientDataModeConstant: {
        uint16_t port         = headerclientGetHeaderPort(ts, l);
        uint16_t port_network = htons(port);
        memoryCopy(out, &port_network, sizeof(port_network));
        return kHeaderClientPortHeaderSize;
    }
    case kHeaderClientDataModeProxyProtocolV1:
        return headerclientBuildProxyProtocolV1(ts, l, out);

    case kHeaderClientDataModeProxyProtocolV2:
        return headerclientBuildProxyProtocolV2(ts, l, out);

    default:
        return 0;
    }
}

static void headerclientCloseLineFromHeaderError(tunnel_t *t, line_t *l, headerclient_lstate_t *ls)
{
    lineLock(l);
    headerclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

void headerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    headerclient_tstate_t *ts = tunnelGetState(t);
    headerclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->header_sent)
    {
        uint8_t  header[kHeaderClientMaxHeaderSize];
        uint32_t header_len = headerclientBuildHeader(ts, l, header);
        if (UNLIKELY(header_len == 0))
        {
            LOGE("HeaderClient: could not build configured header");
            lineReuseBuffer(l, buf);
            headerclientCloseLineFromHeaderError(t, l, ls);
            return;
        }

        ls->header_sent = true;
        assert(sbufGetLeftCapacity(buf) >= header_len);
        sbufShiftLeft(buf, header_len);
        sbufWrite(buf, header, header_len);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

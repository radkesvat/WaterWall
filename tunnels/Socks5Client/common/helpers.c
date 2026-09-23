#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kSocks5Version         = 0x05,
    kSocks5NoAuthMethod    = 0x00,
    kSocks5UserPassMethod  = 0x02,
    kSocks5NoAcceptable    = 0xFF,
    kSocks5CommandConnect  = 0x01,
    kSocks5CommandUdpAssoc = 0x03,
    kSocks5AddrTypeIpv4    = 0x01,
    kSocks5AddrTypeDomain  = 0x03,
    kSocks5AddrTypeIpv6    = 0x04,
    kSocks5AuthVersion     = 0x01
};

static sbuf_t *allocHandshakeBuffer(line_t *l, uint32_t len)
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
    return lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static int getCommandReplyLength(buffer_stream_t *stream)
{
    size_t available = bufferstreamGetBufLen(stream);
    if (available < 4)
    {
        return 0;
    }

    uint8_t header[5] = {0};
    size_t  peek_len  = min(available, sizeof(header));
    bufferstreamViewBytesAt(stream, 0, header, peek_len);

    switch (header[3])
    {
    case kSocks5AddrTypeIpv4:
        return available >= 10 ? 10 : 0;

    case kSocks5AddrTypeIpv6:
        return available >= 22 ? 22 : 0;

    case kSocks5AddrTypeDomain: {
        if (available < 5)
        {
            return 0;
        }

        size_t total = (size_t) 7 + (size_t) header[4];
        return available >= total ? (int) total : 0;
    }

    default:
        return -1;
    }
}

static bool writeAddress(uint8_t *ptr, const address_context_t *ctx, size_t *offset)
{
    if (addresscontextIsIpType(ctx))
    {
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
            return false;
        }
    }
    else if (addresscontextIsDomain(ctx))
    {
        ptr[(*offset)++] = kSocks5AddrTypeDomain;
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

static int parseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
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

static bool getProtocolFromContext(const address_context_t *ctx, socks5client_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kSocks5ClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kSocks5ClientProtocolUdp;
        return true;
    }

    return false;
}

static socks5client_protocol_t resolveConfiguredProtocol(const socks5client_tstate_t *ts,
                                                         const address_context_t     *current_dest_ctx)
{
    if (ts->protocol != kSocks5ClientProtocolDestContext)
    {
        return ts->protocol;
    }

    socks5client_protocol_t protocol = kSocks5ClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("Socks5Client: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kSocks5ClientProtocolTcp;
}

static void fillUdpAssociateRequestTarget(address_context_t *target)
{
    discard addresscontextSetIpAddressPort(target, "0.0.0.0", 0);
    addresscontextSetOnlyProtocol(target, IP_PROTO_UDP);
}

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
}

static line_t *createInternalLine(tunnel_t *t, line_t *application_l, socks5client_line_kind_t kind)
{
    line_t *inner_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(application_l));

    socks5client_lstate_t *inner_ls = lineGetState(inner_l, t);
    socks5clientLinestateInitialize(inner_ls, t, inner_l);
    inner_ls->kind     = kind;
    inner_ls->application_line = application_l;

    return inner_l;
}

void socks5clientTunnelstateDestroy(socks5client_tstate_t *ts)
{
    assert(ts != NULL);

    addresscontextReset(&ts->target_addr);

    if (ts->username != NULL)
    {
        memoryFree(ts->username);
        ts->username = NULL;
    }

    if (ts->password != NULL)
    {
        memoryZero(ts->password, ts->password_len);
        memoryFree(ts->password);
        ts->password = NULL;
    }

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

bool socks5clientApplyTargetContext(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    address_context_t      current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kSocks5ClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextCopy(&current, dest_ctx);
    }

    socks5client_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (! addresscontextIsValid(&current))
        {
            LOGE("Socks5Client: configured to use dest_context->address, but line destination address is not set");
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
        if (current.port == 0)
        {
            LOGE("Socks5Client: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kSocks5ClientProtocolTcp)
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

bool socks5clientMaybeSendGreeting(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (! ls->greeting_due || ls->next_paused)
        return true;
    ls->greeting_due = false;
    return socks5clientSendGreeting(t, l, ls);
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

    sbuf_t *buf = allocHandshakeBuffer(l, len);
    sbufWriteLarge(buf, packet, len);
    return sendBufferUpstream(t, l, buf);
}

bool socks5clientSendAuthRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts  = tunnelGetState(t);
    uint32_t               len = 3U + (uint32_t) ts->username_len + (uint32_t) ts->password_len;
    sbuf_t                *buf = allocHandshakeBuffer(l, len);
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
    uint32_t               addr_len     = 0;

    if (ls->protocol == kSocks5ClientProtocolUdp)
    {
        fillUdpAssociateRequestTarget(&assoc_target);
        target = &assoc_target;
    }

    if (addresscontextIsIpType(target))
    {
        if (target->ip_address.type == IPADDR_TYPE_V4)
        {
            addr_len = 1 + 4 + 2;
        }
        else if (target->ip_address.type == IPADDR_TYPE_V6)
        {
            addr_len = 1 + 16 + 2;
        }
        else
        {
            LOGE("Socks5Client: unsupported IP type for destination context");
            return false;
        }
    }
    else if (addresscontextIsDomain(target))
    {
        addr_len = 1U + 1U + (uint32_t) target->domain_len + 2U;
    }
    else
    {
        LOGE("Socks5Client: target settings are not populated");
        addresscontextReset(&assoc_target);
        return false;
    }

    uint32_t len = 3U + addr_len;
    sbuf_t  *buf = allocHandshakeBuffer(l, len);
    uint8_t *ptr = sbufGetMutablePtr(buf);

    ptr[0] = kSocks5Version;
    ptr[1] = cmd;
    ptr[2] = 0;

    size_t offset = 3;
    if (! writeAddress(ptr, target, &offset))
    {
        lineReuseBuffer(l, buf);
        addresscontextReset(&assoc_target);
        return false;
    }

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

static bool wrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);
    size_t   header_len;

    if (addresscontextIsIpType(target))
    {
        header_len = addresscontextIsIpv6(target) ? (size_t) 4 + 16 + 2 : (size_t) 4 + 4 + 2;
    }
    else if (addresscontextIsDomain(target))
    {
        header_len = (size_t) 4 + 1 + target->domain_len + 2;
    }
    else
    {
        return false;
    }

    if (sbufGetLeftCapacity(buf) < header_len)
    {
        sbuf_t  *wrapped = allocHandshakeBuffer(l, (uint32_t) (payload + header_len));
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
    if (! writeAddress(ptr, target, &off))
    {
        return false;
    }

    return true;
}

static bool forwardUdpPayloadToRelay(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls,
                                     sbuf_t *buf)
{
    if (application_ls->udp_line == NULL || ! lineIsAlive(application_ls->udp_line))
    {
        lineReuseBuffer(application_l, buf);
        return false;
    }

    if (! wrapUdpPayload(application_l, &buf, &application_ls->target_addr))
    {
        lineReuseBuffer(application_l, buf);
        return false;
    }

    return lineCallWithRefWithBuf(application_ls->udp_line, tunnelNextUpStreamPayload, t, buf);
}

static bool updateSourcePressure(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls     = lineGetState(l, t);
    const bool             paused = ls->next_paused || ls->draining_up || bufferqueueGetBufCount(&ls->pending_up) != 0;
    if (ls->source_pause_sent == paused)
        return true;
    ls->source_pause_sent = paused;
    return paused ? lineCallWithRef(l, tunnelPrevDownStreamPause, t)
                  : lineCallWithRef(l, tunnelPrevDownStreamResume, t);
}

bool socks5clientQueuePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls     = lineGetState(l, t);
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_up, &buf)))
    {
        lineReuseBuffer(l, buf);
        socks5clientCloseLineBidirectional(t, l);
        return false;
    }
    return updateSourcePressure(t, l);
}

bool socks5clientDrainPending(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->draining_up || ls->phase != kSocks5ClientPhaseEstablished)
        return true;
    lineRef(l);
    ls->draining_up = true;
    while (lineIsAlive(l) && ! ls->next_paused && bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (ls->kind == kSocks5ClientLineKindUdpApplication)
        {
            if (UNLIKELY(! forwardUdpPayloadToRelay(t, l, ls, buf)))
                break;
        }
        else
            tunnelNextUpStreamPayload(t, l, buf);
    }
    bool alive = lineIsAlive(l);
    if (alive)
    {
        ls->draining_up = false;
        alive           = updateSourcePressure(t, l);
    }
    lineUnref(l);
    return alive;
}

void socks5clientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    ls->next_paused           = paused;
    if (! paused && ! socks5clientMaybeSendGreeting(t, l))
        return;
    line_t *application = (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
                              ? ls->application_line
                              : l;
    if (application == NULL)
        return;
    socks5client_lstate_t *application_ls = lineGetState(application, t);
    if (application != l)
    {
        socks5client_lstate_t *control =
            application_ls->control_line ? lineGetState(application_ls->control_line, t) : NULL;
        socks5client_lstate_t *relay = application_ls->udp_line ? lineGetState(application_ls->udp_line, t) : NULL;
        application_ls->next_paused  = (control && control->next_paused) || (relay && relay->next_paused);
    }
    if (application_ls->next_paused)
    {
        discard updateSourcePressure(t, application);
        return;
    }
    if (UNLIKELY(! socks5clientDrainPending(t, application)))
        return;
    discard updateSourcePressure(t, application);
}

static bool tryEstablishUdpApplication(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls)
{
    if (! application_ls->udp_control_ready || ! application_ls->udp_relay_ready)
        return true;
    application_ls->phase = kSocks5ClientPhaseEstablished;
    return socks5clientDrainPending(t, application_l);
}

static bool startUdpRelayLine(tunnel_t *t, line_t *control_l, socks5client_lstate_t *control_ls,
                              const address_context_t *relay_addr, bool *control_alive_out)
{
    *control_alive_out = true;
    lineRef(control_l);

    line_t *application_l = control_ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(control_l);
        return false;
    }

    lineRef(application_l);

    socks5client_lstate_t *application_ls = lineGetState(application_l, t);
    line_t                *udp_l          = createInternalLine(t, application_l, kSocks5ClientLineKindUdpRelay);

    addresscontextCopy(lineGetDestinationAddressContext(udp_l), relay_addr);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(udp_l), IP_PROTO_UDP);
    addresscontextSetDestinationPinned(lineGetDestinationAddressContext(udp_l), true);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(udp_l), IP_PROTO_UDP);

    application_ls->udp_line = udp_l;

    if (! lineCallWithRef(udp_l, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(application_l))
        {
            application_ls->udp_line = NULL;
        }
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(application_l);
        lineUnref(control_l);
        return false;
    }

    if (lineIsAlive(application_l) && application_ls->prev_paused &&
        ! lineCallWithRef(udp_l, tunnelNextUpStreamPause, t))
    {
        // The callback may have reclaimed udp_l; only our retained application/control remain accessible.
        *control_alive_out = lineIsAlive(control_l);
        lineUnref(application_l);
        lineUnref(control_l);
        return false;
    }

    bool application_alive = lineIsAlive(application_l);
    *control_alive_out = lineIsAlive(control_l);
    if (! application_alive || ! *control_alive_out)
    {
        socks5clientCloseOwnedLine(t, udp_l);
    }
    lineUnref(application_l);
    lineUnref(control_l);

    if (! application_alive || ! *control_alive_out)
    {
        return false;
    }

    return true;
}

bool socks5clientStartUdpAssociation(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, bool *line_alive_out)
{
    *line_alive_out = true;
    lineRef(l);

    line_t                *control_l  = createInternalLine(t, l, kSocks5ClientLineKindUdpControl);
    socks5client_lstate_t *control_ls = lineGetState(control_l, t);

    addresscontextCopy(&control_ls->target_addr, &ls->target_addr);
    control_ls->protocol = ls->protocol;
    setLineProtocol(control_l, IP_PROTO_TCP);

    ls->control_line = control_l;

    if (! lineCallWithRef(control_l, tunnelNextUpStreamInit, t))
    {
        if (lineIsAlive(l))
        {
            ls->control_line = NULL;
        }
        *line_alive_out = lineIsAlive(l);
        lineUnref(l);
        return false;
    }

    *line_alive_out = lineIsAlive(l);
    if (! *line_alive_out)
    {
        socks5clientCloseOwnedLine(t, control_l);
    }
    lineUnref(l);

    return true;
}

bool socks5clientForwardUdpApplicationPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf)
{
    if (ls->phase == kSocks5ClientPhaseEstablished && ! ls->draining_up && bufferqueueGetBufCount(&ls->pending_up) == 0)
        return forwardUdpPayloadToRelay(t, l, ls, buf);
    return socks5clientQueuePayload(t, l, buf) && socks5clientDrainPending(t, l);
}

bool socks5clientHandleUdpRelayPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf)
{
    line_t *application_l = ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    const uint8_t *raw = sbufGetRawPtr(buf);
    size_t         len = sbufGetLength(buf);

    if (len < 4 || raw[0] != 0 || raw[1] != 0)
    {
        lineReuseBuffer(l, buf);
        socks5clientCloseLineBidirectional(t, l);
        return false;
    }

    if (raw[2] != 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    address_context_t source   = {0};
    size_t            addr_len = 0;
    int               parsed   = parseAddressBytes(raw + 3, len - 3, &source, &addr_len);

    if (parsed <= 0 || len < (size_t) (3 + addr_len))
    {
        addresscontextReset(&source);
        lineReuseBuffer(l, buf);
        if (parsed < 0)
        {
            socks5clientCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    addresscontextReset(&source);
    sbufShiftRight(buf, (uint32_t) (3 + addr_len));
    return lineCallWithRefWithBuf(application_l, tunnelPrevDownStreamPayload, t, buf);
}

void socks5clientOnUdpRelayEstablished(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    discard l;

    line_t *application_l = ls->application_line;
    if (application_l == NULL || ! lineIsAlive(application_l))
    {
        return;
    }

    socks5client_lstate_t *application_ls = lineGetState(application_l, t);
    application_ls->udp_relay_ready       = true;
    discard tryEstablishUdpApplication(t, application_l, application_ls);
}

void socks5clientCloseOwnedLine(tunnel_t *t, line_t *owned_l)
{
    if (owned_l == NULL || ! lineIsAlive(owned_l))
    {
        return;
    }

    socks5clientLinestateDestroy(lineGetState(owned_l, t));
    tunnelNextUpStreamFinish(t, owned_l);
    if (lineIsAlive(owned_l))
    {
        lineDestroy(owned_l);
    }
}

void socks5clientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ClientLineKindUdpApplication)
    {
        line_t *control_l = ls->control_line;
        line_t *udp_l     = ls->udp_line;

        ls->control_line = NULL;
        ls->udp_line     = NULL;

        socks5clientCloseOwnedLine(t, udp_l);
        socks5clientCloseOwnedLine(t, control_l);
        socks5clientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    if (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
    {
        line_t *application_l = ls->application_line;
        line_t *control_l = NULL;
        line_t *udp_l     = NULL;

        if (application_l != NULL && lineIsAlive(application_l))
        {
            socks5client_lstate_t *application_ls = lineGetState(application_l, t);

            control_l = application_ls->control_line;
            udp_l     = application_ls->udp_line;
            if (control_l == l)
            {
                control_l = NULL;
            }
            if (udp_l == l)
            {
                udp_l = NULL;
            }

            application_ls->control_line = NULL;
            application_ls->udp_line     = NULL;
        }

        socks5clientLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }

        socks5clientCloseOwnedLine(t, udp_l);
        socks5clientCloseOwnedLine(t, control_l);

        if (application_l != NULL && lineIsAlive(application_l))
        {
            socks5client_lstate_t *application_ls = lineGetState(application_l, t);
            socks5clientLinestateDestroy(application_ls);
            tunnelPrevDownStreamFinish(t, application_l);
        }
        return;
    }

    socks5clientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}

bool socks5clientDrainHandshakeInput(tunnel_t *t, line_t *l, socks5client_lstate_t *ls)
{
    socks5client_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        if (ls->phase == kSocks5ClientPhaseEstablished)
        {
            return true;
        }

        if (ls->phase == kSocks5ClientPhaseWaitMethod)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t reply[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, reply, sizeof(reply));
            lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, sizeof(reply)));

            if (reply[0] != kSocks5Version)
            {
                LOGE("Socks5Client: invalid method reply version 0x%02x", reply[0]);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] == kSocks5NoAcceptable)
            {
                LOGE("Socks5Client: proxy rejected all advertised authentication methods");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] == kSocks5NoAuthMethod)
            {
                if (! socks5clientSendConnectRequest(t, l, ls))
                {
                    return false;
                }
                continue;
            }

            if (reply[1] == kSocks5UserPassMethod)
            {
                if (ts->username_len == 0 || ts->password_len == 0)
                {
                    LOGE("Socks5Client: proxy requested username/password authentication but no credentials are "
                         "configured");
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                if (! socks5clientSendAuthRequest(t, l, ls))
                {
                    return false;
                }
                continue;
            }

            LOGE("Socks5Client: proxy selected unsupported auth method 0x%02x", reply[1]);
            socks5clientCloseLineBidirectional(t, l);
            return false;
        }

        if (ls->phase == kSocks5ClientPhaseWaitAuth)
        {
            if (bufferstreamGetBufLen(&ls->in_stream) < 2)
            {
                return true;
            }

            uint8_t reply[2];
            bufferstreamViewBytesAt(&ls->in_stream, 0, reply, sizeof(reply));
            lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, sizeof(reply)));

            if (reply[0] != kSocks5AuthVersion || reply[1] != 0x00)
            {
                LOGE("Socks5Client: proxy authentication failed");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (! socks5clientSendConnectRequest(t, l, ls))
            {
                return false;
            }
            continue;
        }

        if (ls->phase == kSocks5ClientPhaseWaitCommand)
        {
            int reply_len = getCommandReplyLength(&ls->in_stream);
            if (reply_len == 0)
            {
                return true;
            }

            if (reply_len < 0)
            {
                LOGE("Socks5Client: proxy sent an invalid command reply");
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            sbuf_t        *reply_buf = bufferstreamReadExact(&ls->in_stream, (size_t) reply_len);
            const uint8_t *reply     = sbufGetRawPtr(reply_buf);

            if (reply[0] != kSocks5Version)
            {
                LOGE("Socks5Client: invalid command reply version 0x%02x", reply[0]);
                lineReuseBuffer(l, reply_buf);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (reply[1] != 0x00)
            {
                LOGE("Socks5Client: proxy command failed with reply code 0x%02x", reply[1]);
                lineReuseBuffer(l, reply_buf);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (ls->protocol == kSocks5ClientProtocolUdp)
            {
                address_context_t relay_addr = {0};
                size_t            consumed   = 0;
                int               parsed = parseAddressBytes(reply + 3, (size_t) reply_len - 3, &relay_addr, &consumed);
                lineReuseBuffer(l, reply_buf);

                if (parsed <= 0)
                {
                    addresscontextReset(&relay_addr);
                    LOGE("Socks5Client: proxy sent an invalid UDP relay address");
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                addresscontextSetOnlyProtocol(&relay_addr, IP_PROTO_UDP);
                addresscontextCopy(&ls->relay_addr, &relay_addr);
                ls->phase = kSocks5ClientPhaseEstablished;

                bool control_alive = true;
                if (! startUdpRelayLine(t, l, ls, &relay_addr, &control_alive))
                {
                    addresscontextReset(&relay_addr);
                    if (! control_alive)
                    {
                        return false;
                    }
                    socks5clientCloseLineBidirectional(t, l);
                    return false;
                }

                line_t *application_l = ls->application_line;
                addresscontextReset(&relay_addr);
                if (application_l == NULL || ! lineIsAlive(application_l))
                {
                    return false;
                }

                socks5client_lstate_t *application_ls = lineGetState(application_l, t);
                application_ls->udp_control_ready     = true;

                if (ts->verbose)
                {
                    LOGD("Socks5Client: SOCKS5 UDP association completed");
                }

                return tryEstablishUdpApplication(t, application_l, application_ls);
            }

            lineReuseBuffer(l, reply_buf);
            ls->phase = kSocks5ClientPhaseEstablished;
            // This tail belongs to the accepted reply batch. Publish its consumption
            // before callbacks; the older application FIFO stays authoritative in ls.
            sbuf_t *tail = bufferstreamIsEmpty(&ls->in_stream)
                               ? NULL
                               : bufferstreamReadExact(&ls->in_stream, bufferstreamGetBufLen(&ls->in_stream));
            if (UNLIKELY(tail != NULL && ! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, tail)))
                return false;
            if (ls->prev_paused && ! ls->read_pause_sent)
            {
                ls->read_pause_sent = true;
                if (UNLIKELY(! lineCallWithRef(l, tunnelNextUpStreamPause, t)))
                    return false;
            }
            return socks5clientDrainPending(t, l);
        }

        return true;
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kTrojanCommandConnect      = 0x01,
    kTrojanCommandUdpAssociate = 0x03,
    kTrojanAtypIpv4           = 0x01,
    kTrojanAtypDomain         = 0x03,
    kTrojanAtypIpv6           = 0x04
};

static sbuf_t *allocProtocolBuffer(line_t *l, uint32_t len)
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
    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool flushQueueToNext(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf)))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

static bool flushStreamToPrev(tunnel_t *t, line_t *l, buffer_stream_t *stream)
{
    while (! bufferstreamIsEmpty(stream))
    {
        sbuf_t *buf = bufferstreamIdealRead(stream);
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf)))
        {
            return false;
        }
    }

    return true;
}

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

static int trojanclientParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (len < 1)
    {
        return 0;
    }

    uint8_t atyp = buf[0];
    size_t  need = 0;

    switch (atyp)
    {
    case kTrojanAtypIpv4:
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

    case kTrojanAtypIpv6:
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

    case kTrojanAtypDomain:
        if (len < 2)
        {
            return 0;
        }

        if (buf[1] == 0)
        {
            return -1;
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

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
    lineGetRoutingContext(l)->network_type = protocol == IP_PROTO_UDP ? WIO_TYPE_UDP : WIO_TYPE_TCP;
}

static line_t *createInternalLine(tunnel_t *t, line_t *app_l, trojanclient_line_kind_t kind)
{
    line_t *inner_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(app_l));

    trojanclient_lstate_t *inner_ls = lineGetState(inner_l, t);
    trojanclientLinestateInitialize(inner_ls, t, inner_l);
    inner_ls->kind     = kind;
    inner_ls->app_line = app_l;

    return inner_l;
}

static void dnsRequestDestroy(trojanclient_dns_request_t *request)
{
    if (request == NULL)
    {
        return;
    }

    memoryFree(request->domain);
    memoryFree(request);
}

static void closeBeforeTransportInit(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    trojanclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void continueAfterTargetReady(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    ls->phase = kTrojanClientPhaseIdle;

    if (ls->protocol == kTrojanClientProtocolUdp)
    {
        bool line_alive = true;
        if (UNLIKELY(! trojanclientStartUdpCarrier(t, l, ls, &line_alive)))
        {
            if (! line_alive)
            {
                return;
            }
            closeBeforeTransportInit(t, l, ls);
        }
        return;
    }

    tunnelNextUpStreamInit(t, l);
}

static void onDnsResolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                          size_t naddrs)
{
    trojanclient_dns_request_t *request = userdata;
    tunnel_t                   *t       = request->tunnel;
    line_t                     *l       = request->line;

    if (request->cancelled || ! lineIsAlive(l))
    {
        dnsRequestDestroy(request);
        lineUnlock(l);
        return;
    }

    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->dns_request != request || ls->phase != kTrojanClientPhaseResolving)
    {
        dnsRequestDestroy(request);
        lineUnlock(l);
        return;
    }

    ls->dns_request = NULL;
    ls->phase       = kTrojanClientPhaseIdle;

    if (asyncdnsStatusIsShutdown(status))
    {
        dnsRequestDestroy(request);
        lineUnlock(l);
        return;
    }

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        LOGE("TrojanClient: async dns resolve failed for %s: %s",
             request->domain,
             error != NULL ? error : ares_strerror(status));
        dnsRequestDestroy(request);
        closeBeforeTransportInit(t, l, ls);
        lineUnlock(l);
        return;
    }

    const dns_resolved_addr_t *selected =
        dnsstrategySelectResolvedAddress(addrs, naddrs, (enum domain_strategy) request->strategy);
    if (UNLIKELY(! dnsstrategyApplyResolvedAddress(lineGetDestinationAddressContext(l), selected) ||
                 ! dnsstrategyApplyResolvedAddress(&ls->target_addr, selected)))
    {
        LOGE("TrojanClient: async dns resolve returned no usable address for %s", request->domain);
        dnsRequestDestroy(request);
        closeBeforeTransportInit(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (loggerCheckWriteLevel(getNetworkLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        sockaddr_u resolved_addr = addresscontextToSockAddr(&ls->target_addr);
        char       ip[SOCKADDR_STRLEN];
        LOGD("TrojanClient: %s resolved to %s", request->domain, SOCKADDR_STR(&resolved_addr, ip));
    }

    dnsRequestDestroy(request);
    continueAfterTargetReady(t, l, ls);
    lineUnlock(l);
}

void trojanclientTunnelstateDestroy(trojanclient_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    addresscontextReset(&ts->target_addr);
    memorySet(ts->password_hex, 0, sizeof(ts->password_hex));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l)
{
    trojanclient_tstate_t *ts       = tunnelGetState(t);
    trojanclient_lstate_t *ls       = lineGetState(l, t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    routing_context_t     *route    = lineGetRoutingContext(l);
    address_context_t      current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) ||
                             (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kTrojanClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextAddrCopy(&current, dest_ctx);
        addresscontextSetPort(&current, dest_ctx->port);
    }

    trojanclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextAddrCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("TrojanClient: configured to use dest_context->address, but line destination address is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextAddrCopy(dest_ctx, &current);
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
        route->network_type = WIO_TYPE_TCP;
    }
    else
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
        route->network_type = WIO_TYPE_UDP;
    }

    ls->protocol = resolved_protocol;

    if (uses_current_dest)
    {
        addresscontextReset(&current);
    }

    addresscontextAddrCopy(&ls->target_addr, dest_ctx);
    addresscontextSetPort(&ls->target_addr, dest_ctx->port);
    if (ts->resolve_domains)
    {
        addresscontextSetDomainStrategy(dest_ctx, (enum domain_strategy) ts->domain_strategy);
        addresscontextSetDomainStrategy(&ls->target_addr, (enum domain_strategy) ts->domain_strategy);
    }
    return true;
}

bool trojanclientStartDomainResolveIfNeeded(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, bool *started_out)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);

    *started_out = false;

    if (! ts->resolve_domains || ! addresscontextIsDomain(&ls->target_addr))
    {
        return true;
    }

    trojanclient_dns_request_t *request = memoryAllocate(sizeof(*request));
    if (UNLIKELY(request == NULL))
    {
        LOGE("TrojanClient: failed to allocate async dns request");
        return false;
    }

    char *domain = stringDuplicate(ls->target_addr.domain);
    if (UNLIKELY(domain == NULL))
    {
        memoryFree(request);
        LOGE("TrojanClient: failed to copy async dns domain");
        return false;
    }

    *request = (trojanclient_dns_request_t) {
        .tunnel    = t,
        .line      = l,
        .domain    = domain,
        .strategy  = ts->domain_strategy,
        .cancelled = false,
    };

    lineLock(l);
    ls->dns_request = request;
    ls->phase       = kTrojanClientPhaseResolving;

    int socktype = ls->protocol == kTrojanClientProtocolUdp ? SOCK_DGRAM : SOCK_STREAM;
    int rc       = workerResolveDomainServiceAsync(lineGetWID(l), request->domain, NULL, socktype, onDnsResolved,
                                                   request);
    if (UNLIKELY(rc != ARES_SUCCESS))
    {
        ls->dns_request = NULL;
        ls->phase       = kTrojanClientPhaseIdle;
        lineUnlock(l);
        LOGE("TrojanClient: failed to start async dns resolve for %s: %s", request->domain, ares_strerror(rc));
        dnsRequestDestroy(request);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("TrojanClient: resolving target domain %s", request->domain);
    }

    *started_out = true;
    return true;
}

static bool sendInitialRequest(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    trojanclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t      assoc_target = {0};
    const address_context_t *target  = &ls->target_addr;
    uint8_t                cmd      = protocolToCommand(ls->protocol);
    uint32_t               addr_len = 0;

    if (ls->protocol == kTrojanClientProtocolUdp)
    {
        fillUdpAssociateRequestTarget(&assoc_target);
        target = &assoc_target;
    }

    if (UNLIKELY(! trojanclientAddressLength(target, &addr_len)))
    {
        LOGE("TrojanClient: target settings are not populated");
        addresscontextReset(&assoc_target);
        return false;
    }

    uint32_t len = kTrojanClientPasswordHexLen + kTrojanClientCrlfLen + 1U + addr_len + kTrojanClientCrlfLen;
    sbuf_t  *buf = allocProtocolBuffer(l, len);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;

    memoryCopy(ptr + off, ts->password_hex, kTrojanClientPasswordHexLen);
    off += kTrojanClientPasswordHexLen;
    ptr[off++] = '\r';
    ptr[off++] = '\n';
    ptr[off++] = cmd;

    if (UNLIKELY(! trojanclientWriteAddress(ptr, target, &off)))
    {
        lineReuseBuffer(l, buf);
        addresscontextReset(&assoc_target);
        return false;
    }

    ptr[off++] = '\r';
    ptr[off++] = '\n';

    if (ts->verbose)
    {
        LOGD("TrojanClient: sending command %u for target port %u",
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
        sbuf_t  *wrapped = allocProtocolBuffer(l, payload + header_len);
        uint8_t *dst     = sbufGetMutablePtr(wrapped);
        memoryCopy(dst + header_len, sbufGetRawPtr(buf), payload);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    else
    {
        sbufShiftLeft(buf, header_len);
    }

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

static bool forwardUdpPayloadToCarrier(tunnel_t *t, line_t *app_l, trojanclient_lstate_t *app_ls, sbuf_t *buf)
{
    if (UNLIKELY(app_ls->carrier_line == NULL || ! lineIsAlive(app_ls->carrier_line)))
    {
        lineReuseBuffer(app_l, buf);
        trojanclientCloseLine(t, app_l, kTrojanClientCloseInternal);
        return false;
    }

    if (UNLIKELY(sbufGetLength(buf) > kTrojanClientUdpMaxPacket))
    {
        trojanclient_tstate_t *ts = tunnelGetState(t);
        if (ts->verbose)
        {
            LOGD("TrojanClient: dropping oversized UDP payload len=%u limit=%u",
                 (unsigned int) sbufGetLength(buf),
                 (unsigned int) kTrojanClientUdpMaxPacket);
        }
        lineReuseBuffer(app_l, buf);
        return true;
    }

    if (UNLIKELY(! wrapUdpPayload(app_l, &buf, &app_ls->target_addr)))
    {
        lineReuseBuffer(app_l, buf);
        trojanclientCloseLine(t, app_l, kTrojanClientCloseInternal);
        return false;
    }

    return withLineLockedWithBuf(app_ls->carrier_line, tunnelNextUpStreamPayload, t, buf);
}

static bool drainQueuedUdpPayloads(tunnel_t *t, line_t *app_l, trojanclient_lstate_t *app_ls, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        if (UNLIKELY(! forwardUdpPayloadToCarrier(t, app_l, app_ls, bufferqueuePopFront(queue))))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

bool trojanclientStartUdpCarrier(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, bool *line_alive_out)
{
    *line_alive_out = true;
    lineLock(l);

    line_t                 *carrier_l  = createInternalLine(t, l, kTrojanClientLineKindUdpCarrier);
    trojanclient_lstate_t  *carrier_ls = lineGetState(carrier_l, t);

    addresscontextAddrCopy(&carrier_ls->target_addr, &ls->target_addr);
    carrier_ls->protocol = ls->protocol;
    setLineProtocol(carrier_l, IP_PROTO_TCP);

    ls->carrier_line = carrier_l;

    if (UNLIKELY(! withLineLocked(carrier_l, tunnelNextUpStreamInit, t)))
    {
        if (lineIsAlive(l))
        {
            ls->carrier_line = NULL;
        }
        *line_alive_out = lineIsAlive(l);
        lineUnlock(l);
        return false;
    }

    *line_alive_out = lineIsAlive(l);
    if (! *line_alive_out)
    {
        trojanclientCloseOwnedLine(t, carrier_l);
    }
    lineUnlock(l);

    return true;
}

bool trojanclientForwardUdpAppPayload(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *buf)
{
    if (ls->phase == kTrojanClientPhaseEstablished)
    {
        return forwardUdpPayloadToCarrier(t, l, ls, buf);
    }

    bufferqueuePushBack(&ls->pending_up, buf);

    if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_up) > kTrojanClientMaxPendingBytes))
    {
        LOGE("TrojanClient: UDP carrier queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(&ls->pending_up),
             (unsigned int) kTrojanClientMaxPendingBytes);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return false;
    }

    return true;
}

static bool udpFrameHeaderLength(buffer_stream_t *stream, uint16_t *packet_size, uint32_t *full_len)
{
    if (bufferstreamGetBufLen(stream) == 0)
    {
        return true;
    }

    uint8_t  atyp       = bufferstreamViewByteAt(stream, 0);
    uint32_t header_len = 0;

    switch (atyp)
    {
    case kTrojanAtypIpv4:
        header_len = 1 + 4 + 2 + 2 + 2;
        if (bufferstreamGetBufLen(stream) < header_len)
        {
            return true;
        }
        *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 4 + 2) << 8U) |
                       bufferstreamViewByteAt(stream, 1 + 4 + 2 + 1);
        break;

    case kTrojanAtypDomain:
        if (bufferstreamGetBufLen(stream) < 1 + 1)
        {
            return true;
        }
        {
            uint8_t domain_len = bufferstreamViewByteAt(stream, 1);
            if (UNLIKELY(domain_len == 0))
            {
                return false;
            }
            header_len = 1U + 1U + domain_len + 2U + 2U + 2U;
            if (bufferstreamGetBufLen(stream) < header_len)
            {
                return true;
            }
            *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 1 + domain_len + 2) << 8U) |
                           bufferstreamViewByteAt(stream, 1 + 1 + domain_len + 2 + 1);
        }
        break;

    case kTrojanAtypIpv6:
        header_len = 1 + 16 + 2 + 2 + 2;
        if (bufferstreamGetBufLen(stream) < header_len)
        {
            return true;
        }
        *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 1 + 16 + 2) << 8U) |
                       bufferstreamViewByteAt(stream, 1 + 16 + 2 + 1);
        break;

    default:
        return false;
    }

    if (UNLIKELY(*packet_size > kTrojanClientUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(bufferstreamViewByteAt(stream, header_len - 2U) != '\r' ||
                 bufferstreamViewByteAt(stream, header_len - 1U) != '\n'))
    {
        return false;
    }

    *full_len = header_len + *packet_size;
    return true;
}

static bool parseUdpFrame(sbuf_t *packet, address_context_t *source, uint16_t *header_len, uint16_t *packet_size)
{
    const uint8_t *raw      = sbufGetRawPtr(packet);
    size_t         len      = sbufGetLength(packet);
    size_t         addr_len = 0;

    int parsed = trojanclientParseAddressBytes(raw, len, source, &addr_len);
    if (UNLIKELY(parsed != 1 || len < addr_len + 4U))
    {
        return false;
    }

    uint16_t size_be = 0;
    memoryCopy(&size_be, raw + addr_len, sizeof(size_be));
    *packet_size = be16toh(size_be);

    if (UNLIKELY(*packet_size > kTrojanClientUdpMaxPacket || raw[addr_len + 2U] != '\r' ||
                 raw[addr_len + 3U] != '\n' || len != addr_len + 4U + *packet_size))
    {
        return false;
    }

    *header_len = (uint16_t) (addr_len + 4U);
    return true;
}

static bool drainUdpFrames(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        uint16_t packet_size = 0;
        uint32_t full_len    = 0;

        if (UNLIKELY(! udpFrameHeaderLength(&ls->in_stream, &packet_size, &full_len)))
        {
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            return false;
        }

        if (full_len == 0 || bufferstreamGetBufLen(&ls->in_stream) < full_len)
        {
            return true;
        }

        sbuf_t           *packet             = bufferstreamReadExact(&ls->in_stream, full_len);
        address_context_t source             = {0};
        uint16_t          header_len         = 0;
        uint16_t          parsed_packet_size = 0;

        if (UNLIKELY(! parseUdpFrame(packet, &source, &header_len, &parsed_packet_size) ||
                     parsed_packet_size != packet_size || ! addresscontextHasPort(&source)))
        {
            addresscontextReset(&source);
            lineReuseBuffer(l, packet);
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            return false;
        }

        addresscontextReset(&source);
        sbufShiftRight(packet, header_len);

        line_t *app_l = ls->app_line;
        if (UNLIKELY(app_l == NULL || ! lineIsAlive(app_l)))
        {
            lineReuseBuffer(l, packet);
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            return false;
        }

        lineLock(l);
        bool app_alive     = withLineLockedWithBuf(app_l, tunnelPrevDownStreamPayload, t, packet);
        bool carrier_alive = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! app_alive || ! carrier_alive))
        {
            return false;
        }
    }

    return true;
}

bool trojanclientHandleUdpCarrierPayload(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *buf)
{
    bufferstreamPush(&ls->in_stream, buf);

    if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) > kTrojanClientMaxBufferedBytes))
    {
        LOGE("TrojanClient: UDP carrier input buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kTrojanClientMaxBufferedBytes);
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return false;
    }

    if (ls->phase != kTrojanClientPhaseEstablished)
    {
        return true;
    }

    return drainUdpFrames(t, l, ls);
}

bool trojanclientOnTransportEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ls->phase != kTrojanClientPhaseIdle))
    {
        LOGW("TrojanClient: duplicate downstream establish while phase=%d", ls->phase);
        return true;
    }

    if (UNLIKELY(! sendInitialRequest(t, l, ls)))
    {
        return false;
    }

    ls->phase = kTrojanClientPhaseEstablished;

    if (ls->kind == kTrojanClientLineKindUdpCarrier)
    {
        line_t *app_l = ls->app_line;
        if (UNLIKELY(app_l == NULL || ! lineIsAlive(app_l)))
        {
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            return false;
        }

        trojanclient_lstate_t *app_ls = lineGetState(app_l, t);
        buffer_queue_t         pending_local = bufferqueueCreate(kTrojanClientPendingQueueCap);

        while (bufferqueueGetBufCount(&app_ls->pending_up) > 0)
        {
            bufferqueuePushBack(&pending_local, bufferqueuePopFront(&app_ls->pending_up));
        }

        if (ts->verbose)
        {
            LOGD("TrojanClient: UDP association established");
        }

        lineLock(l);
        bool app_alive     = withLineLocked(app_l, tunnelPrevDownStreamEst, t);
        bool carrier_alive = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! app_alive || ! carrier_alive))
        {
            bufferqueueDestroy(&pending_local);
            return false;
        }

        while (bufferqueueGetBufCount(&app_ls->pending_up) > 0)
        {
            bufferqueuePushBack(&pending_local, bufferqueuePopFront(&app_ls->pending_up));
        }

        app_ls->phase = kTrojanClientPhaseEstablished;

        if (UNLIKELY(! drainQueuedUdpPayloads(t, app_l, app_ls, &pending_local)))
        {
            return false;
        }

        return drainUdpFrames(t, l, ls);
    }

    buffer_queue_t pending_local = bufferqueueCreate(kTrojanClientPendingQueueCap);
    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        bufferqueuePushBack(&pending_local, bufferqueuePopFront(&ls->pending_up));
    }

    if (ts->verbose)
    {
        LOGD("TrojanClient: TCP request sent");
    }

    if (UNLIKELY(! withLineLocked(l, tunnelPrevDownStreamEst, t)))
    {
        bufferqueueDestroy(&pending_local);
        return false;
    }

    if (UNLIKELY(! flushQueueToNext(t, l, &pending_local)))
    {
        return false;
    }

    return flushStreamToPrev(t, l, &ls->in_stream);
}

void trojanclientCloseOwnedLine(tunnel_t *t, line_t *owned_l)
{
    if (owned_l == NULL || ! lineIsAlive(owned_l))
    {
        return;
    }

    trojanclient_lstate_t *ls = lineGetState(owned_l, t);
    if (ls->phase == kTrojanClientPhaseClosing)
    {
        return;
    }

    ls->phase = kTrojanClientPhaseClosing;
    trojanclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, owned_l);
    if (lineIsAlive(owned_l))
    {
        lineDestroy(owned_l);
    }
}

void trojanclientCloseLine(tunnel_t *t, line_t *l, trojanclient_close_origin_t origin)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kTrojanClientPhaseClosing)
    {
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpApp)
    {
        line_t *carrier_l = ls->carrier_line;
        ls->carrier_line  = NULL;
        ls->phase         = kTrojanClientPhaseClosing;

        trojanclientCloseOwnedLine(t, carrier_l);
        trojanclientLinestateDestroy(ls);

        if (origin != kTrojanClientCloseFromPrev)
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpCarrier)
    {
        line_t                *app_l     = ls->app_line;
        trojanclient_lstate_t *app_ls    = NULL;
        bool                   close_app = false;

        if (app_l != NULL && lineIsAlive(app_l))
        {
            app_ls = lineGetState(app_l, t);
            if (app_ls->phase != kTrojanClientPhaseClosing)
            {
                if (app_ls->carrier_line == l)
                {
                    app_ls->carrier_line = NULL;
                }
                close_app = true;
            }
        }

        ls->phase = kTrojanClientPhaseClosing;
        trojanclientLinestateDestroy(ls);

        if (origin != kTrojanClientCloseFromNext)
        {
            tunnelNextUpStreamFinish(t, l);
        }
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }

        if (close_app && app_l != NULL && lineIsAlive(app_l))
        {
            app_ls->phase = kTrojanClientPhaseClosing;
            trojanclientLinestateDestroy(app_ls);
            tunnelPrevDownStreamFinish(t, app_l);
        }
        return;
    }

    bool transport_started = ls->phase != kTrojanClientPhaseResolving;
    ls->phase = kTrojanClientPhaseClosing;
    trojanclientLinestateDestroy(ls);

    if (transport_started && origin != kTrojanClientCloseFromNext)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (origin != kTrojanClientCloseFromPrev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

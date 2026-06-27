#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kVlessVersion    = 0x00,
    kVlessCmdTcp     = 0x01,
    kVlessCmdUdp     = 0x02,
    kVlessAtypIpv4   = 0x01,
    kVlessAtypDomain = 0x02,
    kVlessAtypIpv6   = 0x03
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

static bool getProtocolFromContext(const address_context_t *ctx, vlessclient_protocol_t *protocol_out)
{
    if (ctx->proto_tcp && ! ctx->proto_udp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolTcp;
        return true;
    }

    if (ctx->proto_udp && ! ctx->proto_tcp && ! ctx->proto_icmp && ! ctx->proto_packet)
    {
        *protocol_out = kVlessClientProtocolUdp;
        return true;
    }

    return false;
}

static vlessclient_protocol_t resolveConfiguredProtocol(const vlessclient_tstate_t *ts,
                                                        const address_context_t    *current_dest_ctx)
{
    if (ts->protocol != kVlessClientProtocolDestContext)
    {
        return ts->protocol;
    }

    vlessclient_protocol_t protocol = kVlessClientProtocolTcp;
    if (getProtocolFromContext(current_dest_ctx, &protocol))
    {
        return protocol;
    }

    LOGW("VlessClient: configured protocol is dest_context->protocol, but the destination context protocol was "
         "missing or invalid (tcp=%u, udp=%u, icmp=%u, packet=%u); falling back to TCP",
         (unsigned int) current_dest_ctx->proto_tcp,
         (unsigned int) current_dest_ctx->proto_udp,
         (unsigned int) current_dest_ctx->proto_icmp,
         (unsigned int) current_dest_ctx->proto_packet);
    return kVlessClientProtocolTcp;
}

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
    lineGetRoutingContext(l)->network_type = protocol == IP_PROTO_UDP ? WIO_TYPE_UDP : WIO_TYPE_TCP;
}

static line_t *createInternalLine(tunnel_t *t, line_t *app_l, vlessclient_line_kind_t kind)
{
    line_t *inner_l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(app_l));

    vlessclient_lstate_t *inner_ls = lineGetState(inner_l, t);
    vlessclientLinestateInitialize(inner_ls, t, inner_l);
    inner_ls->kind     = kind;
    inner_ls->app_line = app_l;

    return inner_l;
}

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    addresscontextReset(&ts->target_addr);
    memorySet(ts->uuid, 0, sizeof(ts->uuid));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l, vlessclient_protocol_t *protocol_out)
{
    vlessclient_tstate_t *ts       = tunnelGetState(t);
    address_context_t    *dest_ctx = lineGetDestinationAddressContext(l);
    routing_context_t    *route    = lineGetRoutingContext(l);
    address_context_t     current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant) ||
                             (ts->protocol == kVlessClientProtocolDestContext);

    if (uses_current_dest)
    {
        addresscontextAddrCopy(&current, dest_ctx);
        addresscontextSetPort(&current, dest_ctx->port);
    }

    vlessclient_protocol_t resolved_protocol = resolveConfiguredProtocol(ts, &current);

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextAddrCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (UNLIKELY(! addresscontextIsValid(&current)))
        {
            LOGE("VlessClient: configured to use dest_context->address, but line destination address is not set");
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
            LOGE("VlessClient: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (resolved_protocol == kVlessClientProtocolTcp)
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_TCP);
        route->network_type = WIO_TYPE_TCP;
    }
    else
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
        route->network_type = WIO_TYPE_UDP;
    }

    *protocol_out = resolved_protocol;

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

static bool sendInitialRequest(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, bool *line_alive_out)
{
    vlessclient_tstate_t    *ts       = tunnelGetState(t);
    const address_context_t *target   = &ls->target_addr;
    uint8_t                  cmd      = protocolToCommand(ls->protocol);
    uint32_t                 addr_len = 0;

    *line_alive_out = true;

    if (UNLIKELY(! vlessclientAddressLength(target, &addr_len)))
    {
        LOGE("VlessClient: target settings are not populated");
        return false;
    }

    uint32_t len = 1U + kVlessClientUuidLen + 1U + 1U + addr_len;
    sbuf_t  *buf = allocProtocolBuffer(l, len);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    size_t   off = 0;

    ptr[off++] = kVlessVersion;
    memoryCopy(ptr + off, ts->uuid, kVlessClientUuidLen);
    off += kVlessClientUuidLen;
    ptr[off++] = 0;
    ptr[off++] = cmd;

    if (UNLIKELY(! vlessclientWriteDestination(ptr, target, &off)))
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("VlessClient: sending command %u for target port %u", (unsigned int) cmd, (unsigned int) target->port);
    }

    ls->phase = kVlessClientPhaseWaitResponse;
    if (UNLIKELY(! sendBufferUpstream(t, l, buf)))
    {
        *line_alive_out = false;
        return false;
    }

    return true;
}

static bool wrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);

    if (UNLIKELY(payload == 0 || payload > kVlessClientUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kVlessClientUdpHeaderLen))
    {
        sbuf_t  *wrapped = allocProtocolBuffer(l, payload + kVlessClientUdpHeaderLen);
        uint8_t *dst     = sbufGetMutablePtr(wrapped);
        memoryCopy(dst + kVlessClientUdpHeaderLen, sbufGetRawPtr(buf), payload);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    else
    {
        sbufShiftLeft(buf, kVlessClientUdpHeaderLen);
    }

    *buf_io = buf;

    uint8_t *ptr        = sbufGetMutablePtr(buf);
    uint16_t payload_be = htobe16((uint16_t) payload);
    memoryCopy(ptr, &payload_be, sizeof(payload_be));
    return true;
}

static bool forwardUdpPayloadToCarrier(tunnel_t *t, line_t *app_l, vlessclient_lstate_t *app_ls, sbuf_t *buf)
{
    if (UNLIKELY(app_ls->carrier_line == NULL || ! lineIsAlive(app_ls->carrier_line)))
    {
        lineReuseBuffer(app_l, buf);
        vlessclientCloseLine(t, app_l, kVlessClientCloseInternal);
        return false;
    }

    if (UNLIKELY(sbufGetLength(buf) == 0 || sbufGetLength(buf) > kVlessClientUdpMaxPacket))
    {
        vlessclient_tstate_t *ts = tunnelGetState(t);
        if (ts->verbose)
        {
            LOGD("VlessClient: dropping invalid UDP payload len=%u limit=%u",
                 (unsigned int) sbufGetLength(buf),
                 (unsigned int) kVlessClientUdpMaxPacket);
        }
        lineReuseBuffer(app_l, buf);
        return true;
    }

    if (UNLIKELY(! wrapUdpPayload(app_l, &buf)))
    {
        lineReuseBuffer(app_l, buf);
        vlessclientCloseLine(t, app_l, kVlessClientCloseInternal);
        return false;
    }

    return withLineLockedWithBuf(app_ls->carrier_line, tunnelNextUpStreamPayload, t, buf);
}

static bool drainQueuedUdpPayloads(tunnel_t *t, line_t *app_l, vlessclient_lstate_t *app_ls, buffer_queue_t *queue)
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

bool vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, bool *line_alive_out)
{
    *line_alive_out = true;
    lineLock(l);

    line_t               *carrier_l  = createInternalLine(t, l, kVlessClientLineKindUdpCarrier);
    vlessclient_lstate_t *carrier_ls = lineGetState(carrier_l, t);

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
        vlessclientCloseOwnedLine(t, carrier_l);
    }
    lineUnlock(l);

    return true;
}

bool vlessclientForwardUdpAppPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf)
{
    if (ls->phase == kVlessClientPhaseEstablished)
    {
        return forwardUdpPayloadToCarrier(t, l, ls, buf);
    }

    bufferqueuePushBack(&ls->pending_up, buf);

    if (UNLIKELY(bufferqueueGetBufLen(&ls->pending_up) > kVlessClientMaxPendingBytes))
    {
        LOGE("VlessClient: UDP carrier queue overflow, size=%zu limit=%u",
             bufferqueueGetBufLen(&ls->pending_up),
             (unsigned int) kVlessClientMaxPendingBytes);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return false;
    }

    return true;
}

static bool udpFrameHeader(buffer_stream_t *stream, uint16_t *packet_size, uint32_t *full_len)
{
    size_t available = bufferstreamGetBufLen(stream);
    if (UNLIKELY(available == 0))
    {
        return true;
    }

    if (UNLIKELY(available < kVlessClientUdpHeaderLen))
    {
        return true;
    }

    *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 0) << 8U) | bufferstreamViewByteAt(stream, 1);
    if (UNLIKELY(*packet_size == 0 || *packet_size > kVlessClientUdpMaxPacket))
    {
        return false;
    }

    *full_len = (uint32_t) kVlessClientUdpHeaderLen + *packet_size;
    return true;
}

static bool drainUdpFrames(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        uint16_t packet_size = 0;
        uint32_t full_len    = 0;

        if (UNLIKELY(! udpFrameHeader(&ls->in_stream, &packet_size, &full_len)))
        {
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
            return false;
        }

        if (full_len == 0 || bufferstreamGetBufLen(&ls->in_stream) < full_len)
        {
            return true;
        }

        sbuf_t *packet = bufferstreamReadExact(&ls->in_stream, full_len);
        sbufShiftRight(packet, kVlessClientUdpHeaderLen);

        line_t *app_l = ls->app_line;
        if (UNLIKELY(app_l == NULL || ! lineIsAlive(app_l)))
        {
            lineReuseBuffer(l, packet);
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
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

static bool parseResponseHeader(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, bool *ready_out)
{
    *ready_out = false;

    if (bufferstreamGetBufLen(&ls->in_stream) < kVlessClientResponseLen)
    {
        return true;
    }

    uint8_t version    = bufferstreamViewByteAt(&ls->in_stream, 0);
    uint8_t addons_len = bufferstreamViewByteAt(&ls->in_stream, 1);

    if (UNLIKELY(version != kVlessVersion))
    {
        LOGE("VlessClient: invalid response header version=%u", (unsigned int) version);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return false;
    }

    // Plain VLESS does not need response addons, but a compliant server is allowed to send a
    // non-empty addons section (for example when a flow/seed addon is negotiated). Rejecting it
    // would needlessly break interoperability with such servers, so we accept the header and simply
    // skip the addons bytes. We still log a warning because a non-empty addons section is unexpected
    // for this plain client. Wait until the whole addons section has arrived before consuming it.
    uint32_t header_len = (uint32_t) kVlessClientResponseLen + addons_len;
    if (bufferstreamGetBufLen(&ls->in_stream) < header_len)
    {
        return true;
    }

    if (UNLIKELY(addons_len != 0))
    {
        LOGW("VlessClient: accepting response header with non-empty addons (len=%u)", (unsigned int) addons_len);
    }

    lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, header_len));
    ls->phase  = kVlessClientPhaseEstablished;
    *ready_out = true;
    return true;
}

static bool establishDirectAfterResponse(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    buffer_queue_t pending_local = bufferqueueCreate(kVlessClientPendingQueueCap);
    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        bufferqueuePushBack(&pending_local, bufferqueuePopFront(&ls->pending_up));
    }

    if (UNLIKELY(! flushQueueToNext(t, l, &pending_local)))
    {
        return false;
    }

    return flushStreamToPrev(t, l, &ls->in_stream);
}

static bool establishUdpAppAfterResponse(tunnel_t *t, line_t *carrier_l, vlessclient_lstate_t *carrier_ls)
{
    line_t *app_l = carrier_ls->app_line;
    if (UNLIKELY(app_l == NULL || ! lineIsAlive(app_l)))
    {
        vlessclientCloseLine(t, carrier_l, kVlessClientCloseInternal);
        return false;
    }

    vlessclient_lstate_t *app_ls        = lineGetState(app_l, t);
    buffer_queue_t        pending_local = bufferqueueCreate(kVlessClientPendingQueueCap);
    while (bufferqueueGetBufCount(&app_ls->pending_up) > 0)
    {
        bufferqueuePushBack(&pending_local, bufferqueuePopFront(&app_ls->pending_up));
    }

    if (UNLIKELY(! drainQueuedUdpPayloads(t, app_l, app_ls, &pending_local)))
    {
        return false;
    }

    return drainUdpFrames(t, carrier_l, carrier_ls);
}

bool vlessclientHandleDirectPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf)
{
    bufferstreamPush(&ls->in_stream, buf);

    if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) > kVlessClientMaxBufferedBytes))
    {
        LOGE("VlessClient: downstream buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kVlessClientMaxBufferedBytes);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return false;
    }

    if (ls->phase == kVlessClientPhaseWaitResponse)
    {
        bool ready = false;
        if (UNLIKELY(! parseResponseHeader(t, l, ls, &ready)))
        {
            return false;
        }

        if (! ready)
        {
            return true;
        }

        return establishDirectAfterResponse(t, l, ls);
    }

    if (ls->phase == kVlessClientPhaseEstablished)
    {
        return flushStreamToPrev(t, l, &ls->in_stream);
    }

    return true;
}

bool vlessclientHandleUdpCarrierPayload(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *buf)
{
    bufferstreamPush(&ls->in_stream, buf);

    if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) > kVlessClientMaxBufferedBytes))
    {
        LOGE("VlessClient: UDP carrier input buffer overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->in_stream),
             (unsigned int) kVlessClientMaxBufferedBytes);
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return false;
    }

    if (ls->phase == kVlessClientPhaseWaitResponse)
    {
        bool ready = false;
        if (UNLIKELY(! parseResponseHeader(t, l, ls, &ready)))
        {
            return false;
        }

        if (! ready)
        {
            return true;
        }

        return establishUdpAppAfterResponse(t, l, ls);
    }

    if (ls->phase != kVlessClientPhaseEstablished)
    {
        return true;
    }

    return drainUdpFrames(t, l, ls);
}

bool vlessclientOnTransportEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    vlessclient_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ls->phase != kVlessClientPhaseIdle))
    {
        LOGW("VlessClient: duplicate downstream establish while phase=%d", ls->phase);
        return true;
    }

    if (ls->kind == kVlessClientLineKindUdpCarrier)
    {
        line_t *app_l = ls->app_line;
        if (UNLIKELY(app_l == NULL || ! lineIsAlive(app_l)))
        {
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
            return false;
        }

        vlessclient_lstate_t *app_ls        = lineGetState(app_l, t);
        buffer_queue_t        pending_local = bufferqueueCreate(kVlessClientPendingQueueCap);

        // Forward Est before sending the VLESS request so re-entrant app payload queues locally;
        // the queued bytes are flushed only after the protocol header is on the wire.
        lineLock(l);
        bool app_alive     = withLineLocked(app_l, tunnelPrevDownStreamEst, t);
        bool carrier_alive = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! app_alive || ! carrier_alive))
        {
            bufferqueueDestroy(&pending_local);
            return false;
        }

        ls     = lineGetState(l, t);
        app_ls = lineGetState(app_l, t);

        bool line_alive = true;
        if (UNLIKELY(! sendInitialRequest(t, l, ls, &line_alive)))
        {
            bufferqueueDestroy(&pending_local);
            if (line_alive)
            {
                vlessclientCloseLine(t, l, kVlessClientCloseInternal);
            }
            return false;
        }

        if (ts->verbose)
        {
            LOGD("VlessClient: UDP request sent");
        }

        while (bufferqueueGetBufCount(&app_ls->pending_up) > 0)
        {
            bufferqueuePushBack(&pending_local, bufferqueuePopFront(&app_ls->pending_up));
        }

        app_ls->phase = kVlessClientPhaseEstablished;

        if (UNLIKELY(! drainQueuedUdpPayloads(t, app_l, app_ls, &pending_local)))
        {
            return false;
        }

        return true;
    }

    buffer_queue_t pending_local = bufferqueueCreate(kVlessClientPendingQueueCap);

    // Forward Est before sending the VLESS request so re-entrant app payload queues locally;
    // the queued bytes are flushed only after the protocol header is on the wire.
    if (UNLIKELY(! withLineLocked(l, tunnelPrevDownStreamEst, t)))
    {
        bufferqueueDestroy(&pending_local);
        return false;
    }

    ls              = lineGetState(l, t);
    bool line_alive = true;
    if (UNLIKELY(! sendInitialRequest(t, l, ls, &line_alive)))
    {
        bufferqueueDestroy(&pending_local);
        if (line_alive)
        {
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        }
        return false;
    }

    if (ts->verbose)
    {
        LOGD("VlessClient: TCP request sent");
    }

    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        bufferqueuePushBack(&pending_local, bufferqueuePopFront(&ls->pending_up));
    }

    return flushQueueToNext(t, l, &pending_local);
}

void vlessclientCloseOwnedLine(tunnel_t *t, line_t *owned_l)
{
    if (owned_l == NULL || ! lineIsAlive(owned_l))
    {
        return;
    }

    vlessclient_lstate_t *ls = lineGetState(owned_l, t);
    if (ls->phase == kVlessClientPhaseClosing)
    {
        return;
    }

    ls->phase = kVlessClientPhaseClosing;
    vlessclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, owned_l);
    if (lineIsAlive(owned_l))
    {
        lineDestroy(owned_l);
    }
}

void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kVlessClientPhaseClosing)
    {
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpApp)
    {
        line_t *carrier_l = ls->carrier_line;
        ls->carrier_line  = NULL;
        ls->phase         = kVlessClientPhaseClosing;

        vlessclientCloseOwnedLine(t, carrier_l);
        vlessclientLinestateDestroy(ls);

        if (origin != kVlessClientCloseFromPrev)
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpCarrier)
    {
        line_t               *app_l     = ls->app_line;
        vlessclient_lstate_t *app_ls    = NULL;
        bool                  close_app = false;

        if (app_l != NULL && lineIsAlive(app_l))
        {
            app_ls = lineGetState(app_l, t);
            if (app_ls->phase != kVlessClientPhaseClosing)
            {
                if (app_ls->carrier_line == l)
                {
                    app_ls->carrier_line = NULL;
                }
                close_app = true;
            }
        }

        ls->phase = kVlessClientPhaseClosing;
        vlessclientLinestateDestroy(ls);

        if (origin != kVlessClientCloseFromNext)
        {
            tunnelNextUpStreamFinish(t, l);
        }
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }

        if (close_app && app_l != NULL && lineIsAlive(app_l))
        {
            app_ls->phase = kVlessClientPhaseClosing;
            vlessclientLinestateDestroy(app_ls);
            tunnelPrevDownStreamFinish(t, app_l);
        }
        return;
    }

    ls->phase = kVlessClientPhaseClosing;
    vlessclientLinestateDestroy(ls);

    if (origin != kVlessClientCloseFromNext)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (origin != kVlessClientCloseFromPrev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

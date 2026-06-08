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
    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool flushQueueToNext(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    return true;
}

static bool flushQueueToPrev(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    return true;
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

static uint8_t protocolToCommand(socks5client_protocol_t protocol)
{
    return protocol == kSocks5ClientProtocolUdp ? kSocks5CommandUdpAssoc : kSocks5CommandConnect;
}

void socks5clientTunnelstateDestroy(socks5client_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    addresscontextReset(&ts->target_addr);

    if (ts->username != NULL)
    {
        memoryFree(ts->username);
        ts->username = NULL;
    }

    if (ts->password != NULL)
    {
        memorySet(ts->password, 0, ts->password_len);
        memoryFree(ts->password);
        ts->password = NULL;
    }

    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

bool socks5clientApplyTargetContext(tunnel_t *t, line_t *l)
{
    socks5client_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *dest_ctx = lineGetDestinationAddressContext(l);
    routing_context_t     *route    = lineGetRoutingContext(l);
    address_context_t      current  = {0};
    bool uses_current_dest = (ts->target_addr_source != kDvsConstant) || (ts->target_port_source != kDvsConstant);

    if (uses_current_dest)
    {
        addresscontextAddrCopy(&current, dest_ctx);
    }

    if (ts->target_addr_source == kDvsConstant)
    {
        addresscontextAddrCopy(dest_ctx, &ts->target_addr);
    }
    else
    {
        if (! addresscontextIsValid(&current))
        {
            LOGE("Socks5Client: configured to use dest_context->address, but line destination address is not set");
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
        if (current.port == 0)
        {
            LOGE("Socks5Client: configured to use dest_context->port, but line destination port is not set");
            addresscontextReset(&current);
            return false;
        }

        addresscontextSetPort(dest_ctx, current.port);
    }

    if (ts->protocol == kSocks5ClientProtocolTcp)
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_TCP);
        route->network_type = WIO_TYPE_TCP;
    }
    else
    {
        addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
        route->network_type = WIO_TYPE_UDP;
    }

    if (uses_current_dest)
    {
        addresscontextReset(&current);
    }

    return true;
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
    socks5client_tstate_t *ts       = tunnelGetState(t);
    address_context_t     *target   = lineGetDestinationAddressContext(l);
    uint8_t                cmd      = protocolToCommand(ts->protocol);
    uint8_t                atyp     = 0;
    uint32_t               addr_len = 0;

    if (addresscontextIsIp(target))
    {
        if (target->ip_address.type == IPADDR_TYPE_V4)
        {
            atyp     = kSocks5AddrTypeIpv4;
            addr_len = 4;
        }
        else if (target->ip_address.type == IPADDR_TYPE_V6)
        {
            atyp     = kSocks5AddrTypeIpv6;
            addr_len = 16;
        }
        else
        {
            LOGE("Socks5Client: unsupported IP type for destination context");
            return false;
        }
    }
    else if (addresscontextIsDomain(target))
    {
        atyp     = kSocks5AddrTypeDomain;
        addr_len = (uint32_t) target->domain_len + 1U;
    }
    else
    {
        LOGE("Socks5Client: target settings are not populated");
        return false;
    }

    uint32_t len = 4U + addr_len + 2U;
    sbuf_t  *buf = allocHandshakeBuffer(l, len);
    uint8_t *ptr = sbufGetMutablePtr(buf);

    ptr[0] = kSocks5Version;
    ptr[1] = cmd;
    ptr[2] = 0;
    ptr[3] = atyp;

    size_t offset = 4;
    if (atyp == kSocks5AddrTypeIpv4)
    {
        memoryCopy(ptr + offset, &target->ip_address.u_addr.ip4.addr, 4);
        offset += 4;
    }
    else if (atyp == kSocks5AddrTypeIpv6)
    {
        memoryCopy(ptr + offset, &target->ip_address.u_addr.ip6, 16);
        offset += 16;
    }
    else
    {
        ptr[offset++] = target->domain_len;
        memoryCopy(ptr + offset, target->domain, target->domain_len);
        offset += target->domain_len;
    }

    uint16_t port_be = htobe16(target->port);
    memoryCopy(ptr + offset, &port_be, sizeof(port_be));

    ls->phase = kSocks5ClientPhaseWaitCommand;

    if (ts->verbose)
    {
        LOGD("Socks5Client: sending proxy command %u for target port %u",
             (unsigned int) cmd,
             (unsigned int) target->port);
    }

    return sendBufferUpstream(t, l, buf);
}

void socks5clientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    socks5clientLinestateDestroy(lineGetState(l, t));
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

            uint8_t header[5];
            bufferstreamViewBytesAt(&ls->in_stream, 0, header, sizeof(header));
            lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, (size_t) reply_len));

            if (header[0] != kSocks5Version)
            {
                LOGE("Socks5Client: invalid command reply version 0x%02x", header[0]);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            if (header[1] != 0x00)
            {
                LOGE("Socks5Client: proxy command failed with reply code 0x%02x", header[1]);
                socks5clientCloseLineBidirectional(t, l);
                return false;
            }

            buffer_queue_t pending_local = bufferqueueCreate(kSocks5ClientPendingQueueCap);
            buffer_queue_t down_local    = bufferqueueCreate(kSocks5ClientPendingQueueCap);

            while (bufferqueueGetBufCount(&ls->pending_up) > 0)
            {
                bufferqueuePushBack(&pending_local, bufferqueuePopFront(&ls->pending_up));
            }

            while (! bufferstreamIsEmpty(&ls->in_stream))
            {
                bufferqueuePushBack(&down_local, bufferstreamIdealRead(&ls->in_stream));
            }

            ls->phase = kSocks5ClientPhaseEstablished;

            if (ts->verbose)
            {
                LOGD("Socks5Client: SOCKS5 handshake completed");
            }

            if (! withLineLocked(l, tunnelPrevDownStreamEst, t))
            {
                bufferqueueDestroy(&pending_local);
                bufferqueueDestroy(&down_local);
                return false;
            }

            if (! flushQueueToNext(t, l, &pending_local))
            {
                bufferqueueDestroy(&down_local);
                return false;
            }

            if (! flushQueueToPrev(t, l, &down_local))
            {
                return false;
            }

            return true;
        }

        return true;
    }
}

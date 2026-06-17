#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kVlessVersion      = 0x00,
    kVlessCmdTcp       = 0x01,
    kVlessCmdUdp       = 0x02,
    kVlessAtypIpv4     = 0x01,
    kVlessAtypDomain   = 0x02,
    kVlessAtypIpv6     = 0x03
};

static sbuf_t *vlessserverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        len <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);

    buf = sbufReserveSpace(buf, len);
    sbufSetLength(buf, len);
    return buf;
}

static bool vlessserverUuidAllowed(tunnel_t *t, line_t *l, const uint8_t uuid[kVlessServerUuidLen])
{
    vlessserver_tstate_t *ts      = tunnelGetState(t);
    bool                 matched = false;

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        matched |= wCryptoEqual(ts->users[i].uuid, uuid, kVlessServerUuidLen);
    }

    if (UNLIKELY(! matched && ts->verbose))
    {
        LOGW("VlessServer: rejected unknown UUID on worker %u", (unsigned int) lineGetWID(l));
    }

    return matched;
}

static int vlessserverParseDestination(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed)
{
    if (UNLIKELY(len < 3))
    {
        return 0;
    }

    uint16_t port_be = 0;
    memoryCopy(&port_be, buf, sizeof(port_be));
    uint16_t port = be16toh(port_be);
    uint8_t  atyp = buf[2];

    if (atyp == kVlessAtypIpv4)
    {
        if (UNLIKELY(len < 2 + 1 + 4))
        {
            return 0;
        }

        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V4;
        memoryCopy(&ip.u_addr.ip4.addr, buf + 3, 4);
        addresscontextSetIpPort(out, &ip, port);
        *consumed = 2 + 1 + 4;
        return 1;
    }

    if (atyp == kVlessAtypIpv6)
    {
        if (UNLIKELY(len < 2 + 1 + 16))
        {
            return 0;
        }

        ip_addr_t ip = {0};
        ip.type      = IPADDR_TYPE_V6;
        memoryCopy(&ip.u_addr.ip6, buf + 3, 16);
        addresscontextSetIpPort(out, &ip, port);
        *consumed = 2 + 1 + 16;
        return 1;
    }

    if (atyp == kVlessAtypDomain)
    {
        if (UNLIKELY(len < 2 + 1 + 1))
        {
            return 0;
        }

        uint8_t domain_len = buf[3];
        if (UNLIKELY(domain_len == 0))
        {
            return -1;
        }

        if (UNLIKELY(len < (size_t) (2 + 1 + 1 + domain_len)))
        {
            return 0;
        }

        addresscontextDomainSet(out, (const char *) (buf + 4), domain_len);
        addresscontextSetPort(out, port);
        *consumed = 2 + 1 + 1 + domain_len;
        return 1;
    }

    return -1;
}

static void vlessserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp)
{
    address_context_t *dest  = lineGetDestinationAddressContext(l);
    routing_context_t *route = lineGetRoutingContext(l);

    addresscontextAddrCopy(dest, target);
    addresscontextSetOnlyProtocol(dest, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    route->network_type = udp ? WIO_TYPE_UDP : WIO_TYPE_TCP;
}

static bool vlessserverFlushQueueToPrev(tunnel_t *t, line_t *l, buffer_queue_t *queue)
{
    while (bufferqueueGetBufCount(queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(queue);
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf)))
        {
            bufferqueueDestroy(queue);
            return false;
        }
    }

    bufferqueueDestroy(queue);
    return true;
}

static bool vlessserverSendResponseHeaderIfNeeded(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    if (LIKELY(ls->response_sent))
    {
        return true;
    }

    sbuf_t  *buf = vlessserverAllocBuffer(l, kVlessServerResponseLen);
    uint8_t *ptr = sbufGetMutablePtr(buf);
    ptr[0]       = kVlessVersion;
    ptr[1]       = 0;

    ls->response_sent = true;
    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

static bool vlessserverForwardBufferedTcpPayload(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *buf = bufferstreamIdealRead(&ls->in_stream);
        if (UNLIKELY(! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf)))
        {
            return false;
        }
    }

    return true;
}

static void vlessserverDetachRemoteFromClient(vlessserver_lstate_t *remote_ls)
{
    line_t *client_line = remote_ls->client_line;

    if (client_line != NULL && remote_ls->client_line_locked)
    {
        if (lineIsAlive(client_line))
        {
            vlessserver_lstate_t *client_ls = lineGetState(client_line, remote_ls->tunnel);
            if (client_ls->udp_remote_line == remote_ls->line)
            {
                client_ls->udp_remote_line = NULL;
            }
        }

        lineUnlock(client_line);
    }

    remote_ls->client_line        = NULL;
    remote_ls->client_line_locked = false;
}

static line_t *vlessserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, vlessserver_lstate_t *client_ls)
{
    if (client_ls->udp_remote_line != NULL && lineIsAlive(client_ls->udp_remote_line))
    {
        return client_ls->udp_remote_line;
    }

    if (UNLIKELY(! addresscontextHasPort(&client_ls->udp_target)))
    {
        return NULL;
    }

    line_t                *remote_l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(client_l));
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    vlessserverLinestateInitialize(remote_ls, t, remote_l, kVlessServerLineKindUdpRemote);
    remote_ls->client_line        = client_l;
    remote_ls->client_line_locked = true;
    remote_ls->phase              = kVlessServerPhaseUdpConnecting;

    lineLock(client_l);

    lineGetRoutingContext(remote_l)->local_listener_port = lineGetRoutingContext(client_l)->local_listener_port;
    lineCopyUsers(remote_l, client_l);
    vlessserverApplyDestinationContext(remote_l, &client_ls->udp_target, true);
    client_ls->udp_remote_line = remote_l;

    if (UNLIKELY(! withLineLocked(remote_l, tunnelNextUpStreamInit, t)))
    {
        return NULL;
    }

    return remote_l;
}

static bool vlessserverInitialCommandIsAllowed(tunnel_t *t, uint8_t cmd)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    if (cmd == kVlessCmdTcp)
    {
        return ts->allow_connect;
    }

    if (cmd == kVlessCmdUdp)
    {
        return ts->allow_udp;
    }

    return false;
}

static bool vlessserverStartTcpBranch(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                      const address_context_t *target)
{
    vlessserverApplyDestinationContext(l, target, false);
    ls->phase = kVlessServerPhaseTcpConnecting;

    if (UNLIKELY(! withLineLocked(l, tunnelNextUpStreamInit, t)))
    {
        return false;
    }

    return vlessserverForwardBufferedTcpPayload(t, l, ls);
}

static bool vlessserverStartUdpBranch(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                      const address_context_t *target)
{
    addresscontextAddrCopy(&ls->udp_target, target);
    ls->phase = kVlessServerPhaseUdpConnecting;

    lineLock(l);
    line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
    bool    client_alive = lineIsAlive(l);
    lineUnlock(l);

    if (UNLIKELY(! client_alive))
    {
        return false;
    }

    if (UNLIKELY(remote_l == NULL))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    return vlessserverDrainInput(t, l, ls);
}

static bool vlessserverHandleInitialRequest(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    size_t available = bufferstreamGetBufLen(&ls->in_stream);

    if (UNLIKELY(available < 1))
    {
        return true;
    }

    if (UNLIKELY(bufferstreamViewByteAt(&ls->in_stream, 0) != kVlessVersion))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    if (UNLIKELY(available < 1 + kVlessServerUuidLen + 1))
    {
        return true;
    }

    uint8_t user_id[kVlessServerUuidLen] = {0};
    bufferstreamViewBytesAt(&ls->in_stream, 1, user_id, sizeof(user_id));
    if (UNLIKELY(! vlessserverUuidAllowed(t, l, user_id)))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    uint8_t addons_len = bufferstreamViewByteAt(&ls->in_stream, 1 + kVlessServerUuidLen);
    size_t  command_at = 1U + kVlessServerUuidLen + 1U + addons_len;

    if (UNLIKELY(available < command_at))
    {
        if (UNLIKELY(available > kVlessServerMaxInitialBytes))
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    if (UNLIKELY(addons_len != 0))
    {
        if (UNLIKELY(available < command_at))
        {
            return true;
        }
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    if (UNLIKELY(available < command_at + 1U))
    {
        return true;
    }

    uint8_t request_buf[kVlessServerInitialMaxReqLen] = {0};
    size_t  copy_len = min(sizeof(request_buf), available);
    bufferstreamViewBytesAt(&ls->in_stream, 0, request_buf, copy_len);

    uint8_t cmd = request_buf[command_at];
    if (UNLIKELY(! vlessserverInitialCommandIsAllowed(t, cmd)))
    {
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    address_context_t target   = {0};
    size_t            dest_len = 0;
    int parse_res =
        vlessserverParseDestination(request_buf + command_at + 1U,
                                    copy_len > command_at + 1U ? copy_len - command_at - 1U : 0U,
                                    &target,
                                    &dest_len);

    if (UNLIKELY(parse_res == 0))
    {
        addresscontextReset(&target);
        if (UNLIKELY(available > kVlessServerMaxInitialBytes))
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }
        return true;
    }

    if (UNLIKELY(parse_res < 0 || ! addresscontextHasPort(&target)))
    {
        addresscontextReset(&target);
        vlessserverCloseLineBidirectional(t, l);
        return false;
    }

    size_t request_len = command_at + 1U + dest_len;
    lineReuseBuffer(l, bufferstreamReadExact(&ls->in_stream, request_len));

    bool ok = cmd == kVlessCmdTcp ? vlessserverStartTcpBranch(t, l, ls, &target)
                                  : vlessserverStartUdpBranch(t, l, ls, &target);
    addresscontextReset(&target);
    return ok;
}

static bool vlessserverUdpFrameHeader(buffer_stream_t *stream, uint16_t *packet_size, uint32_t *full_len)
{
    size_t available = bufferstreamGetBufLen(stream);
    if (UNLIKELY(available == 0))
    {
        return true;
    }

    if (UNLIKELY(available < kVlessServerUdpHeaderLen))
    {
        return true;
    }

    *packet_size = ((uint16_t) bufferstreamViewByteAt(stream, 0) << 8U) | bufferstreamViewByteAt(stream, 1);
    if (UNLIKELY(*packet_size == 0 || *packet_size > kVlessServerUdpMaxPacket))
    {
        return false;
    }

    *full_len = (uint32_t) kVlessServerUdpHeaderLen + *packet_size;
    return true;
}

static bool vlessserverDrainUdpPackets(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        uint16_t packet_size = 0;
        uint32_t full_len    = 0;

        if (UNLIKELY(! vlessserverUdpFrameHeader(&ls->in_stream, &packet_size, &full_len)))
        {
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }

        if (UNLIKELY(bufferstreamGetBufLen(&ls->in_stream) < full_len))
        {
            return true;
        }

        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *packet = bufferstreamReadExact(&ls->in_stream, full_len);
        sbufShiftRight(packet, kVlessServerUdpHeaderLen);

        lineLock(l);
        line_t *remote_l     = vlessserverGetOrCreateUdpRemoteLine(t, l, ls);
        bool    client_alive = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! client_alive))
        {
            bufferpoolReuseBuffer(pool, packet);
            return false;
        }

        if (UNLIKELY(remote_l == NULL))
        {
            bufferpoolReuseBuffer(pool, packet);
            vlessserverCloseLineBidirectional(t, l);
            return false;
        }

        if (ls->phase == kVlessServerPhaseUdpWaitPacket)
        {
            ls->phase = kVlessServerPhaseUdpConnecting;
        }

        lineLock(l);
        bool remote_alive = withLineLockedWithBuf(remote_l, tunnelNextUpStreamPayload, t, packet);
        client_alive      = lineIsAlive(l);
        lineUnlock(l);

        if (UNLIKELY(! client_alive))
        {
            return false;
        }

        if (UNLIKELY(! remote_alive))
        {
            continue;
        }
    }

    return true;
}

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    if (ls->phase == kVlessServerPhaseWaitInitial)
    {
        return vlessserverHandleInitialRequest(t, l, ls);
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return vlessserverDrainUdpPackets(t, l, ls);
    }

    return true;
}

static bool vlessserverHasTcpUpstreamPeer(const vlessserver_lstate_t *ls)
{
    return ls->line_kind == kVlessServerLineKindClient &&
           (ls->phase == kVlessServerPhaseTcpConnecting || ls->phase == kVlessServerPhaseTcpEstablished);
}

static void vlessserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next)
{
    vlessserver_lstate_t *remote_ls = lineGetState(remote_l, t);

    if (UNLIKELY(remote_ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    remote_ls->phase = kVlessServerPhaseClosing;
    lineLock(remote_l);

    vlessserverDetachRemoteFromClient(remote_ls);
    vlessserverLinestateDestroy(remote_ls);

    if (close_next && LIKELY(lineIsAlive(remote_l)))
    {
        tunnelNextUpStreamFinish(t, remote_l);
    }

    if (LIKELY(lineIsAlive(remote_l)))
    {
        lineDestroy(remote_l);
    }

    lineUnlock(remote_l);
}

static void vlessserverCloseOwnedUdpRemoteLine(tunnel_t *t, vlessserver_lstate_t *client_ls, bool close_next)
{
    line_t *remote_l = client_ls->udp_remote_line;

    if (remote_l == NULL || ! lineIsAlive(remote_l))
    {
        return;
    }

    vlessserverCloseUdpRemoteLineInternal(t, remote_l, close_next);
}

static void vlessserverCloseLine(tunnel_t *t, line_t *l, vlessserver_close_origin_t origin)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->line_kind == kVlessServerLineKindUdpRemote))
    {
        vlessserverCloseUdpRemoteLineInternal(t, l, origin != kVlessServerCloseFromNext);
        return;
    }

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    bool close_next = origin != kVlessServerCloseFromNext && vlessserverHasTcpUpstreamPeer(ls);
    bool close_prev = origin != kVlessServerCloseFromPrev;

    ls->phase = kVlessServerPhaseClosing;
    lineLock(l);

    vlessserverCloseOwnedUdpRemoteLine(t, ls, origin != kVlessServerCloseFromNext);
    vlessserverLinestateDestroy(ls);

    if (close_next && LIKELY(lineIsAlive(l)))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (close_prev && LIKELY(lineIsAlive(l)))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

void vlessserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromPrev);
}

void vlessserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseFromNext);
}

void vlessserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    vlessserverCloseLine(t, l, kVlessServerCloseInternal);
}

void vlessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls)
{
    buffer_queue_t down_local = bufferqueueCreate(kVlessServerBufferQueueCap);

    while (bufferqueueGetBufCount(&ls->pending_down) > 0)
    {
        bufferqueuePushBack(&down_local, bufferqueuePopFront(&ls->pending_down));
    }

    if (UNLIKELY(ls->line_kind == kVlessServerLineKindUdpRemote))
    {
        if (ls->phase == kVlessServerPhaseUdpConnecting)
        {
            ls->phase = kVlessServerPhaseUdpEstablished;
        }

        line_t *client_l = ls->client_line;
        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            bufferqueueDestroy(&down_local);
            vlessserverCloseLineBidirectional(t, l);
            return;
        }

        lineLock(l);
        vlessserver_lstate_t *client_ls = lineGetState(client_l, t);
        if (client_ls->phase == kVlessServerPhaseUdpWaitPacket ||
            client_ls->phase == kVlessServerPhaseUdpConnecting)
        {
            client_ls->phase = kVlessServerPhaseUdpEstablished;
        }

        if (! client_ls->response_sent)
        {
            bool client_alive = withLineLocked(client_l, tunnelPrevDownStreamEst, t);
            bool remote_alive = lineIsAlive(l);
            if (UNLIKELY(! client_alive || ! remote_alive))
            {
                bufferqueueDestroy(&down_local);
                lineUnlock(l);
                return;
            }

            if (UNLIKELY(! vlessserverSendResponseHeaderIfNeeded(t, client_l, client_ls)))
            {
                bufferqueueDestroy(&down_local);
                lineUnlock(l);
                return;
            }

            if (UNLIKELY(! lineIsAlive(l)))
            {
                bufferqueueDestroy(&down_local);
                lineUnlock(l);
                return;
            }
        }

        discard vlessserverFlushQueueToPrev(t, client_l, &down_local);
        lineUnlock(l);
        return;
    }

    if (ls->phase == kVlessServerPhaseTcpConnecting)
    {
        ls->phase = kVlessServerPhaseTcpEstablished;
    }

    if (UNLIKELY(! withLineLocked(l, tunnelPrevDownStreamEst, t)))
    {
        bufferqueueDestroy(&down_local);
        return;
    }

    if (UNLIKELY(! vlessserverSendResponseHeaderIfNeeded(t, l, ls)))
    {
        bufferqueueDestroy(&down_local);
        return;
    }

    vlessserverFlushQueueToPrev(t, l, &down_local);
}

bool vlessserverWrapUdpPayload(line_t *l, sbuf_t **buf_io)
{
    sbuf_t  *buf     = *buf_io;
    uint32_t payload = sbufGetLength(buf);

    if (UNLIKELY(payload == 0 || payload > kVlessServerUdpMaxPacket))
    {
        return false;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kVlessServerUdpHeaderLen))
    {
        sbuf_t  *wrapped = vlessserverAllocBuffer(l, payload + kVlessServerUdpHeaderLen);
        uint8_t *dst     = sbufGetMutablePtr(wrapped);
        memoryCopy(dst + kVlessServerUdpHeaderLen, sbufGetRawPtr(buf), payload);
        lineReuseBuffer(l, buf);
        buf = wrapped;
    }
    else
    {
        sbufShiftLeft(buf, kVlessServerUdpHeaderLen);
    }

    *buf_io = buf;

    uint8_t *ptr     = sbufGetMutablePtr(buf);
    uint16_t len_be  = htobe16((uint16_t) payload);
    memoryCopy(ptr, &len_be, sizeof(len_be));
    return true;
}

void vlessserverTunnelstateDestroy(vlessserver_tstate_t *ts)
{
    memoryFree(ts->users);
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

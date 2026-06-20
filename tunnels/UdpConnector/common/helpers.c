#include "structure.h"

#include "loggers/network_logger.h"

local_idle_table_t *udpconnectorGetWorkerIdleTable(udpconnector_tstate_t *ts)
{
    assert(ts != NULL);
    assert(ts->idle_tables != NULL);

    wid_t wid = getWID();
    assert(wid < getWorkersCount());

    local_idle_table_t *table = ts->idle_tables[wid];
    if (table == NULL)
    {
        table                = localIdleTableCreate(getWorkerLoop(wid));
        ts->idle_tables[wid] = table;
    }

    return table;
}

local_idle_table_t *udpconnectorGetLineIdleTable(udpconnector_tstate_t *ts, line_t *l)
{
    assert(l != NULL);
    assert(lineGetWID(l) == getWID());
    discard l;
    return udpconnectorGetWorkerIdleTable(ts);
}

static bool udpconnectorSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
{
    if (lhs == NULL || rhs == NULL || lhs->sa.sa_family != rhs->sa.sa_family)
    {
        return false;
    }

    switch (lhs->sa.sa_family)
    {
    case AF_INET:
        return lhs->sin.sin_port == rhs->sin.sin_port && lhs->sin.sin_addr.s_addr == rhs->sin.sin_addr.s_addr;
    case AF_INET6:
        return lhs->sin6.sin6_port == rhs->sin6.sin6_port && memoryCompare(lhs->sin6.sin6_addr.s6_addr,
                                                                           rhs->sin6.sin6_addr.s6_addr,
                                                                           sizeof(lhs->sin6.sin6_addr.s6_addr)) == 0;
    default:
        return false;
    }
}

void udpconnectorOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    udpconnector_lstate_t *ls = (udpconnector_lstate_t *) (weventGetUserdata(io));

    if (ls == NULL || ls->read_paused)
    {
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    // LOGD("reading %d bytes", sbufGetLength(buf));

    tunnel_t              *t       = ls->tunnel;
    line_t                *l       = ls->line;
    sbuf_t                *payload = buf;
    udpconnector_tstate_t *ts      = tunnelGetState(t);

    if (ts->balance_mode == kUdpConnectorBalanceModeConnection &&
        ! udpconnectorSockAddrEquals(wioGetPeerAddrU(io), &ls->peer_addr))
    {
        if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
        {
            char expected_peeraddrstr[SOCKADDR_STRLEN] = {0};
            char actual_peeraddrstr[SOCKADDR_STRLEN]   = {0};

            LOGD("UdpConnector: dropped %u-byte datagram from unexpected peer [%s], expected [%s]",
                 sbufGetLength(payload),
                 SOCKADDR_STR(wioGetPeerAddrU(io), actual_peeraddrstr),
                 SOCKADDR_STR(&ls->peer_addr, expected_peeraddrstr));
        }

        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), payload);
        return;
    }

    if (! ls->established)
    {
        ls->established = true;
        if (! withLineLocked(l, tunnelPrevDownStreamEst, t))
        {
            LOGW("UdpConnector: socket just got closed by upstream before anything happend");
            bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), payload);
            return;
        }
    }

    localidletableKeepIdleItemForAtleast(udpconnectorGetLineIdleTable(ts, l), ls->idle_handle, kUdpKeepExpireTime);

    tunnelPrevDownStreamPayload(t, l, payload);
}

void udpconnectorOnClose(wio_t *io)
{
    udpconnector_lstate_t *ls = (udpconnector_lstate_t *) (weventGetUserdata(io));
    if (ls != NULL)
    {
        LOGD("UdpConnector: received close for FD:%x ", wioGetFD(io));
        weventSetUserData(ls->io, NULL);

        line_t   *l = ls->line;
        tunnel_t *t = ls->tunnel;

        udpconnector_tstate_t *ts = tunnelGetState(ls->tunnel);

        bool removed = localidletableRemoveIdleItemByHash(udpconnectorGetLineIdleTable(ts, l), udpconnectorIdleKey(io));
        if (! removed)
        {
            LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(io));
            terminateProgram(1);
        }
        ls->idle_handle = NULL; // mark as removed

        udpconnectorLinestateDestroy(ls);

        tunnelPrevDownStreamFinish(t, l);
    }
    else
    {
        LOGD("UdpConnector: sent close for FD:%x ", wioGetFD(io));
    }
}

void udpconnectorOnIdleConnectionExpire(local_idle_item_t *idle_udp)
{
    udpconnector_lstate_t *ls = (udpconnector_lstate_t *) (idle_udp->userdata);

    assert(ls != NULL && ls->tunnel != NULL);

    idle_udp->userdata = NULL;
    ls->idle_handle    = NULL; // mark as removed

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    LOGW("UdpConnector: expired 1 udp connection FD:%x ", wioGetFD(ls->io));
    weventSetUserData(ls->io, NULL);
    wioClose(ls->io);
    udpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

size_t udpconnectorQueuedWriteBytes(udpconnector_lstate_t *ls)
{
    size_t total = bufferqueueGetBufLen(&ls->pause_queue);

    for (uint32_t i = 0; i < ls->packet_destinations_count; ++i)
    {
        total += bufferqueueGetBufLen(&ls->packet_destinations[i].pending_queue);
    }

    return total;
}

void udpconnectorFlushWriteQueue(udpconnector_lstate_t *ls)
{
    if (ls->io == NULL)
    {
        return;
    }

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        if (wioIsClosed(ls->io))
        {
            return;
        }

        sbuf_t *buf = bufferqueuePopFront(&ls->pause_queue);
        wioWrite(ls->io, buf);
    }
}

bool udpconnectorReplayWriteQueue(udpconnector_lstate_t *ls)
{
    if (ls->io == NULL)
    {
        return true;
    }

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        if (wioIsClosed(ls->io))
        {
            return true;
        }

        sbuf_t *buf = bufferqueuePopFront(&ls->pause_queue);
        udpconnectorTunnelUpStreamPayload(t, l, buf);

        if (! lineIsAlive(l))
        {
            return false;
        }
    }

    return true;
}

#include "structure.h"

#include "loggers/network_logger.h"

static void closeLine(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls)
{
    if (ls->io != NULL)
    {
        bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, udpconnectorIdleKey(ls->io));
        if (! removed)
        {
            LOGF("UdpConnector: failed to remove idle item for FD:%x ", wioGetFD(ls->io));
            terminateProgram(1);
        }

        ls->idle_handle = NULL;
        weventSetUserData(ls->io, NULL);
        wioClose(ls->io);
    }

    udpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void handleQueueOverflow(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls)
{
    LOGE("UdpConnector: upstream write queue overflow, size: %d, limit: %d",
         (int) bufferqueueGetBufLen(&ls->pause_queue),
         (int) kUdpMaxPauseQueueSize);

    closeLine(t, l, ts, ls);
}

static void handleQueuedWrite(tunnel_t *t, line_t *l, udpconnector_tstate_t *ts, udpconnector_lstate_t *ls, sbuf_t *buf)
{
    if (! ls->queue_pause_sent && bufferqueueGetBufLen(&ls->pause_queue) > kUdpMinPauseQueueSize)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        if (! withLineLocked(l, tunnelPrevDownStreamPause, t))
        {
            bufferpoolReuseBuffer(pool, buf);
            return;
        }
        ls->queue_pause_sent = true;
    }

    bufferqueuePushBack(&ls->pause_queue, buf);

    if (bufferqueueGetBufLen(&ls->pause_queue) > kUdpMaxPauseQueueSize)
    {
        handleQueueOverflow(t, l, ts, ls);
    }
}

static bool udpconnectorPayloadSockAddrEquals(const sockaddr_u *lhs, const sockaddr_u *rhs)
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
        return lhs->sin6.sin6_port == rhs->sin6.sin6_port &&
               memoryCompare(lhs->sin6.sin6_addr.s6_addr, rhs->sin6.sin6_addr.s6_addr,
                             sizeof(lhs->sin6.sin6_addr.s6_addr)) == 0;
    default:
        return false;
    }
}

void udpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    udpconnector_lstate_t *ls = lineGetState(l, t);

    wio_t *io = ls->io;
    if (ls->write_paused || ls->resolving || io == NULL)
    {
        handleQueuedWrite(t, l, ts, ls, buf);
        return;
    }

    if (UNLIKELY(wioIsClosed(io)))
    {
        // should not happen in our structure
        LOGF("UdpConnector: UpStream Payload is called on closed wio. This should not happen");
        lineReuseBuffer(l, buf);
        // tunnelPrevDownStreamFinish(t, l);
        assert(false);
        terminateProgram(1);
    }
    // LOGD("writing %d bytes", sbufGetLength(buf));

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kUdpKeepExpireTime);

    // recvfrom() mutates io->peeraddr, so refresh the selected remote peer before every send.
    if (! udpconnectorPayloadSockAddrEquals(wioGetPeerAddrU(io), &ls->peer_addr))
    {
        wioSetPeerAddr(io, &ls->peer_addr.sa, sockaddrLen(&ls->peer_addr));
    }

    wioWrite(io, buf);
}

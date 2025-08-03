#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorOnClose(wio_t *io)
{
    tcpconnector_lstate_t *ls = (tcpconnector_lstate_t *) (weventGetUserdata(io));
    if (ls != NULL)
    {
        LOGD("TcpConnector: received close for FD:%x ", wioGetFD(io));
        weventSetUserData(ls->io, NULL);

        line_t                *l  = ls->line;
        tunnel_t              *t  = ls->tunnel;
        tcpconnector_tstate_t *ts = tunnelGetState(t);

        bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(io));
        if (! removed)
        {
            LOGF("TcpConnector: failed to remove idle item for FD:%x ", wioGetFD(io));
            terminateProgram(1);
        }
        ls->idle_handle = NULL; // mark as removed

        tcpconnectorLinestateDestroy(ls);

        tunnelPrevDownStreamFinish(t, l);
    }
    else
    {
        LOGD("TcpConnector: sent close for FD:%x ", wioGetFD(io));
    }
}

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcpconnector_lstate_t *lstate = weventGetUserdata(io);
    if (UNLIKELY(lstate == NULL))
    {
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        // assert(false);
        return;
    }
    tunnel_t              *t  = lstate->tunnel;
    line_t                *l  = lstate->line;
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    tcpconnector_lstate_t *ls = lineGetState(l, t);
    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kReadWriteTimeoutMs);

    tunnelPrevDownStreamPayload(t, l, buf);
}

static bool resumeWriteQueue(tcpconnector_lstate_t *lstate)
{
    buffer_queue_t *pause_queue = &lstate->pause_queue;
    wio_t          *io          = lstate->io;
    while (bufferqueueLen(pause_queue) > 0)
    {
        sbuf_t *buf    = bufferqueuePopFront(pause_queue);
        int     bytes  = (int) sbufGetLength(buf);
        int     nwrite = wioWrite(io, buf);

        if (nwrite < bytes)
        {
            return false; // write pending
        }
    }

    return true;
}

void tcpconnectorOnOutBoundConnected(wio_t *upstream_io)
{
    tcpconnector_lstate_t *lstate = weventGetUserdata(upstream_io);
    if (UNLIKELY(lstate == NULL))
    {
        // assert(false);
        return;
    }

    tunnel_t *t = lstate->tunnel;
    line_t   *l = lstate->line;
    wioSetCallBackRead(upstream_io, onRecv);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGD("TcpConnector: connection succeed FD:%x [%s] => [%s]", wioGetFD(upstream_io),
             SOCKADDR_STR(wioGetLocaladdr(upstream_io), localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(upstream_io), peeraddrstr));
    }

    wioRead(lstate->io);

    if (bufferqueueLen(&lstate->pause_queue) > 0)
    {
        if (resumeWriteQueue(lstate))
        {
            wioSetCallBackWrite(lstate->io, NULL);
            lstate->write_paused = false;

            tunnelPrevDownStreamResume(t, l);
        }
        else
        {

            if (! lineIsAlive(l))
            {
                LOGW("TcpConnector: line destroyed when resumed after connection !");
                return;
            }
        }
    }
    else
    {
        lstate->write_paused = false;
    }

    tunnelPrevDownStreamEst(t, l);
}

void tcpconnectorFlushWriteQueue(tcpconnector_lstate_t *lstate)
{
    while (bufferqueueLen(&lstate->pause_queue) > 0)
    {
        if (wioIsClosed(lstate->io))
        {
            return;
        }
        sbuf_t *buf = bufferqueuePopFront(&lstate->pause_queue);
        wioWrite(lstate->io, buf);
    }
}

void tcpconnectorOnWriteComplete(wio_t *io)
{
    // resume the read on other end of the connection
    tcpconnector_lstate_t *lstate = (tcpconnector_lstate_t *) (weventGetUserdata(io));
    if (UNLIKELY(lstate == NULL))
    {
        // assert(false);
        return;
    }

    wioSetCallBackWrite(lstate->io, NULL);

    if (wioCheckWriteComplete(io))
    {
        if (! resumeWriteQueue(lstate))
        {
            wioSetCallBackWrite(lstate->io, tcpconnectorOnWriteComplete);
            return;
        }
        lstate->write_paused = false;

        tunnelPrevDownStreamResume(lstate->tunnel, lstate->line);
    }
}

void tcpconnectorOnIdleConnectionExpire(widle_item_t *idle_tcp)
{
    tcpconnector_lstate_t *ls = idle_tcp->userdata;

    assert(ls != NULL && ls->tunnel != NULL);
    
    idle_tcp->userdata = NULL;
    ls->idle_handle    = NULL; // mark as removed

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    LOGW("TcpConnector: expired 1 tcp connection on FD:%x ", wioGetFD(ls->io));
    weventSetUserData(ls->io, NULL);
    tcpconnectorFlushWriteQueue(ls);
    wioClose(ls->io);
    tcpconnectorLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

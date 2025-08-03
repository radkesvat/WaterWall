#include "loggers/network_logger.h"
#include "structure.h"

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcplistener_lstate_t *lstate = (tcplistener_lstate_t *) (weventGetUserdata(io));
    if (UNLIKELY(lstate == NULL))
    {
        // assert(false);
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    line_t               *l  = lstate->line;
    tunnel_t             *t  = lstate->tunnel;
    tcplistener_lstate_t *ls = lineGetState(l, t);
    tcplistener_tstate_t *ts = tunnelGetState(t);

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kEstablishedKeepAliveTimeOutMs);

    tunnelNextUpStreamPayload(t, l, buf);
}

static void onClose(wio_t *io)
{
    tcplistener_lstate_t *ls = (tcplistener_lstate_t *) (weventGetUserdata(io));
    if (ls != NULL)
    {
        LOGD("TcpListener: received close for FD:%x ", wioGetFD(io));
        line_t               *l  = ls->line;
        tunnel_t             *t  = ls->tunnel;
        tcplistener_tstate_t *ts = tunnelGetState(t);

        weventSetUserData(ls->io, NULL);
        bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(io));
        if (! removed)
        {
            LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(io));
            terminateProgram(1);
        }
        ls->idle_handle = NULL; // mark as removed

        tcplistenerLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        lineDestroy(l);
    }
    else
    {
        LOGD("TcpListener: sent close for FD:%x ", wioGetFD(io));
    }
}

void tcplistenerOnInboundConnected(wevent_t *ev)
{
    wloop_t                *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *) weventGetUserdata(ev);
    wio_t                  *io   = data->io;
    wid_t                   wid  = data->wid;
    tunnel_t               *t    = data->tunnel;
    tcplistener_tstate_t   *ts   = tunnelGetState(t);

    wioAttach(loop, io);

    line_t               *l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    tcplistenerLinestateInitialize(ls, io, t, l);

    l->routing_context.src_ctx.type_ip   = true; // we have a client ip
    l->routing_context.src_ctx.proto_tcp = true; // tcp client
    sockaddrToIpAddr((const sockaddr_u *) wioGetPeerAddr(io), &(l->routing_context.src_ctx.ip_address));
    l->routing_context.src_ctx.port = data->real_localport;

    weventSetUserData(io, ls);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        struct sockaddr log_localaddr = *wioGetLocaladdr(io);
        sockaddrSetPort((sockaddr_u *) &(log_localaddr), data->real_localport);

        LOGD("TcpListener: Accepted FD:%x  [%s] <= [%s]", wioGetFD(io), SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    socketacceptresultDestroy(data);

    wioSetCallBackRead(io, onRecv);
    wioSetCallBackClose(io, onClose);
    // wioSetReadTimeout(io, 1600 * 1000);

    ls->idle_handle = idletableCreateItem(ts->idle_table, (hash_t) (wioGetFD(io)), ls,
                                          tcplistenerOnIdleConnectionExpire, wid, kDefaultKeepAliveTimeOutMs);
    while (ls->idle_handle == NULL)
    {
        // a very rare case where the socket FD from another thread is still present in the idle table
        cycleDelay(100);
        ls->idle_handle = idletableCreateItem(ts->idle_table, (hash_t) (wioGetFD(io)), ls,
                                              tcplistenerOnIdleConnectionExpire, wid, kDefaultKeepAliveTimeOutMs);
    }

    // send the init packet

    lineLock(l);
    tunnelNextUpStreamInit(t, l);
    if (! lineIsAlive(l))
    {
        LOGW("TcpListener: socket just got closed by upstream before anything happend");
        lineUnlock(l);
        return;
    }
    lineUnlock(l);

    wioRead(io);
}

void tcplistenerFlushWriteQueue(tcplistener_lstate_t *lstate)
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

static bool resumeWriteQueue(tcplistener_lstate_t *lstate)
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

void tcplistenerOnWriteComplete(wio_t *io)
{
    // resume the read on other end of the connection
    tcplistener_lstate_t *lstate = (tcplistener_lstate_t *) (weventGetUserdata(io));
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
            wioSetCallBackWrite(lstate->io, tcplistenerOnWriteComplete);
            return;
        }
        lstate->write_paused = false;

        tunnelNextUpStreamResume(lstate->tunnel, lstate->line);
    }
}

void tcplistenerOnIdleConnectionExpire(widle_item_t *idle_tcp)
{
    tcplistener_lstate_t *ls = idle_tcp->userdata;

    assert(ls != NULL && ls->tunnel != NULL);

    idle_tcp->userdata = NULL;
    ls->idle_handle    = NULL; // mark as removed

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    LOGW("TcpListener: expired 1 tcp connection on FD:%x ", wioGetFD(ls->io));
    weventSetUserData(ls->io, NULL);
    tcplistenerFlushWriteQueue(ls);
    wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    lineDestroy(l);
}

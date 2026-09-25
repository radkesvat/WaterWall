#include "loggers/network_logger.h"
#include "structure.h"
#include "wevent.h"

local_idle_table_t *tcplistenerGetWorkerIdleTable(tcplistener_tstate_t *ts)
{
    assert(ts != NULL);
    assert(ts->idle_tables != NULL);

    // Worker-local table: one checked identity for both the per-worker array and
    // the loop it is armed on. A non-event thread fails loudly instead of
    // silently creating a table on worker 0's loop.
    const wid_t wid = getCurrentEventWorkerWID();
    assert(wid < getWorkersCount());

    local_idle_table_t *table = ts->idle_tables[wid];
    if (table == NULL)
    {
        table                = localIdleTableCreate(getWorkerLoop(wid));
        ts->idle_tables[wid] = table;
    }
    return table;
}

local_idle_table_t *tcplistenerGetLineIdleTable(tcplistener_tstate_t *ts, line_t *l)
{
    assert(l != NULL);
    assert(lineIsOnCurrentEventWorker(l));
    discard l;

    return tcplistenerGetWorkerIdleTable(ts);
}

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

    tcplistenerApplyReadPreference(ls);
    localidletableKeepIdleItemForAtleast(
        tcplistenerGetLineIdleTable(ts, l), ls->idle_handle, ts->active_idle_timeout_ms);

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
        local_idle_item_t *idle_item = ls->idle_handle;
        ls->idle_handle              = NULL;
        bool removed                 = localidletableRemoveIdleItem(tcplistenerGetLineIdleTable(ts, l), idle_item);
        if (! removed)
        {
            LOGF("TcpListener: failed to remove idle item for FD:%x ", wioGetFD(io));
            abortProgramNow(1);
        }

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

    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        LOGD("TcpListener: rejecting accepted FD:%x because tunnel is stopping", wioGetFD(io));
        wioFree(io);
        socketacceptresultDestroy(data);
        return;
    }

    wioAttach(loop, io);

    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain->supports_splice)
    {
        if (UNLIKELY(wioEnableSplice(io) != 0))
        {
            LOGE("TcpListener: failed to enable splice for FD:%x (errno:%d)", wioGetFD(io), errno);
            wioFree(io);
            socketacceptresultDestroy(data);
            return;
        }
    }

    line_t               *l     = lineCreate(tunnelchainGetLinePools(chain), wid);
    tcplistener_lstate_t *ls    = lineGetState(l, t);

    tcplistenerLinestateInitialize(ls, io, t, l);

    const sockaddr_u *peer_addr = (const sockaddr_u *) wioGetPeerAddr(io);

    l->routing_context.src_ctx.type_ip   = true; // we have a client ip
    l->routing_context.src_ctx.proto_tcp = true; // tcp client
    sockaddrToIpAddr(peer_addr, &(l->routing_context.src_ctx.ip_address));
    l->routing_context.peer_source_port    = sockaddrPort((sockaddr_u *) peer_addr);
    l->routing_context.src_ctx.port        = data->real_localport;
    l->routing_context.local_listener_port = data->real_localport;

    weventSetUserData(io, ls);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        struct sockaddr log_localaddr = *wioGetLocaladdr(io);
        sockaddrSetPort((sockaddr_u *) &(log_localaddr), data->real_localport);

        LOGD("TcpListener: Accepted FD:%x  [%s] <= [%s]",
             wioGetFD(io),
             SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    socketacceptresultDestroy(data);

    wioSetCallBackRead(io, onRecv);
    wioSetCallBackClose(io, onClose);
    // wioSetReadTimeout(io, 1600 * 1000);

    ls->idle_handle = localidletableCreateItem(tcplistenerGetLineIdleTable(ts, l),
                                               tcplistenerIdleKey(io),
                                               ls,
                                               tcplistenerOnIdleConnectionExpire,
                                               ts->initial_idle_timeout_ms);
    if (UNLIKELY(ls->idle_handle == NULL))
    {
        LOGE("TcpListener: failed to register idle item for io id:%u FD:%x", wioGetID(io), wioGetFD(io));
        weventSetUserData(io, NULL);
        wioClose(io);
        tcplistenerLinestateDestroy(ls);
        lineDestroy(l);
        return;
    }

    // send the init packet
    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
    {
        LOGW("TcpListener: socket just got closed by upstream before anything happend");
        return;
    }

    // Init may attach this source to an already backpressured Mux parent.
    tcplistenerApplyReadPreference(ls);
    if (! ls->read_paused && UNLIKELY(wioRead(io) != 0))
    {
        return;
    }
}

void tcplistenerFlushWriteQueue(tcplistener_lstate_t *lstate)
{
    assert(lstate->io != NULL && ! wioIsClosed(lstate->io));

    while (bufferqueueGetBufCount(&lstate->pause_queue) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&lstate->pause_queue);
        if (UNLIKELY(sbufGetLength(buf) == 0))
        {
            lineReuseBuffer(lstate->line, buf);
            continue;
        }
        wioWrite(lstate->io, buf);
    }
}

static bool resumeWriteQueue(tcplistener_lstate_t *lstate)
{
    line_t *line = lstate->line;
    wio_t  *io   = lstate->io;
    // Suppress synchronous WIO completion reentry until this FIFO drain yields.
    wioSetCallBackWrite(io, NULL);
    bufferbudgetReservationRelease(&lstate->active_write);
    while (bufferqueueGetBufCount(&lstate->pause_queue) > 0)
    {
        sbuf_t   *buf         = bufferqueuePopFrontReserved(&lstate->pause_queue, &lstate->active_write);
        const int bytes       = (int) sbufGetLength(buf);
        if (UNLIKELY(bytes == 0))
        {
            lineReuseBuffer(line, buf);
            bufferbudgetReservationRelease(&lstate->active_write);
            continue;
        }
        const int nwrite = wioWrite(io, buf);
        if (UNLIKELY(! lineIsAlive(line)))
            return false;
        tcplistenerRefreshWriteBudget(lstate);
        if (UNLIKELY(nwrite < 0))
            return false;
        if (nwrite < bytes)
        {
            wioSetCallBackWrite(io, tcplistenerOnWriteComplete);
            return false;
        }
        bufferbudgetReservationRelease(&lstate->active_write);
    }
    return true;
}

void tcplistenerOnWriteComplete(wio_t *io)
{
    tcplistener_lstate_t *ls = weventGetUserdata(io);
    if (ls == NULL)
        return;
    tcplistenerApplyReadPreference(ls);
    tcplistenerRefreshWriteBudget(ls);
    if (! wioCheckWriteComplete(io))
        return;
    line_t   *line = ls->line;
    tunnel_t *t    = ls->tunnel;
    lineRef(line);
    if (resumeWriteQueue(ls) && lineIsAlive(line))
    {
        ls->write_paused     = false;
        const bool notify    = ls->queue_pause_sent;
        ls->queue_pause_sent = false;
        if (notify)
            tunnelNextUpStreamResume(t, line);
    }
    lineUnref(line);
}

void tcplistenerOnIdleConnectionExpire(local_idle_item_t *idle_tcp)
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

void tcplistenerRefreshWriteBudget(tcplistener_lstate_t *ls)
{
    if (ls->active_write.budget != NULL)
    {
        // WIO owns the buffer, possibly already freed; only inspect its byte counter.
        bufferbudgetReservationSetBytes(&ls->active_write, wioGetWriteBufSize(ls->io));
    }
}

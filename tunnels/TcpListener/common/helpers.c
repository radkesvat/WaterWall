#include "loggers/network_logger.h"
#include "structure.h"

local_idle_table_t *tcplistenerGetWorkerIdleTable(tcplistener_tstate_t *ts)
{
    assert(ts != NULL);
    assert(ts->idle_tables != NULL);

    // Worker-local table: one checked identity for both the per-worker array and
    // the loop it is armed on. A non-event thread fails loudly instead of
    // silently creating a table on worker 0's loop.
    const wid_t wid = getCurrentWorkerWID();
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
    assert(lineIsOnCurrentWorker(l));
    discard l;

    return tcplistenerGetWorkerIdleTable(ts);
}

#ifdef OS_LINUX
typedef struct tcplistener_linger_s
{
    wio_t              *io;
    local_idle_table_t *table;
    local_idle_item_t  *idle;
    uint64_t            deadline_ms;
} tcplistener_linger_t;

enum
{
    kFallbackLingerIdleMs  = 5000,
    kFallbackLingerTotalMs = 30000
};

static void onLingerClose(wio_t *io)
{
    tcplistener_linger_t *linger = weventGetUserdata(io);
    weventSetUserData(io, NULL);
    wioSetCallBackRead(io, NULL);
    wioSetCallBackWrite(io, NULL);
    wioSetCallBackClose(io, NULL);
    local_idle_item_t *idle = linger->idle;
    linger->idle            = NULL;
    if (idle != NULL)
    {
        bool removed = localidletableRemoveIdleItem(linger->table, idle);
        if (! removed)
        {
            LOGF("TcpListener: failed to remove closing socket idle item");
            abortProgramNow(1);
        }
    }
    memoryFree(linger);
}

static void onLingerExpire(local_idle_item_t *item)
{
    tcplistener_linger_t *linger = item->userdata;
    item->userdata               = NULL;
    linger->idle                 = NULL;
    // A pending response must not extend the terminal drain deadline.
    wioFree(linger->io);
}

static void onLingerRead(wio_t *io, sbuf_t *buf)
{
    tcplistener_linger_t *linger = weventGetUserdata(io);
    bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
    if (linger->deadline_ms == 0)
        return;

    const uint64_t now = wloopNowMonotonicMS(weventGetLoop(io));
    if (now >= linger->deadline_ms)
    {
        wioFree(io);
        return;
    }
    localidletableKeepIdleItemForAtleast(
        linger->table, linger->idle, min((uint64_t) kFallbackLingerIdleMs, linger->deadline_ms - now));
}

static void onLingerWriteComplete(wio_t *io)
{
    if (! wioCheckWriteComplete(io))
        return;

    wioSetCallBackWrite(io, NULL);
    if (shutdown(wioGetFD(io), SHUT_WR) != 0)
    {
        wioClose(io);
        return;
    }

    tcplistener_linger_t *linger = weventGetUserdata(io);
    local_idle_item_t    *idle   = linger->idle;
    linger->idle                 = NULL;
    bool removed                 = localidletableRemoveIdleItem(linger->table, idle);
    if (! removed)
    {
        LOGF("TcpListener: failed to replace draining socket idle item");
        abortProgramNow(1);
    }
    const uint64_t now  = wloopNowMonotonicMS(weventGetLoop(io));
    linger->deadline_ms = now + kFallbackLingerTotalMs;
    linger->idle =
        localidletableCreateItem(linger->table, tcplistenerIdleKey(io), linger, onLingerExpire, kFallbackLingerIdleMs);
    if (linger->idle == NULL)
    {
        LOGF("TcpListener: duplicate half-closed socket idle item");
        abortProgramNow(1);
    }
}
#endif

bool tcplistenerBeginFallbackLinger(tunnel_t *t, wio_t *io)
{
#ifdef OS_LINUX
    tcplistener_tstate_t *ts = tunnelGetState(t);
    if (atomicLoadRelaxed(&ts->stopping) || ! wloopNormalDispatchAllowed(weventGetLoop(io)) || wioIsClosed(io) ||
        wioGetError(io) != 0)
        return false;

    // This socket context owns no line state or line reference.
    tcplistener_linger_t *linger = memoryAllocateZero(sizeof(*linger));
    linger->io                   = io;
    linger->table                = tcplistenerGetWorkerIdleTable(ts);
    linger->idle                 = localidletableCreateItem(
        linger->table, tcplistenerIdleKey(io), linger, onLingerExpire, WIO_DEFAULT_CLOSE_TIMEOUT);
    if (linger->idle == NULL)
    {
        LOGF("TcpListener: duplicate draining socket idle item");
        abortProgramNow(1);
    }
    weventSetUserData(io, linger);
    wioSetCallBackRead(io, onLingerRead);
    wioSetCallBackClose(io, onLingerClose);
    wioSetCallBackWrite(io, onLingerWriteComplete);
    wioDisableSplice(io);
    if (wioRead(io) == 0)
        onLingerWriteComplete(io);
    return true;
#else
    discard t;
    discard io;
    return false;
#endif
}

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcplistener_lstate_t *ls = weventGetUserdata(io);
    if (UNLIKELY(ls == NULL))
    {
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    line_t               *l  = ls->line;
    tunnel_t             *t  = ls->tunnel;
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

        sockaddr_u log_localaddr = *wioGetLocaladdrU(io);
        sockaddrSetPort(&log_localaddr, data->real_localport);

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
    if (! ls->read_paused)
        discard wioRead(io);
}

void tcplistenerFlushWriteQueue(tcplistener_lstate_t *lstate)
{
    assert(lstate->io != NULL && ! wioIsClosed(lstate->io));

    sbuf_t *buf;
    while ((buf = awqPopForFinish(&lstate->write_queue, lineGetBufferPool(lstate->line))) != NULL)
    {
        wioWriteWithHint(lstate->io, buf, awqGetQueuedBytes(&lstate->write_queue) != 0);
    }
}

// Returns true only after draining the FIFO with the line still alive.
static bool resumeWriteQueue(tcplistener_lstate_t *lstate)
{
    line_t *line = lstate->line;
    wio_t  *io   = lstate->io;
    // Suppress synchronous WIO completion reentry until this FIFO drain yields.
    wioSetCallBackWrite(io, NULL);
    awqReleaseCompleted(&lstate->write_queue);
    sbuf_t *buf;
    while ((buf = awqNextToWrite(&lstate->write_queue, lineGetBufferPool(line))) != NULL)
    {
        const uint32_t bytes  = sbufGetLength(buf);
        const int      nwrite = wioWriteWithHint(io, buf, awqGetQueuedBytes(&lstate->write_queue) != 0);
        if (UNLIKELY(! lineIsAlive(line)))
            return false;
        const awq_write_result_t result = awqAfterWrite(&lstate->write_queue, nwrite, bytes, wioGetWriteBufSize(io));
        if (UNLIKELY(result == kAwqWriteFailed))
            return false;
        if (result == kAwqWriteBlocked)
        {
            wioSetCallBackWrite(io, tcplistenerOnWriteComplete);
            return false;
        }
    }
    return true;
}

void tcplistenerOnWriteComplete(wio_t *io)
{
    tcplistener_lstate_t *ls = weventGetUserdata(io);
    if (ls == NULL)
        return;
    tcplistenerApplyReadPreference(ls);
    awqRefreshPending(&ls->write_queue, wioGetWriteBufSize(io));
    if (! wioCheckWriteComplete(io))
        return;
    line_t   *line = ls->line;
    tunnel_t *t    = ls->tunnel;
    lineRef(line);
    if (resumeWriteQueue(ls))
    {
        if (awqTakeResume(&ls->write_queue))
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
    wioSetCallBackWrite(ls->io, NULL);
    tcplistenerFlushWriteQueue(ls);
    wioClose(ls->io);
    tcplistenerLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    lineDestroy(l);
}

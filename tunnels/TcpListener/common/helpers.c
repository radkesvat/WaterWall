#include "loggers/network_logger.h"
#include "structure.h"

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcplistener_lstate_t *lstate = (tcplistener_lstate_t *) (weventGetUserdata(io));
    if (UNLIKELY(lstate == NULL))
    {
        assert(false);
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    line_t   *l = lstate->line;
    tunnel_t *t = lstate->tunnel;

    lineLock(l);
    tunnelNextUpStreamPayload(t, l, buf);
    lineUnlock(l);
}

static void onClose(wio_t *io)
{
    tcplistener_lstate_t *lstate = (tcplistener_lstate_t *) (weventGetUserdata(io));
    if (lstate != NULL)
    {
        LOGD("TcpListener: received close for FD:%x ", wioGetFD(io));
        weventSetUserData(lstate->io, NULL);

        line_t   *l = lstate->line;
        tunnel_t *t = lstate->tunnel;

        lineLock(l);
        lineDestroy(l);
        lineStateDestroy(lstate);

        tunnelNextUpStreamFinish(t, l);

        lineUnlock(l);
    }
    else
    {
        LOGD("TcpListener: sent close for FD:%x ", wioGetFD(io));
    }
}

void onInboundConnected(wevent_t *ev)
{
    wloop_t                *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *) weventGetUserdata(ev);
    wio_t                  *io   = data->io;
    wid_t                   wid  = data->wid;
    tunnel_t               *t    = data->tunnel;

    wioAttach(loop, io);
    wioSetKeepaliveTimeout(io, kDefaultKeepAliveTimeOutMs);

    line_t               *line   = lineCreate(tunnelchainGetLinePool(t->chain, wid), wid);
    tcplistener_lstate_t *lstate = lineGetState(line, t);

    line->src_ctx.address_protocol = kSapTcp;
    line->src_ctx.address          = *(sockaddr_u *) wioGetPeerAddr(io);

    lineStateInitialize(lstate, wid);

    lstate->io           = io;
    lstate->tunnel       = t;
    lstate->line         = line;
    lstate->write_paused = false;
    lstate->established  = false;

    sockaddrSetPort(&(line->src_ctx.address), data->real_localport);
    line->src_ctx.address_type = line->src_ctx.address.sa.sa_family == AF_INET ? kSatIPV4 : kSatIPV6;
    weventSetUserData(io, lstate);

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

    // send the init packet

    lineLock(line);
    tunnelNextUpStreamInit(t, line);
    if (! lineIsAlive(line))
    {
        LOGW("TcpListener: socket just got closed by upstream before anything happend");
        lineUnlock(line);
        return;
    }
    lineUnlock(line);
    wioRead(io);
}

void flushWriteQueue(tcplistener_lstate_t *lstate)
{
    while (bufferqueueLen(lstate->data_queue) > 0)
    {
        if (wioIsClosed(lstate->io))
        {
            return;
        }
        sbuf_t *buf = bufferqueuePop(lstate->data_queue);
        wioWrite(lstate->io, buf);
    }
}

static bool resumeWriteQueue(tcplistener_lstate_t *lstate)
{
    buffer_queue_t *data_queue = (lstate)->data_queue;
    wio_t          *io         = lstate->io;
    while (bufferqueueLen(data_queue) > 0)
    {
        sbuf_t *buf    = bufferqueuePop(data_queue);
        int     bytes  = (int) sbufGetBufLength(buf);
        int     nwrite = wioWrite(io, buf);

        if (nwrite < bytes)
        {
            return false; // write pending
        }
    }

    return true;
}

void onWriteComplete(wio_t *io)
{
    // resume the read on other end of the connection
    tcplistener_lstate_t *lstate = (tcplistener_lstate_t *) (weventGetUserdata(io));
    if (UNLIKELY(lstate == NULL))
    {
        assert(false);
        return;
    }

    if (wioCheckWriteComplete(io))
    {

        buffer_queue_t *data_queue = lstate->data_queue;
        if (bufferqueueLen(data_queue) > 0 && ! resumeWriteQueue(lstate))
        {
            return;
        }
        wioSetCallBackWrite(lstate->io, NULL);
        lstate->write_paused = false;
        tunnelNextUpStreamResume(lstate->tunnel, lstate->line);
    }
}

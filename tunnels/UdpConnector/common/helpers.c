#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorOnRecvFrom(wio_t *io, sbuf_t *buf)
{
    udpconnector_lstate_t *ls = (udpconnector_lstate_t *) (weventGetUserdata(io));

    if (ls == NULL || ls->read_paused)
    {
        bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    // LOGD("reading %d bytes", sbufGetLength(buf));

    tunnel_t *t       = ls->tunnel;
    line_t   *l       = ls->line;
    sbuf_t   *payload = buf;

    if (! ls->established)
    {
        ls->established = true;
        lineLock(l);
        tunnelPrevDownStreamEst(t, l);
        if (! lineIsAlive(l))
        {
            bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), payload);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
    }
    udpconnector_tstate_t *ts = tunnelGetState(ls->tunnel);

    idletableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kUdpKeepExpireTime);

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

        bool removed = idletableRemoveIdleItemByHash(lineGetWID(l), ts->idle_table, wioGetFD(io));
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

void udpconnectorOnIdleConnectionExpire(idle_item_t *idle_udp)
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

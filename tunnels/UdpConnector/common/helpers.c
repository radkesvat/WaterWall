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
    tunnelPrevDownStreamPayload(t, l, payload);

}

void udpconnectorOnClose(wio_t *io)
{
    udpconnector_lstate_t *lstate = (udpconnector_lstate_t *) (weventGetUserdata(io));
    if (lstate != NULL)
    {
        LOGD("UdpConnector: received close for FD:%x ", wioGetFD(io));
        weventSetUserData(lstate->io, NULL);

        line_t   *l = lstate->line;
        tunnel_t *t = lstate->tunnel;

        udpconnectorLinestateDestroy(lstate);

        tunnelPrevDownStreamFinish(t, l);

    }
    else
    {
        LOGD("UdpConnector: sent close for FD:%x ", wioGetFD(io));
    }
}

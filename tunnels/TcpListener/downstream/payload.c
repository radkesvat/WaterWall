#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcplistener_tstate_t *ts = tunnelGetState(t);
    tcplistener_lstate_t *ls = lineGetState(l, t);

    if (ls->write_paused)
    {
        tunnelNextUpStreamPause(t, l);
        bufferqueuePush(&ls->pause_queue, buf);
    }
    else
    {
        int bytes  = (int) sbufGetLength(buf);
        int nwrite = wioWrite(ls->io, buf);

        idleTableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kEstablishedKeepAliveTimeOutMs);

        if (nwrite >= 0 && nwrite < bytes)
        {
            ls->write_paused = true;
            wioSetCallBackWrite(ls->io, tcplistenerOnWriteComplete);
            tunnelNextUpStreamPause(t, l);
        }
    }
}

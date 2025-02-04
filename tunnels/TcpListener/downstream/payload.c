#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcplistener_lstate_t *lstate = lineGetState(l, t);

    if (lstate->write_paused)
    {
        tunnelNextUpStreamPause(t, l);
        bufferqueuePush(lstate->data_queue, buf);
    }
    else
    {
        int bytes  = (int) sbufGetBufLength(buf);
        int nwrite = wioWrite(lstate->io, buf);


        if (nwrite >= 0 && nwrite < bytes)
        {
            lstate->write_paused = true;
            wioSetCallBackWrite(lstate->io, tcplistenerOnWriteComplete);
            tunnelNextUpStreamPause(t, l);
        }
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamFinish(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);

    line_t *d = uls->d;

    if (uls->buffering)
    {
        bufferpoolReuseBuffer(lineGetBufferPool(d), uls->buffering);
        uls->buffering = NULL;
    }

    if (d)
    {
        reverseserver_lstate_t *dls = lineGetState(d, t);
        reverseserverLinestateDestroy(dls);
        tunnelPrevDownStreamFinish(t, d);
    }
    else
    {
        reverseserver_tstate_t *ts  = tunnelGetState(t);
        wid_t                   wid = lineGetWID(u);

        reverseserver_thread_box_t *this_tb = &(ts->threadlocal_pool[wid]);
        if (uls->handshaked)
        {
            reverseserverRemoveConnectionU(this_tb, uls);
        }
    }
    reverseserverLinestateDestroy(uls);
}

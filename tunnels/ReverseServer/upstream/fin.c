#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamFinish(tunnel_t *t, line_t *d)
{
    reverseserver_tstate_t     *ts      = tunnelGetState(t);
    reverseserver_lstate_t     *dls     = lineGetState(d, t);
    reverseserver_thread_box_t *this_tb = &(ts->threadlocal_pool[lineGetWID(d)]);

    if (dls->paired)
    {
        line_t                 *u   = dls->u;
        reverseserver_lstate_t *uls = lineGetState(u, t);
        reverseserverLinestateDestroy(dls);
        reverseserverLinestateDestroy(uls);
        tunnelNextUpStreamFinish(t, u);

    }
    else
    {
        if (dls->buffering != NULL)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(d), dls->buffering);
            dls->buffering = NULL;
        }

        if (dls->handshaked)
        {
            reverseserverRemoveConnectionD(this_tb, dls);
        }
        reverseserverLinestateDestroy(dls);
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *u, sbuf_t *buf)
{

    reverseserver_tstate_t *ts  = tunnelGetState(t);
    reverseserver_lstate_t *uls = lineGetState(u, t);
    wid_t                   wid = lineGetWID(u);

    if (uls->paired)
    {
        tunnelPrevDownStreamPayload(t, uls->d, buf);
    }
    else
    {

        if (uls->buffering != NULL)
        {
            uls->buffering = sbufAppendMerge(lineGetBufferPool(u), uls->buffering, buf);
            buf            = uls->buffering;
            uls->buffering = NULL;
        }
        if (sbufGetLength(buf) > kMaxBuffering)
        {
            LOGD("ReverseServer: Downstream payload is too large, dropping connection");

            bufferpoolReuseBuffer(lineGetBufferPool(u), buf);
            reverseserverLinestateDestroy(uls);
            tunnelNextUpStreamFinish(t, u);
            return;
        }

        reverseserver_thread_box_t *this_tb = &(ts->threadlocal_pool[wid]);
        if (this_tb->d_count > 0)
        {
            reverseserver_lstate_t *dls = this_tb->d_root;
            line_t                 *d   = dls->d;
            reverseserverRemoveConnectionD(this_tb, dls);
            dls->u      = u;
            dls->paired = true;
            uls->paired = true;
            uls->d      = dls->d;

            lineLock(d);

            sbuf_t *dbuf   = dls->buffering;
            dls->buffering = NULL;

            tunnelPrevDownStreamPayload(t, d, buf);

            if (! lineIsAlive(d))
            {
                bufferpoolReuseBuffer(lineGetBufferPool(d), dbuf);
                lineUnlock(d);
                return;
            }
            lineUnlock(d);

            tunnelNextUpStreamPayload(t, u, dbuf);
        }
        else
        {
            LOGW("ReverseServer: no peer left, waiting tid: %d", lineGetWID(u));

            reverseserverAddConnectionU(this_tb, uls);
            uls->buffering = buf;
        }
    }
}

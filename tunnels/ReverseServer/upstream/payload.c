#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverTunnelUpStreamPayload(tunnel_t *t, line_t *d, sbuf_t *buf)
{
    reverseserver_tstate_t     *ts      = tunnelGetState(t);
    reverseserver_lstate_t     *dls     = lineGetState(d, t);
    reverseserver_thread_box_t *this_tb = &(ts->threadlocal_pool[lineGetWID(d)]);

    if (dls->paired)
    {
        tunnelNextUpStreamPayload(t, dls->u, buf);
    }
    else
    {
        if (dls->buffering != NULL)
        {
            dls->buffering = sbufAppendMerge(lineGetBufferPool(d), dls->buffering, buf);
            buf            = dls->buffering;
            dls->buffering = NULL;
        }
        if (sbufGetLength(buf) > kMaxBuffering)
        {
            LOGD("ReverseServer: Upstream payload is too large, dropping connection");

            bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
            reverseserverLinestateDestroy(dls);
            tunnelPrevDownStreamFinish(t, d);
            return;
        }
        if (! dls->handshaked)
        {
            if (sbufGetLength(buf) >= kHandShakeLength)
            {
                for (int i = 0; i < kHandShakeLength; i++)
                {
                    if (sbufGetMutablePtr(buf)[i] != kHandShakeByte)
                    {
                        LOGD("ReverseServer: Handshake failed, dropping connection");

                        bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
                        reverseserverLinestateDestroy(dls);
                        tunnelPrevDownStreamFinish(t, d);
                        return;
                    }
                }
                dls->handshaked = true;
                sbufShiftRight(buf, kHandShakeLength);
                reverseserverAddConnectionD(this_tb, dls);

                if (sbufGetLength(buf) <= 0)
                {
                    bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
                    return;
                }
            }
            else
            {
                dls->buffering = buf;
                return;
            }
        }

        if (this_tb->u_count > 0)
        {
            reverseserver_lstate_t *uls = this_tb->u_root;
            line_t                 *u   = uls->u;

            reverseserverRemoveConnectionU(this_tb, uls);

            uls->d      = d;
            uls->paired = true;
            dls->paired = true;
            dls->u      = u;

            if (uls->buffering != NULL)
            {
                lineLock(d);

                sbuf_t* ubuf = uls->buffering;
                uls->buffering = NULL;
                tunnelPrevDownStreamPayload(t, d, ubuf);

                if (! lineIsAlive(d))
                {
                    bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
                    lineUnlock(d);
                    return;
                }
                
            }

            tunnelNextUpStreamPayload(t, u, buf);
            return;
        }

        for (wid_t wi = 0; wi < getWorkersCount() - WORKER_ADDITIONS; wi++)
        {
            if (wi != lineGetWID(d) && ts->threadlocal_pool[wi].u_count > 0)
            {
                if (pipeTo(t, d, wi))
                {
                    reverseserverLinestateDestroy(dls);

                    sbuf_t *handshake_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(d));
                    sbufReserveSpace(handshake_buf, kHandShakeLength);
                    sbufSetLength(handshake_buf, kHandShakeLength);
                    memorySet(sbufGetMutablePtr(handshake_buf), kHandShakeByte, kHandShakeLength);

                    // wirte to pipe
                    tunnel_t *prev_tun = t->prev;
                    tunnelUpStreamPayload(prev_tun, d, handshake_buf);
                    tunnelUpStreamPayload(prev_tun, d, buf);
                    return;
                }
                // stay here untill a peer connection is available
                dls->buffering = buf;
                return;
            }
        }

        // stay here untill a peer connection is available
        dls->buffering = buf;
    }
}

#include "structure.h"

#include "loggers/network_logger.h"

static void handleBufferMerging(line_t *d, reverseserver_lstate_t *dls, sbuf_t **buf)
{
    if (dls->buffering != NULL)
    {
        dls->buffering = sbufAppendMerge(lineGetBufferPool(d), dls->buffering, *buf);
        *buf           = dls->buffering;
        dls->buffering = NULL;
    }
}

static bool checkBufferSizeLimit(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                 reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    if (sbufGetLength(buf) > kMaxBuffering)
    {
        LOGD("ReverseServer: Upstream payload is too large, dropping connection");

        bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
        if (dls->handshaked)
        {
            reverseserverRemoveConnectionD(this_tb, dls);
        }
        reverseserverLinestateDestroy(dls);
        tunnelPrevDownStreamFinish(t, d);
        return false;
    }
    return true;
}

static bool validateHandshake(sbuf_t *buf)
{
    for (int i = 0; i < kHandShakeLength; i++)
    {
        if (sbufGetMutablePtr(buf)[i] != kHandShakeByte)
        {
            return false;
        }
    }
    return true;
}

static bool processHandshake(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_thread_box_t *this_tb,
                             sbuf_t *buf)
{
    if (dls->handshaked)
    {
        dls->buffering = buf;
        return true;
    }

    if (sbufGetLength(buf) >= kHandShakeLength)
    {
        if (! validateHandshake(buf))
        {
            LOGD("ReverseServer: Handshake failed, dropping connection");
            bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
            reverseserverLinestateDestroy(dls);
            tunnelPrevDownStreamFinish(t, d);
            return false;
        }

        dls->handshaked = true;
        sbufShiftRight(buf, kHandShakeLength);
        reverseserverAddConnectionD(this_tb, dls);

        if (sbufGetLength(buf) <= 0)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(d), buf);
        }
        else
        {
            dls->buffering = buf;
        }
        // LOGD("ReverseServer: Handshake successful, connection established");
        return true;
    }

    dls->buffering = buf;
    return false;
}

static bool pairWithLocalUpstreamConnection(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                            reverseserver_thread_box_t *this_tb)
{
    if (this_tb->u_count <= 0)
    {
        return false;
    }

    reverseserverRemoveConnectionD(this_tb, dls);

    reverseserver_lstate_t *uls = this_tb->u_root;
    line_t                 *u   = uls->u;

    reverseserverRemoveConnectionU(this_tb, uls);

    uls->d      = d;
    uls->paired = true;
    dls->paired = true;
    dls->u      = u;

    sbuf_t *dbuf   = dls->buffering;
    dls->buffering = NULL;

    assert(uls->buffering);
    lineLock(d);

    sbuf_t *ubuf   = uls->buffering;
    uls->buffering = NULL;
    // LOGD("ReverseServer: Pairing upstream connection %u with downstream connection %u, buf has %zu bytes",
    //  lineGetWID(u), lineGetWID(d), sbufGetLength(ubuf));
    tunnelPrevDownStreamPayload(t, d, ubuf);

    if (! lineIsAlive(d))
    {
        if (dbuf)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(d), dbuf);
        }
        lineUnlock(d);
        return true;
    }

    lineUnlock(d);
    if (dbuf)
    {
        tunnelNextUpStreamPayload(t, u, dbuf);
    }
    return true;
}

static sbuf_t *createHandshakeBuffer(line_t *d)
{
    sbuf_t *handshake_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(d));
    sbufReserveSpace(handshake_buf, kHandShakeLength);
    sbufSetLength(handshake_buf, kHandShakeLength);
    memorySet(sbufGetMutablePtr(handshake_buf), kHandShakeByte, kHandShakeLength);
    return handshake_buf;
}

static bool pipeToRemoteWorker(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_thread_box_t *this_tb,
                               wid_t wi, sbuf_t *buf)
{
    if (! pipeTo(t, d, wi))
    {
        return false;
    }

    reverseserverRemoveConnectionD(this_tb, dls);
    reverseserverLinestateDestroy(dls);

    sbuf_t   *handshake_buf = createHandshakeBuffer(d);
    tunnel_t *prev_tun      = t->prev;

    tunnelUpStreamPayload(prev_tun, d, handshake_buf);
    if (buf)
    {
        tunnelUpStreamPayload(prev_tun, d, buf);
    }
    return true;
}

static bool tryPairWithRemoteUpstreamConnection(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                                reverseserver_tstate_t *ts, reverseserver_thread_box_t *this_tb)
{
    sbuf_t *dbuf   = dls->buffering;
    dls->buffering = NULL;

    for (wid_t wi = 0; wi < getWorkersCount() - WORKER_ADDITIONS; wi++)
    {
        if (wi != lineGetWID(d) && ts->threadlocal_pool[wi].u_count > 0)
        {
            if (pipeToRemoteWorker(t, d, dls, this_tb, wi, dbuf))
            {
                return true;
            }

            dls->buffering = dbuf;
            return true;
        }
    }
    return false;
}

static void handleUnpairedConnection(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_tstate_t *ts,
                                     reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    handleBufferMerging(d, dls, &buf);

    if (! checkBufferSizeLimit(t, d, dls, this_tb, buf))
    {
        return;
    }

    if (! processHandshake(t, d, dls, this_tb, buf))
    {
        return;
    }

    if (pairWithLocalUpstreamConnection(t, d, dls, this_tb))
    {
        return;
    }

    if (tryPairWithRemoteUpstreamConnection(t, d, dls, ts, this_tb))
    {
        return;
    }
}

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
        handleUnpairedConnection(t, d, dls, ts, this_tb, buf);
    }
}

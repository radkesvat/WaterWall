#include "structure.h"

#include "loggers/network_logger.h"

static void reverseclienthandleBufferMerging(line_t *d, reverseserver_lstate_t *dls, sbuf_t **buf)
{
    if (dls->buffering != NULL)
    {
        dls->buffering = sbufAppendMerge(lineGetBufferPool(d), dls->buffering, *buf);
        *buf           = dls->buffering;
        dls->buffering = NULL;
    }
}

static bool checkBufferSizeLimitD(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                  reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    if (sbufGetLength(buf) > kMaxBuffering)
    {
        LOGD("ReverseServer: Upstream payload is too large, dropping connection");

        lineReuseBuffer(d, buf);
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
    return memoryCompare(sbufGetMutablePtr(buf), reverseclientHandshakeBytes, reverseclientHandshakeLength) == 0;
}

static bool processHandshakeD(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_thread_box_t *this_tb,
                              sbuf_t *buf)
{
    if (dls->handshaked)
    {
        dls->buffering = buf;
        return true;
    }

    if (sbufGetLength(buf) >= reverseclientHandshakeLength)
    {
        if (! validateHandshake(buf))
        {
            LOGD("ReverseServer: Handshake failed, dropping connection");
            lineReuseBuffer(d, buf);
            reverseserverLinestateDestroy(dls);
            tunnelPrevDownStreamFinish(t, d);
            return false;
        }

        dls->handshaked = true;
        sbufShiftRight(buf, reverseclientHandshakeLength);
        reverseserverAddConnectionD(this_tb, dls);

        if (sbufGetLength(buf) <= 0)
        {
            lineReuseBuffer(d, buf);
        }
        else
        {
            dls->buffering = buf;
        }
        // LOGD("ReverseServer: Handshake successful");
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

    sbuf_t *ubuf   = uls->buffering;
    uls->buffering = NULL;

    // since we are paired, if this call returns false that means both linses are closed
    if (! withLineLockedWithBuf(d, tunnelPrevDownStreamPayload, t, ubuf))
    {
        if (dbuf)
        {
            reuseBuffer(dbuf);
        }

        return true;
    }

    if (dbuf)
    {
        tunnelNextUpStreamPayload(t, u, dbuf);
    }
    return true;
}

static sbuf_t *createHandshakeBuffer(line_t *d)
{
    sbuf_t *handshake_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(d));
    handshake_buf = sbufReserveSpace(handshake_buf, reverseclientHandshakeLength);
    sbufSetLength(handshake_buf, reverseclientHandshakeLength);
    memoryCopy(sbufGetMutablePtr(handshake_buf), reverseclientHandshakeBytes, reverseclientHandshakeLength);
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

    if (! withLineLockedWithBuf(d, tunnelUpStreamPayload, prev_tun, handshake_buf))
    {
        if (buf != NULL)
        {
            reuseBuffer(buf);
        }
        return true;
    }

    if (buf != NULL)
    {
        discard withLineLockedWithBuf(d, tunnelUpStreamPayload, prev_tun, buf);
    }

    return true;
}

static bool tryPairWithRemoteUpstreamConnection(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                                reverseserver_tstate_t *ts, reverseserver_thread_box_t *this_tb)
{
    sbuf_t *dbuf   = dls->buffering;
    dls->buffering = NULL;

    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        if (wi != lineGetWID(d) && ts->threadlocal_pool[wi].u_count > 0)
        {
            if (pipeToRemoteWorker(t, d, dls, this_tb, wi, dbuf))
            {
                return true;
            }
        }
    }

    dls->buffering = dbuf;
    return false;
}

static void handleUnpairedConnectionD(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_tstate_t *ts,
                                      reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    reverseclienthandleBufferMerging(d, dls, &buf);

    if (! checkBufferSizeLimitD(t, d, dls, this_tb, buf))
    {
        return;
    }

    if (! processHandshakeD(t, d, dls, this_tb, buf))
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
        handleUnpairedConnectionD(t, d, dls, ts, this_tb, buf);
    }
}

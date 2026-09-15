#include "structure.h"

#include "loggers/network_logger.h"

static void reverseServerHandleBufferMerging(line_t *u, reverseserver_lstate_t *uls, sbuf_t **buf)
{
    if (uls->buffering != NULL)
    {
        uls->buffering = sbufAppendMerge(lineGetBufferPool(u), uls->buffering, *buf);
        *buf           = uls->buffering;
        uls->buffering = NULL;
    }
}

static bool checkBufferSizeLimitU(tunnel_t *t, line_t *u, reverseserver_lstate_t *uls,
                                  reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    if (sbufGetLength(buf) > reverseserverWaitingLimit(u))
    {
        LOGD("ReverseServer: Downstream payload is too large, dropping connection");

        lineReuseBuffer(u, buf);
        if (uls->handshaked)
        {
            reverseserverRemoveConnectionU(this_tb, uls);
        }
        reverseserverLinestateDestroy(uls);
        tunnelNextUpStreamFinish(t, u);
        return false;
    }
    return true;
}

static void processHandshakeU(reverseserver_lstate_t *uls, reverseserver_thread_box_t *this_tb)
{
    if (! uls->handshaked)
    {
        uls->handshaked = true;
        reverseserverAddConnectionU(this_tb, uls);
    }
}

static bool pairWithLocalDownstreamConnection(tunnel_t *t, line_t *u, reverseserver_lstate_t *uls,
                                              reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    if (this_tb->d_count <= 0)
    {
        return false;
    }

    reverseserverRemoveConnectionU(this_tb, uls);
    reverseserver_lstate_t *dls = this_tb->d_root;
    line_t                 *d   = dls->d;
    reverseserverRemoveConnectionD(this_tb, dls);

    dls->u      = u;
    dls->paired = true;
    uls->paired = true;
    uls->d      = d;


    sbuf_t *dbuf   = dls->buffering;
    dls->buffering = NULL;

    if (! lineCallWithRefWithBuf(d, tunnelPrevDownStreamPayload, t, buf))
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

static void handleUnpairedConnectionU(tunnel_t *t, line_t *u, reverseserver_lstate_t *uls,
                                      reverseserver_thread_box_t *this_tb, sbuf_t *buf)
{
    uint32_t       capacity;
    const uint64_t total = (uint64_t) sbufGetLength(buf) + (uls->buffering != NULL ? sbufGetLength(uls->buffering) : 0);
    if (! sbufTryComputeCapacity(total, bufferpoolGetLargeBufferPadding(lineGetBufferPool(u)), &capacity))
    {
        lineReuseBuffer(u, buf);
        if (uls->buffering != NULL)
            lineReuseBuffer(u, uls->buffering);
        uls->buffering = NULL;
        if (uls->handshaked)
            reverseserverRemoveConnectionU(this_tb, uls);
        reverseserverLinestateDestroy(uls);
        tunnelNextUpStreamFinish(t, u);
        return;
    }
    reverseServerHandleBufferMerging(u, uls, &buf);

    processHandshakeU(uls, this_tb);

    if (pairWithLocalDownstreamConnection(t, u, uls, this_tb, buf))
    {
        return;
    }

    if (! checkBufferSizeLimitU(t, u, uls, this_tb, buf))
    {
        return;
    }

    LOGW("ReverseServer: no peer left, waiting tid: %d", lineGetWID(u));
    uls->buffering = buf;
}

void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *u, sbuf_t *buf)
{
    reverseserver_tstate_t     *ts      = tunnelGetState(t);
    reverseserver_lstate_t     *uls     = lineGetState(u, t);
    wid_t                       wid     = lineGetWID(u);
    reverseserver_thread_box_t *this_tb = &(ts->threadlocal_pool[wid]);

    if (uls->paired)
    {
        tunnelPrevDownStreamPayload(t, uls->d, buf);
    }
    else
    {
        handleUnpairedConnectionU(t, u, uls, this_tb, buf);
    }
}

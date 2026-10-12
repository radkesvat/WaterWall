#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverAddConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next = box->u_root;
    con->prev = NULL; // New head has no previous node
    if (box->u_root)
    {
        box->u_root->prev = con;
    }
    box->u_root = con;
    atomicInc(&box->u_count);
}
void reverseserverRemoveConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    if (con->prev)
    {
        con->prev->next = con->next;
    }
    else
    {
        // con is the head, update root pointer
        box->u_root = con->next;
    }

    if (con->next)
    {
        con->next->prev = con->prev;
    }
    atomicDec(&box->u_count);
}

void reverseserverAddConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    con->next = box->d_root;
    con->prev = NULL; // New head has no previous node
    if (box->d_root)
    {
        box->d_root->prev = con;
    }
    box->d_root = con;
    atomicInc(&box->d_count);
}
void reverseserverRemoveConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con)
{
    if (con->prev)
    {
        con->prev->next = con->next;
    }
    else
    {
        // con is the head, update root pointer
        box->d_root = con->next;
    }

    if (con->next)
    {
        con->next->prev = con->prev;
    }
    atomicDec(&box->d_count);
}

static void closePair(tunnel_t *t, line_t *u, line_t *d)
{
    reverseserverLinestateDestroy(lineGetState(u, t));
    reverseserverLinestateDestroy(lineGetState(d, t));
    lineRef(u);
    tunnelPrevDownStreamFinish(t, d);
    if (lineIsAlive(u))
        tunnelNextUpStreamFinish(t, u);
    lineUnref(u);
}

void reverseserverCloseLine(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t *ls = lineGetState(line, t);
    if (ls->paired)
    {
        closePair(t, ls->u, ls->d);
        return;
    }
    const bool                  user = ls->u == line;
    reverseserver_tstate_t     *ts   = tunnelGetState(t);
    reverseserver_thread_box_t *box  = &ts->threadlocal_pool[lineGetWID(line)];
    if (ls->handshaked)
    {
        if (user)
            reverseserverRemoveConnectionU(box, ls);
        else
            reverseserverRemoveConnectionD(box, ls);
    }
    reverseserverLinestateDestroy(ls);
    if (user)
        tunnelNextUpStreamFinish(t, line);
    else
        tunnelPrevDownStreamFinish(t, line);
}

bool reverseserverReconcileSource(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t *ls     = lineGetState(line, t);
    const bool              user   = ls->u == line;
    bool                    paused = ls->handshaked;
    if (ls->paired)
    {
        reverseserver_lstate_t *peer = lineGetState(user ? ls->d : ls->u, t);
        paused = ls->replaying || bufferqueueGetBufCount(&ls->pending) != 0 || peer->output_paused;
    }
    if (paused == ls->source_paused)
        return true;

    /* Publish the combined waiting/FIFO/consumer hold before notification. */
    ls->source_paused = paused;
    lineRef(line);
    if (user)
    {
        if (paused)
            tunnelNextUpStreamPause(t, line);
        else
            tunnelNextUpStreamResume(t, line);
    }
    else
    {
        if (paused)
            tunnelPrevDownStreamPause(t, line);
        else
            tunnelPrevDownStreamResume(t, line);
    }
    const bool alive = lineIsAlive(line);
    lineUnref(line);
    return alive;
}

bool reverseserverRetainPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    reverseserver_lstate_t *ls     = lineGetState(line, t);
    const uint32_t          length = sbufGetLength(buf);
    if (length == 0)
    {
        lineReuseBuffer(line, buf);
        return true;
    }
    const buffer_budget_cost_t used = bufferbudgetGetUsage(&ls->pending_budget);
    if (length > kReverseServerPendingBytes - used.bytes || used.entries >= kReverseServerPendingBuffers ||
        (ls->replaying && (ls->replay_admitted + length > kReverseServerPendingBytes ||
                           ls->replay_admitted_buffers >= kReverseServerPendingBuffers)))
    {
        lineReuseBuffer(line, buf);
        reverseserverCloseLine(t, line);
        return false;
    }
    buf = sbufEnsureOrdinary(lineGetBufferPool(line), buf);
    if (! bufferqueueTryPushBack(&ls->pending, &buf))
    {
        LOGD("ReverseServer: application backlog exceeds its byte or buffer limit");
        lineReuseBuffer(line, buf);
        reverseserverCloseLine(t, line);
        return false;
    }
    if (ls->replaying)
    {
        ls->replay_admitted += length;
        ++ls->replay_admitted_buffers;
    }
    return true;
}

void reverseserverDrainPair(tunnel_t *t, line_t *u)
{
    reverseserver_lstate_t *uls = lineGetState(u, t);
    if (uls->replaying)
        return;

    line_t                 *d   = uls->d;
    reverseserver_lstate_t *dls = lineGetState(d, t);
    lineRef(u);
    lineRef(d);
    uls->replaying = dls->replaying = true;
    uls->replay_admitted = dls->replay_admitted = 0;
    uls->replay_admitted_buffers = dls->replay_admitted_buffers = 0;
    while (lineIsAlive(u) && lineIsAlive(d))
    {
        bool progress = false;
        if (bufferqueueGetBufCount(&uls->pending) != 0 && ! dls->output_paused)
        {
            sbuf_t *buf = bufferqueuePopFront(&uls->pending);
            tunnelPrevDownStreamPayload(t, d, buf);
            progress = true;
        }
        if (! lineIsAlive(u) || ! lineIsAlive(d))
            break;
        if (bufferqueueGetBufCount(&dls->pending) != 0 && ! uls->output_paused)
        {
            sbuf_t *buf = bufferqueuePopFront(&dls->pending);
            tunnelNextUpStreamPayload(t, u, buf);
            progress = true;
        }
        if (! progress)
            break;
    }
    if (lineIsAlive(u) && lineIsAlive(d))
    {
        uls->replaying = dls->replaying = false;
        reverseserverReconcileSource(t, u);
        if (lineIsAlive(u) && lineIsAlive(d))
            reverseserverReconcileSource(t, d);
    }
    lineUnref(d);
    lineUnref(u);
}

void reverseserverPair(tunnel_t *t, line_t *u, line_t *d)
{
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    reverseserver_lstate_t     *uls = lineGetState(u, t);
    reverseserver_lstate_t     *dls = lineGetState(d, t);
    assert(lineGetWID(u) == lineGetWID(d) && uls->handshaked && dls->handshaked);
    reverseserverRemoveConnectionU(box, uls);
    reverseserverRemoveConnectionD(box, dls);
    uls->d      = d;
    dls->u      = u;
    uls->paired = dls->paired = true;

    const uint32_t length     = fastRandRange32(ts->activation_min_size, ts->activation_max_size);
    buffer_pool_t *pool       = lineGetBufferPool(d);
    sbuf_t        *activation = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    getRandomBytes(sbufGetMutablePtr(activation), length);
    reverseActivationWriteSize(sbufGetMutablePtr(activation), length);
    sbufSetLength(activation, length);
    /* Activation alone crosses Pause; both application FIFOs stay behind it. */
    uls->replaying = dls->replaying = true;
    uls->replay_admitted = dls->replay_admitted = 0;
    uls->replay_admitted_buffers = dls->replay_admitted_buffers = 0;
    lineRef(u);
    lineRef(d);
    reverseserverReconcileSource(t, u);
    if (lineIsAlive(u) && lineIsAlive(d))
        reverseserverReconcileSource(t, d);
    if (lineIsAlive(u) && lineIsAlive(d))
        tunnelPrevDownStreamPayload(t, d, activation);
    else
        bufferpoolReuseBuffer(pool, activation);
    if (lineIsAlive(u) && lineIsAlive(d))
    {
        uls->replaying = dls->replaying = false;
        reverseserverDrainPair(t, u);
    }
    lineUnref(d);
    lineUnref(u);
}

bool reverseserverQueuePairedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    reverseserver_lstate_t *ls = lineGetState(line, t);
    if (! ls->replaying && bufferqueueGetBufCount(&ls->pending) == 0)
        return false;
    if (! reverseserverRetainPayload(t, line, buf))
        return true;
    reverseserverDrainPair(t, ls->u);
    return true;
}

#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverEnterWaiting(reverseserver_waitlist_t *list, reverseserver_lstate_t *half)
{
    assert(half->phase == kReverseHalfOpening);
    half->phase = kReverseHalfWaiting;
    half->next  = list->head;
    if (list->head != NULL)
        list->head->prev = half;
    list->head = half;
    atomicInc(&list->count);
}

void reverseserverLeaveWaiting(reverseserver_waitlist_t *list, reverseserver_lstate_t *half, reverseserver_phase_t next)
{
    assert(half->phase == kReverseHalfWaiting && (half->prev != NULL || list->head == half));
    if (half->prev != NULL)
        half->prev->next = half->next;
    else
        list->head = half->next;
    if (half->next != NULL)
        half->next->prev = half->prev;
    half->prev = half->next = NULL;
    half->phase             = next;
    atomicDec(&list->count);
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

static void settleCloseDrain(tunnel_t *t, line_t *line, const char *reason)
{
    reverseserver_lstate_t *ls   = lineGetState(line, t);
    const bool              user = ls->u == line;
    if (reason != NULL)
    {
        LOGW("ReverseServer: %s with %zu undelivered application bytes", reason, bufferqueueGetLength(&ls->pending));
    }
    reverseserverLinestateDestroy(ls);
    if (user)
        tunnelNextUpStreamFinish(t, line);
    else
        tunnelPrevDownStreamFinish(t, line);
}

static void cancelCloseDrain(close_drain_t *drain, const char *reason)
{
    reverseserver_lstate_t *ls = container_of(drain, reverseserver_lstate_t, close_drain);
    settleCloseDrain(ls->drain_tunnel, ls->u != NULL ? ls->u : ls->d, reason);
}

static void closeDrainExpired(close_drain_t *drain)
{
    cancelCloseDrain(drain, "close drain timed out");
}

void reverseserverQuiesceDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    for (close_drain_t *drain = ts->threadlocal_pool[wid].drains; drain != NULL; drain = drain->next)
        closeDrainCancelTimer(drain);
}

void reverseserverStopDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    while (ts->threadlocal_pool[wid].drains != NULL)
        cancelCloseDrain(ts->threadlocal_pool[wid].drains, "worker stopped during close drain");
}

void reverseserverPumpClose(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t *ls = lineGetState(line, t);
    if (ls->phase != kReverseHalfDraining || ls->replaying || ls->handoff_depth != 0)
        return;

    wloop_t   *loop = getWorkerLoop(lineGetWID(line));
    const bool user = ls->u == line;
    lineRef(line);
    ++ls->handoff_depth;
    while (lineIsAlive(line) && ls->phase == kReverseHalfDraining)
    {
        if (ls->activation == NULL && bufferqueueGetEntryCount(&ls->pending) == 0)
        {
            settleCloseDrain(t, line, NULL);
            break;
        }
        if (closeDrainTimeRemaining(&ls->close_drain) == 0 || ! wloopNormalDispatchAllowed(loop))
        {
            settleCloseDrain(t, line, "close drain deadline or worker admission ended");
            break;
        }
        if (ls->activation != NULL)
        {
            sbuf_t *activation = ls->activation;
            ls->activation     = NULL;
            tunnelPrevDownStreamPayload(t, line, activation);
            continue;
        }
        if (ls->source_paused)
        {
            ls->source_paused = false;
            if (user)
                tunnelNextUpStreamResume(t, line);
            else
                tunnelPrevDownStreamResume(t, line);
            continue;
        }
        if (ls->output_paused)
        {
            --ls->handoff_depth;
            if (! closeDrainArm(&ls->close_drain, loop))
                settleCloseDrain(t, line, "close drain timer refused");
            break;
        }
        sbuf_t *buf = bufferqueuePopFront(&ls->pending);
        if (user)
            tunnelNextUpStreamPayload(t, line, buf);
        else
            tunnelPrevDownStreamPayload(t, line, buf);
    }
    lineUnref(line);
}

void reverseserverFinishHalf(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t     *ls   = lineGetState(line, t);
    const bool                  user = ls->u == line;
    reverseserver_tstate_t     *ts   = tunnelGetState(t);
    reverseserver_thread_box_t *box  = &ts->threadlocal_pool[lineGetWID(line)];
    if (ls->phase == kReverseHalfPaired)
    {
        line_t                 *survivor = user ? ls->d : ls->u;
        reverseserver_lstate_t *other    = lineGetState(survivor, t);
        bufferqueueDestroy(&other->pending);
        // The budgets have identical limits. The survivor owns no active
        // reservations, because the paired pump releases cost before handoff.
        if (UNLIKELY(! bufferqueueTryRebindBudget(&ls->pending, &other->pending_budget)))
        {
            LOGF("ReverseServer: close drain could not transfer the paired queue budget");
            abortProgramNow(1);
        }
        other->pending = ls->pending;
        bufferqueueInitEmpty(&ls->pending);
        other->phase        = kReverseHalfDraining;
        other->u            = user ? NULL : survivor;
        other->d            = user ? survivor : NULL;
        other->drain_tunnel = t;
        closeDrainBegin(&other->close_drain, &box->drains, closeDrainExpired);
        reverseserverLinestateDestroy(ls);
        reverseserverPumpClose(t, survivor);
        return;
    }
    if (ls->phase == kReverseHalfWaiting)
        reverseserverLeaveWaiting(user ? &box->users : &box->reverse_links, ls, kReverseHalfClosed);
    reverseserverLinestateDestroy(ls);
}

void reverseserverCloseLine(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t *ls = lineGetState(line, t);
    if (ls->phase == kReverseHalfPaired)
    {
        closePair(t, ls->u, ls->d);
        return;
    }
    const bool                  user = ls->u == line;
    reverseserver_tstate_t     *ts   = tunnelGetState(t);
    reverseserver_thread_box_t *box  = &ts->threadlocal_pool[lineGetWID(line)];
    if (ls->phase == kReverseHalfWaiting)
        reverseserverLeaveWaiting(user ? &box->users : &box->reverse_links, ls, kReverseHalfClosed);
    reverseserverLinestateDestroy(ls);
    if (user)
        tunnelNextUpStreamFinish(t, line);
    else
        tunnelPrevDownStreamFinish(t, line);
}

bool reverseserverReconcileSource(tunnel_t *t, line_t *line)
{
    reverseserver_lstate_t *ls = lineGetState(line, t);
    if (ls->phase == kReverseHalfDraining)
        return true;
    const bool user   = ls->u == line;
    bool       paused = ls->phase == kReverseHalfWaiting;
    if (ls->phase == kReverseHalfPaired)
    {
        reverseserver_lstate_t *peer = lineGetState(user ? ls->d : ls->u, t);
        paused = ls->replaying || bufferqueueGetEntryCount(&ls->pending) != 0 || peer->output_paused;
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

void reverseserverSetOutputPaused(tunnel_t *t, line_t *line, bool paused)
{
    reverseserver_lstate_t *half = lineGetState(line, t);
    if (half->phase == kReverseHalfClosed)
        return;
    half->output_paused = paused;
    if (half->phase == kReverseHalfPaired)
    {
        if (paused)
            reverseserverReconcileSource(t, half->u == line ? half->d : half->u);
        else
            reverseserverDrainPair(t, half->u);
    }
    else if (! paused && half->phase == kReverseHalfDraining)
        reverseserverPumpClose(t, line);
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
    if (length > kReverseServerPendingBytes - used.bytes ||
        (ls->replaying && (ls->replay_admitted + length > kReverseServerPendingBytes ||
                           ls->replay_admitted_buffers >= kReverseServerReplayDeliveries)))
    {
        LOGW("ReverseServer: closing connection: pending application %s limit exceeded "
             "(retained_bytes=%zu, incoming_bytes=%u, limit_bytes=%u, replay_admitted_bytes=%" PRIu64 ", "
             "replay_admitted_buffers=%u, replay_buffer_limit=%u)",
             length > kReverseServerPendingBytes - used.bytes            ? "byte budget"
             : ls->replay_admitted + length > kReverseServerPendingBytes ? "replay byte"
                                                                         : "replay delivery",
             used.bytes,
             length,
             (unsigned) kReverseServerPendingBytes,
             ls->replay_admitted,
             ls->replay_admitted_buffers,
             (unsigned) kReverseServerReplayDeliveries);
        lineReuseBuffer(line, buf);
        reverseserverCloseLine(t, line);
        return false;
    }
    buf = sbufEnsureOrdinary(lineGetBufferPool(line), buf);
    if (! bufferqueueTryPushBack(&ls->pending, &buf))
    {
        const buffer_budget_cost_t limits          = bufferbudgetGetLimits(&ls->pending_budget);
        const size_t               incoming_charge = sbufGetQueueCharge(buf);
        LOGW("ReverseServer: closing connection: application backlog %s "
             "(retained_bytes=%zu, incoming_bytes=%u, limit_bytes=%zu, retained_charge_bytes=%zu, "
             "incoming_charge_bytes=%zu, limit_charge_bytes=%zu)",
             incoming_charge > limits.charge - used.charge ? "storage charge budget exceeded"
                                                           : "queue admission failed",
             used.bytes,
             length,
             limits.bytes,
             used.charge,
             incoming_charge,
             limits.charge);
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

/* Both halves enter and leave Paired together on their owner worker. */
static bool pairIsActive(tunnel_t *t, line_t *u, line_t *d)
{
    if (! lineIsAlive(u) || ! lineIsAlive(d))
        return false;
    reverseserver_lstate_t *user = lineGetState(u, t);
    return user->phase == kReverseHalfPaired && user->d == d;
}

static void continueDrainAfterReplay(tunnel_t *t, line_t *line)
{
    if (! lineIsAlive(line))
        return;
    reverseserver_lstate_t *half = lineGetState(line, t);
    if (half->phase == kReverseHalfDraining)
    {
        half->replaying = false;
        reverseserverPumpClose(t, line);
    }
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
    while (pairIsActive(t, u, d))
    {
        bool progress = false;
        if (bufferqueueGetEntryCount(&uls->pending) != 0 && ! dls->output_paused)
        {
            sbuf_t *buf = bufferqueuePopFront(&uls->pending);
            tunnelPrevDownStreamPayload(t, d, buf);
            progress = true;
        }
        if (! pairIsActive(t, u, d))
            break;
        if (bufferqueueGetEntryCount(&dls->pending) != 0 && ! uls->output_paused)
        {
            sbuf_t *buf = bufferqueuePopFront(&dls->pending);
            tunnelNextUpStreamPayload(t, u, buf);
            progress = true;
        }
        if (! progress)
            break;
    }
    if (pairIsActive(t, u, d))
    {
        uls->replaying = dls->replaying = false;
        reverseserverReconcileSource(t, u);
        if (pairIsActive(t, u, d))
            reverseserverReconcileSource(t, d);
    }
    continueDrainAfterReplay(t, u);
    continueDrainAfterReplay(t, d);
    lineUnref(d);
    lineUnref(u);
}

void reverseserverPair(tunnel_t *t, line_t *u, line_t *d)
{
    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(u)];
    reverseserver_lstate_t     *uls = lineGetState(u, t);
    reverseserver_lstate_t     *dls = lineGetState(d, t);
    assert(lineGetWID(u) == lineGetWID(d));
    reverseserverLeaveWaiting(&box->users, uls, kReverseHalfPaired);
    reverseserverLeaveWaiting(&box->reverse_links, dls, kReverseHalfPaired);
    uls->d      = d;
    dls->u      = u;

    const uint32_t length     = fastRandRange32(ts->activation_min_size, ts->activation_max_size);
    buffer_pool_t *pool       = lineGetBufferPool(d);
    sbuf_t        *activation = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    getRandomBytes(sbufGetMutablePtr(activation), length);
    reverseActivationWriteSize(sbufGetMutablePtr(activation), length);
    sbufSetLength(activation, length);
    dls->activation = activation;
    /* Activation alone crosses Pause; both application FIFOs stay behind it. */
    uls->replaying = dls->replaying = true;
    uls->replay_admitted = dls->replay_admitted = 0;
    uls->replay_admitted_buffers = dls->replay_admitted_buffers = 0;
    lineRef(u);
    lineRef(d);
    reverseserverReconcileSource(t, u);
    if (pairIsActive(t, u, d))
        reverseserverReconcileSource(t, d);
    if (pairIsActive(t, u, d))
    {
        dls->activation = NULL;
        tunnelPrevDownStreamPayload(t, d, activation);
    }
    if (pairIsActive(t, u, d))
    {
        uls->replaying = dls->replaying = false;
        reverseserverDrainPair(t, u);
    }
    continueDrainAfterReplay(t, u);
    continueDrainAfterReplay(t, d);
    lineUnref(d);
    lineUnref(u);
}

void reverseserverForwardPairedPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    reverseserver_lstate_t *ls     = lineGetState(line, t);
    const bool              user   = ls->u == line;
    line_t                 *target = user ? ls->d : ls->u;
    reverseserver_lstate_t *other  = lineGetState(target, t);
    if (ls->replaying || other->output_paused || bufferqueueGetEntryCount(&ls->pending) != 0)
    {
        if (reverseserverRetainPayload(t, line, buf))
            reverseserverDrainPair(t, ls->u);
        return;
    }
    lineRef(target);
    ++other->handoff_depth;
    if (user)
        tunnelPrevDownStreamPayload(t, target, buf);
    else
        tunnelNextUpStreamPayload(t, target, buf);
    if (lineIsAlive(target) && (other->phase == kReverseHalfPaired || other->phase == kReverseHalfDraining))
    {
        --other->handoff_depth;
        reverseserverPumpClose(t, target);
    }
    lineUnref(target);
}

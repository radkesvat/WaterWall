#include "structure.h"

#include "loggers/network_logger.h"

static bool pipeToRemoteWorker(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls, reverseserver_thread_box_t *box,
                               reverseserver_tstate_t *ts, wid_t target)
{
    buffer_pool_t *pool   = lineGetBufferPool(d);
    const uint64_t length = ts->handshake_length + (uint64_t) bufferqueueGetBufLen(&dls->pending);
    uint32_t       capacity;
    if (! sbufTryComputeCapacity(length, bufferpoolGetLargeBufferPadding(pool), &capacity) || ! pipeTo(t, d, target))
        return false;

    const bool output_paused = dls->output_paused;
    sbuf_t    *replay        = bufferpoolGetBestFit(pool, (uint32_t) length, bufferpoolGetLargeBufferPadding(pool));
    uint8_t   *bytes         = sbufGetMutablePtr(replay);
    memoryCopy(bytes, ts->handshake_bytes, ts->handshake_length);
    size_t offset = ts->handshake_length;
    while (bufferqueueGetBufCount(&dls->pending) != 0)
    {
        sbuf_t        *body  = bufferqueuePopFront(&dls->pending);
        const uint32_t count = sbufGetLength(body);
        sbufReadRangeToMemory(body, bytes + offset, count);
        offset += count;
        bufferpoolReuseBuffer(pool, body);
    }
    sbufSetLength(replay, (uint32_t) length);
    reverseserverRemoveConnectionD(box, dls);
    reverseserverLinestateDestroy(dls);

    /* Keep the physical source paused. The target's complete handshake repeats
     * that hold through PipeTunnel, then pairing releases it on the source worker.
     * Consumer pressure must also precede the replay on the target. */
    if (output_paused && ! lineCallWithRef(d, tunnelUpStreamPause, t->prev))
    {
        bufferpoolReuseBuffer(pool, replay);
        return true;
    }
    tunnelUpStreamPayload(t->prev, d, replay);
    return true;
}

static void tryPairWithRemoteUpstreamConnection(tunnel_t *t, line_t *d, reverseserver_lstate_t *dls,
                                                reverseserver_tstate_t *ts, reverseserver_thread_box_t *box)
{
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        if (wid != lineGetWID(d) && atomicLoad(&ts->threadlocal_pool[wid].u_count) != 0 &&
            pipeToRemoteWorker(t, d, dls, box, ts, wid))
            return;
    }
}

static void pairWaitingPeerOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                     arg3;
    tunnel_t                   *t        = arg1;
    const wid_t                 user_wid = (wid_t) (uintptr_t) arg2;
    reverseserver_tstate_t     *ts       = tunnelGetState(t);
    reverseserver_thread_box_t *box      = &ts->threadlocal_pool[worker->wid];
    if (atomicLoad(&ts->threadlocal_pool[user_wid].u_count) == 0)
        return;
    for (reverseserver_lstate_t *ls = box->d_root; ls != NULL; ls = ls->next)
    {
        if (pipeToRemoteWorker(t, ls->d, ls, box, ts, user_wid))
            return;
    }
}

static void cancelPairingNotification(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg1;
    discard arg2;
    discard arg3;
    if (reason == kWorkerMessageCancelEnqueueFailure || reason == kWorkerMessageCancelTargetUnavailable)
    {
        LOGF("ReverseServer: failed to submit a required pairing notification");
        abortProgramNow(1);
    }
}

void reverseserverNotifyWaitingPeers(tunnel_t *t, wid_t user_wid)
{
    reverseserver_tstate_t *ts = tunnelGetState(t);
    for (wid_t wi = 0; wi < getWorkersCount(); ++wi)
    {
        if (wi != user_wid && atomicLoad(&ts->threadlocal_pool[wi].d_count) > 0)
        {
            /* No line pointer crosses this boundary. The peer worker resolves
             * its own live waiting list; quiescence simply cancels the hint. */
            const worker_message_submit_result_e result =
                sendWorkerMessageForceQueueWithCleanup(wi,
                                                       (WorkerMessageCallback) pairWaitingPeerOnWorker,
                                                       cancelPairingNotification,
                                                       t,
                                                       (void *) (uintptr_t) user_wid,
                                                       NULL);
            discard result;
            return;
        }
    }
}

void reverseserverTunnelUpStreamPayload(tunnel_t *t, line_t *d, sbuf_t *buf)
{
    reverseserver_lstate_t *dls = lineGetState(d, t);
    if (dls->paired)
    {
        if (! reverseserverQueuePairedPayload(t, d, buf))
            tunnelNextUpStreamPayload(t, dls->u, buf);
        return;
    }

    reverseserver_tstate_t     *ts  = tunnelGetState(t);
    reverseserver_thread_box_t *box = &ts->threadlocal_pool[lineGetWID(d)];
    buf                             = sbufEnsureOrdinary(lineGetBufferPool(d), buf);
    if (! dls->handshaked)
    {
        const uint32_t count = min(sbufGetLength(buf), ts->handshake_length - dls->handshake_read);
        if (memoryCompare(sbufGetRawPtr(buf), ts->handshake_bytes + dls->handshake_read, count) != 0)
        {
            LOGD("ReverseServer: invalid reverse handshake");
            lineReuseBuffer(d, buf);
            reverseserverCloseLine(t, d);
            return;
        }
        dls->handshake_read += count;
        sbufShiftRight(buf, count);
        if (dls->handshake_read != ts->handshake_length)
        {
            lineReuseBuffer(d, buf);
            return;
        }
        dls->handshaked = true;
        reverseserverAddConnectionD(box, dls);
    }
    /* Own the coalesced application tail before Pause can reenter. */
    if (! reverseserverRetainPayload(t, d, buf) || ! reverseserverReconcileSource(t, d))
        return;
    if (dls->paired || dls->d != d)
        return;
    if (atomicLoad(&box->u_count) != 0)
        reverseserverPair(t, box->u_root->u, d);
    else
        tryPairWithRemoteUpstreamConnection(t, d, dls, ts, box);
}

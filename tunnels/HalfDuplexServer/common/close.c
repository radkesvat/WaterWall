#include "structure.h"

#include "loggers/network_logger.h"

static hmap_cons_t_iter waitingUpload(halfduplexserver_tstate_t *ts, halfduplexserver_lstate_t *ls)
{
    hmap_cons_t_iter it = hmap_cons_t_find(&ts->upload_line_map, ls->pair_id);
    if (UNLIKELY(it.ref == hmap_cons_t_end(&ts->upload_line_map).ref || it.ref->second != ls))
    {
        LOGF("HalfDuplexServer: waiting upload missing from its rendezvous table");
        abortProgramNow(1);
    }
    return it;
}

static void cancelDetachedUpload(halfduplexserver_detached_upload_t *upload, const char *reason)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(upload->owner);
    halfduplexserver_lstate_t *ls = &upload->entry;
    mutexLock(&ts->pending_line_maps_mutex);
    hmap_cons_t_erase_at(&ts->upload_line_map, waitingUpload(ts, ls));
    --ts->detached_count;
    ts->detached_charge -= upload->charge;
    mutexUnlock(&ts->pending_line_maps_mutex);

    closeDrainEnd(&ls->close_drain);
    LOGW(
        "HalfDuplexServer: %s with %u undelivered upload bytes", reason, sbufGetLength(ls->buffering) - kHLFDIntroSize);
    bufferpoolReuseBuffer(ls->startup_pool, ls->buffering);
    memoryFree(upload);
}

static void detachedUploadExpired(close_drain_t *drain)
{
    halfduplexserver_lstate_t *ls = container_of(drain, halfduplexserver_lstate_t, close_drain);
    cancelDetachedUpload(container_of(ls, halfduplexserver_detached_upload_t, entry), "detached upload timed out");
}

void halfduplexserverDiscardWaitingUpload(tunnel_t *t, line_t *line)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(halfduplexserverOwner(t));
    halfduplexserver_lstate_t *ls = lineGetState(line, t);
    mutexLock(&ts->pending_line_maps_mutex);
    hmap_cons_t_erase_at(&ts->upload_line_map, waitingUpload(ts, ls));
    mutexUnlock(&ts->pending_line_maps_mutex);
    lineReuseBuffer(line, ls->buffering);
    ls->buffering = NULL;
    halfduplexserverLinestateDestroy(ls);
}

void halfduplexserverDetachWaitingUpload(tunnel_t *t, line_t *line)
{
    const uint64_t             deadline = getHRTimeUs() / 1000U + kCloseDrainTimeoutMs;
    tunnel_t                  *owner    = halfduplexserverOwner(t);
    halfduplexserver_tstate_t *ts       = tunnelGetState(owner);
    halfduplexserver_lstate_t *ls       = lineGetState(line, t);
    const wid_t                wid      = lineGetWID(line);
    wloop_t                   *loop     = getWorkerLoop(wid);
    const size_t               charge   = sbufGetQueueCharge(ls->buffering);
    mutexLock(&ts->pending_line_maps_mutex);
    hmap_cons_t_iter it = waitingUpload(ts, ls);
    if (! wloopNormalDispatchAllowed(loop) || ts->detached_count >= kHalfDuplexServerDetachedUploads ||
        charge > kHalfDuplexServerDetachedCharge - ts->detached_charge)
    {
        hmap_cons_t_erase_at(&ts->upload_line_map, it);
        mutexUnlock(&ts->pending_line_maps_mutex);
        LOGW("HalfDuplexServer: detached upload admission refused with %u undelivered upload bytes",
             sbufGetLength(ls->buffering) - kHLFDIntroSize);
        lineReuseBuffer(line, ls->buffering);
        ls->buffering = NULL;
        halfduplexserverLinestateDestroy(ls);
        return;
    }

    halfduplexserver_detached_upload_t *upload = memoryAllocate(sizeof(*upload));
    *upload        = (halfduplexserver_detached_upload_t) {.entry  = {.buffering    = ls->buffering,
                                                                      .state        = kCsUploadDetached,
                                                                      .pair_id      = ls->pair_id,
                                                                      .startup_pool = lineGetBufferPool(line)},
                                                           .owner  = owner,
                                                           .worker = wid,
                                                           .charge = charge};
    ls->buffering  = NULL;
    it.ref->second = &upload->entry;
    ++ts->detached_count;
    ts->detached_charge += charge;
    closeDrainBeginAt(&upload->entry.close_drain, &ts->drains[wid], detachedUploadExpired, deadline);
    mutexUnlock(&ts->pending_line_maps_mutex);

    halfduplexserverLinestateDestroy(ls);
    if (! closeDrainArm(&upload->entry.close_drain, loop))
        cancelDetachedUpload(upload, "detached upload timer refused");
}

void halfduplexserverCloseService(tunnel_t *t, line_t *main, bool send_finish, const char *reason)
{
    halfduplexserver_lstate_t *ls          = lineGetState(main, t);
    line_t                    *download    = ls->download_line;
    tunnel_t                  *ingress     = ls->download_tunnel;
    halfduplexserver_lstate_t *download_ls = NULL;
    lineRef(main);
    if (download != NULL)
    {
        lineRef(download);
        download_ls = lineGetState(download, ingress);
        assert(download_ls->state == kCsDownloadDirect && download_ls->main_line == main &&
               download_ls->upload_line == NULL);
        /* The service callback can retire the borrowed download while its line stays alive. */
        download_ls->main_line = NULL;
        download_ls->state     = kCsDownloadFinishPending;
    }
    if (reason != NULL)
    {
        const size_t initial = ls->startup_initial != NULL ? sbufGetLength(ls->startup_initial) : 0;
        LOGW("HalfDuplexServer: %s with %zu undelivered upload bytes",
             reason,
             initial + bufferqueueGetLength(&ls->startup_pending));
    }
    halfduplexserverLinestateDestroy(ls);
    if (send_finish)
        tunnelNextUpStreamFinish(t, main);
    if (lineIsAlive(main))
        lineDestroy(main);
    if (download != NULL)
    {
        if (lineIsAlive(download) && download_ls->state == kCsDownloadFinishPending)
        {
            halfduplexserverLinestateDestroy(download_ls);
            tunnelPrevDownStreamFinish(ingress, download);
        }
        lineUnref(download);
    }
    lineUnref(main);
}

static void serviceCloseExpired(close_drain_t *drain)
{
    halfduplexserver_lstate_t *ls = container_of(drain, halfduplexserver_lstate_t, close_drain);
    halfduplexserverCloseService(ls->ingress_tunnel, ls->main_line, true, "service close drain timed out");
}

void halfduplexserverBeginServiceClose(tunnel_t *t, line_t *main, uint64_t deadline_ms)
{
    halfduplexserver_lstate_t *ls   = lineGetState(main, t);
    halfduplexserver_tstate_t *ts   = tunnelGetState(t);
    close_drain_t            **head = &ts->drains[lineGetWID(main)];
    ls->ingress_tunnel              = t;
    if (deadline_ms == 0)
        closeDrainBegin(&ls->close_drain, head, serviceCloseExpired);
    else
        closeDrainBeginAt(&ls->close_drain, head, serviceCloseExpired, deadline_ms);
}

void halfduplexserverPumpClose(tunnel_t *t, line_t *main)
{
    halfduplexserver_lstate_t *ls = lineGetState(main, t);
    if (! closeDrainIsActive(&ls->close_drain) || ls->startup_initializing || ls->startup_dispatching ||
        ls->handoff_depth != 0)
        return;

    wloop_t *loop = getWorkerLoop(lineGetWID(main));
    lineRef(main);
    ++ls->handoff_depth;
    while (lineIsAlive(main) && closeDrainIsActive(&ls->close_drain))
    {
        if (ls->startup_initial == NULL && bufferqueueGetEntryCount(&ls->startup_pending) == 0)
        {
            halfduplexserverCloseService(t, main, true, NULL);
            break;
        }
        if (closeDrainTimeRemaining(&ls->close_drain) == 0 || ! wloopNormalDispatchAllowed(loop))
        {
            halfduplexserverCloseService(t, main, true, "service close drain deadline or worker admission ended");
            break;
        }
        if (ls->next_paused)
        {
            --ls->handoff_depth;
            if (! closeDrainArm(&ls->close_drain, loop))
                halfduplexserverCloseService(t, main, true, "service close drain timer refused");
            break;
        }
        sbuf_t *buf         = ls->startup_initial;
        ls->startup_initial = NULL;
        if (buf == NULL)
            buf = bufferqueuePopFront(&ls->startup_pending);
        tunnelNextUpStreamPayload(t, main, buf);
    }
    lineUnref(main);
}

void halfduplexserverSendServicePayload(tunnel_t *t, line_t *main, sbuf_t *buf)
{
    halfduplexserver_lstate_t *ls = lineGetState(main, t);
    lineRef(main);
    ++ls->handoff_depth;
    tunnelNextUpStreamPayload(t, main, buf);
    if (lineIsAlive(main) && ls->main_line == main)
    {
        --ls->handoff_depth;
        halfduplexserverPumpClose(t, main);
    }
    lineUnref(main);
}

void halfduplexserverQuiesceDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    for (close_drain_t *drain = ts->drains[wid]; drain != NULL; drain = drain->next)
        closeDrainCancelTimer(drain);
}

void halfduplexserverStopDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    while (ts->drains[wid] != NULL)
    {
        halfduplexserver_lstate_t *ls = container_of(ts->drains[wid], halfduplexserver_lstate_t, close_drain);
        if (ls->state == kCsUploadDetached)
            cancelDetachedUpload(container_of(ls, halfduplexserver_detached_upload_t, entry),
                                 "worker stopped with a detached upload");
        else
            halfduplexserverCloseService(t, ls->main_line, true, "worker stopped during service close drain");
    }
}

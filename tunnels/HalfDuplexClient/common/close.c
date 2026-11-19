#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientCloseChild(halfduplexclient_pair_t *pair, line_t **slot, bool notify)
{
    line_t *child = *slot;
    if (child == NULL)
        return;
    halfduplexclient_tstate_t *ts    = tunnelGetState(pair->tunnel);
    tunnel_t                  *entry = slot == &pair->upload ? ts->upload_tunnel : ts->download_tunnel;
    *slot                            = NULL;
    halfduplexclientSetPair(pair->tunnel, child, NULL);
    lineRef(child);
    if (notify)
        tunnelUpStreamFin(entry, child);
    if (lineIsAlive(child))
        lineDestroy(child);
    lineUnref(child);
}

void halfduplexclientEndPair(halfduplexclient_pair_t *pair, const char *reason)
{
    if (pair->ending)
        return;
    pair->ending = true;
    line_t *main = pair->main;
    if (main != NULL)
        lineRef(main);
    closeDrainEnd(&pair->deadline);
    if (reason != NULL)
    {
        size_t bytes = bufferqueueGetLength(&pair->pending);
        if (pair->upload_intro != NULL)
            bytes += sbufGetLength(pair->upload_intro) - kHLFDIntroSize;
        LOGW("HalfDuplexClient: %s with %zu undelivered upload bytes", reason, bytes);
    }
    halfduplexclientDiscardUpload(pair);
    halfduplexclientCloseChild(pair, &pair->upload, true);
    halfduplexclientCloseChild(pair, &pair->download, true);
    // Either child callback can finish the application or its sibling.
    const bool notify_main = pair->main != NULL;
    pair->main             = NULL;
    if (notify_main && lineIsAlive(main))
    {
        halfduplexclientSetPair(pair->tunnel, main, NULL);
        tunnelPrevDownStreamFinish(pair->tunnel, main);
    }
    if (main != NULL)
        lineUnref(main);
    halfduplexclientReleasePair(pair);
}

static void closeDrainExpired(close_drain_t *drain)
{
    halfduplexclientEndPair(container_of(drain, halfduplexclient_pair_t, deadline), "close drain timed out");
}

void halfduplexclientBeginDrain(halfduplexclient_pair_t *pair)
{
    halfduplexclient_tstate_t *ts = tunnelGetState(pair->tunnel);
    closeDrainBegin(&pair->deadline, &ts->drains[lineGetWID(pair->upload)], closeDrainExpired);
    halfduplexclientPump(pair, NULL);
}

void halfduplexclientQuiesceDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    halfduplexclient_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    for (close_drain_t *drain = ts->drains[wid]; drain != NULL; drain = drain->next)
        closeDrainCancelTimer(drain);
}

void halfduplexclientStopDrains(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    halfduplexclient_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    while (ts->drains[wid] != NULL)
        halfduplexclientEndPair(container_of(ts->drains[wid], halfduplexclient_pair_t, deadline),
                                "worker stopped during close drain");
}

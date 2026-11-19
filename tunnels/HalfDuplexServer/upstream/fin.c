#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLineUpStream(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->upload_line != NULL || ls->download_line != NULL);
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

void halfduplexserverAbortDirectTransportPair(tunnel_t *t, line_t *current_line, bool current_is_download)
{
    halfduplexserver_lstate_t *current_ls = lineGetState(current_line, t);
    tunnel_t *const            owner      = halfduplexserverOwner(t);
    tunnel_t *const sibling_tunnel = current_is_download ? current_ls->upload_tunnel : current_ls->download_tunnel;
    line_t *const              main_line    = current_ls->main_line;
    line_t *const              sibling_line = current_is_download ? current_ls->upload_line : current_ls->download_line;

    lineRef(current_line);
    if (main_line != NULL)
    {
        lineRef(main_line);
        halfduplexserver_lstate_t *main_ls = lineGetState(main_line, owner);
        halfduplexserverLinestateDestroy(main_ls);
    }
    if (sibling_line != NULL)
    {
        lineRef(sibling_line);
        halfduplexserver_lstate_t *sibling_ls = lineGetState(sibling_line, sibling_tunnel);
        sibling_ls->main_line                 = NULL;
        if (current_is_download)
        {
            sibling_ls->download_line   = NULL;
            sibling_ls->download_tunnel = NULL;
        }
        else
        {
            sibling_ls->upload_line   = NULL;
            sibling_ls->upload_tunnel = NULL;
        }
    }

    /* No direct-pair state may be read after the first cross-line callback. */
    halfduplexserverLinestateDestroy(current_ls);

    if (main_line != NULL && lineIsAlive(main_line))
    {
        tunnelNextUpStreamFinish(owner, main_line);
        if (lineIsAlive(main_line))
        {
            lineDestroy(main_line);
        }
    }

    if (sibling_line != NULL && lineIsAlive(sibling_line))
    {
        const line_task_submit_result_e result =
            lineScheduleTask(sibling_line, localAsyncCloseLineUpStream, sibling_tunnel, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            if (lineIsAlive(sibling_line))
            {
                localAsyncCloseLineUpStream(sibling_tunnel, sibling_line);
            }
        }
        else
        {
            assert(result == kLineTaskSubmitAcceptedAsync);
        }
    }

    if (sibling_line != NULL)
    {
        lineUnref(sibling_line);
    }
    if (main_line != NULL)
    {
        lineUnref(main_line);
    }
    lineUnref(current_line);
}

void halfduplexserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(halfduplexserverOwner(t));
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    switch (ls->state)
    {

    case kCsUnkown: {
        if (ls->buffering)
        {
            lineReuseBuffer(l, ls->buffering);
            ls->buffering = NULL;
        }
        halfduplexserverLinestateDestroy(ls);
    }
    break;

    case kCsUploadInTable: {
        halfduplexserverDetachWaitingUpload(t, l);
    }
    break;

    case kCsDownloadInTable: {
        mutexLock(&(ts->pending_line_maps_mutex));

        hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->download_line_map), ls->pair_id);
        bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->download_line_map)).ref;
        if (! found)
        {
            LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
            abortProgramNow(1);
        }
        hmap_cons_t_erase_at(&(ts->download_line_map), f_iter);

        mutexUnlock(&(ts->pending_line_maps_mutex));
        halfduplexserverLinestateDestroy(ls);
    }
    break;

    case kCsDownloadFinishPending:
        halfduplexserverLinestateDestroy(ls);
        break;

    case kCsDownloadDirect: {
        tunnel_t                  *owner   = halfduplexserverOwner(t);
        line_t                    *main    = ls->main_line;
        halfduplexserver_lstate_t *service = main != NULL ? lineGetState(main, owner) : NULL;
        if (service != NULL && closeDrainIsActive(&service->close_drain))
        {
            const bool release       = ls->transport_paused && ! service->startup_initializing;
            service->download_line   = NULL;
            service->download_tunnel = NULL;
            halfduplexserverLinestateDestroy(ls);
            if (release)
                tunnelNextUpStreamResume(owner, main);
        }
        else
            halfduplexserverAbortDirectTransportPair(t, l, true);
    }
    break;

    case kCsUploadDirect: {
        line_t *main = ls->main_line;
        if (main == NULL)
        {
            halfduplexserverLinestateDestroy(ls);
            break;
        }
        tunnel_t                  *owner    = halfduplexserverOwner(t);
        halfduplexserver_lstate_t *service  = lineGetState(main, owner);
        halfduplexserver_lstate_t *download = lineGetState(service->download_line, service->download_tunnel);
        download->upload_line               = NULL;
        download->upload_tunnel             = NULL;
        service->upload_line                = NULL;
        service->upload_tunnel              = NULL;
        service->source_paused              = false;
        halfduplexserverBeginServiceClose(owner, main, 0);
        halfduplexserverLinestateDestroy(ls);
        halfduplexserverPumpClose(owner, main);
    }
    break;

    default:
        LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
        abortProgramNow(1);
        break;
    }
}

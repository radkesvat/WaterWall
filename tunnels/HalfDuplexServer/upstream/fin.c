#include "structure.h"

#include "loggers/network_logger.h"

static void localAsyncCloseLineUpStream(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->upload_line != NULL || ls->download_line != NULL);
    halfduplexserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}

static void closeDirectTransportPair(tunnel_t *t, line_t *current_line, bool current_is_download)
{
    halfduplexserver_lstate_t *current_ls   = lineGetState(current_line, t);
    line_t *const              main_line    = current_ls->main_line;
    line_t *const              sibling_line = current_is_download ? current_ls->upload_line : current_ls->download_line;

    lineRef(current_line);
    if (main_line != NULL)
    {
        lineRef(main_line);
        halfduplexserverLinestateDestroy(lineGetState(main_line, t));
    }
    if (sibling_line != NULL)
    {
        lineRef(sibling_line);
        halfduplexserver_lstate_t *sibling_ls = lineGetState(sibling_line, t);
        sibling_ls->main_line                 = NULL;
        if (current_is_download)
        {
            sibling_ls->download_line = NULL;
        }
        else
        {
            sibling_ls->upload_line = NULL;
        }
    }

    /* No direct-pair state may be read after the first cross-line callback. */
    halfduplexserverLinestateDestroy(current_ls);

    if (main_line != NULL && lineIsAlive(main_line))
    {
        tunnelNextUpStreamFinish(t, main_line);
        if (lineIsAlive(main_line))
        {
            lineDestroy(main_line);
        }
    }

    if (sibling_line != NULL && lineIsAlive(sibling_line))
    {
        const line_task_submit_result_e result = lineScheduleTask(sibling_line, localAsyncCloseLineUpStream, t, NULL);
        if (result == kLineTaskSubmitRejectedSettled)
        {
            if (lineIsAlive(sibling_line))
            {
                localAsyncCloseLineUpStream(t, sibling_line);
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
    halfduplexserver_tstate_t *ts = tunnelGetState(t);
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

        mutexLock(&(ts->pending_line_maps_mutex));

        hmap_cons_t_iter f_iter = hmap_cons_t_find(&(ts->upload_line_map), ls->pair_id);
        bool             found  = f_iter.ref != hmap_cons_t_end(&(ts->upload_line_map)).ref;
        if (! found)
        {
            LOGF("HalfDuplexServer: Thread safety is done incorrectly  [%s:%d]", __FILENAME__, __LINE__);
            abortProgramNow(1);
        }
        hmap_cons_t_erase_at(&(ts->upload_line_map), f_iter);

        mutexUnlock(&(ts->pending_line_maps_mutex));
        if (ls->buffering)
        {
            lineReuseBuffer(l, ls->buffering);
            ls->buffering = NULL;
        }
        halfduplexserverLinestateDestroy(ls);
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

    case kCsDownloadDirect: {
        closeDirectTransportPair(t, l, true);
    }
    break;

    case kCsUploadDirect: {
        closeDirectTransportPair(t, l, false);
    }
    break;

    default:
        LOGF("HalfDuplexServer: Unexpected  [%s:%d]", __FILENAME__, __LINE__);
        abortProgramNow(1);
        break;
    }
}
